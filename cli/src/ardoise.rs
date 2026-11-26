//! Ardoise : micropaiements répétés chez un vendeur, réglés en une seule transaction.
//! L'agent dépose une somme (comptée dans son budget), puis signe hors chaîne des bons cumulés ;
//! le vendeur encaisse le dernier bon, le reste revient au propriétaire (contracts/ardoise.sil).
#![allow(dead_code)] // bibliothèque prête ; les commandes de l'outil arrivent ensuite

use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use secp256k1::{Keypair, Message, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use crate::sequestre::{h, spk_hash};
use crate::{Res, bytecode, vault_sigscript, xonly};

pub const SOURCE: &str = include_str!("../../contracts/ardoise.sil");
/// Le vendeur doit avoir le temps de clore avant que le remboursement devienne possible.
pub const MIN_TIMEOUT: i64 = 36_000; // ≈ 1 h
pub const DEFAULT_TIMEOUT: i64 = crate::JOUR_DAA;
pub const MAX_FEE: i64 = 3_000_000;
/// Budgets de calcul (marge incluse) : clôture = deux vérifications de signature.
pub const CB_CLOSE: u16 = 25;
pub const CB_REFUND: u16 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct Ardoise {
    pub txid: String,
    pub index: u32,
    pub depot: u64,
    pub timeout: i64,
}

impl Ardoise {
    fn outpoint(&self) -> Res<TransactionOutpoint> {
        Ok(TransactionOutpoint::new(TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&self.txid)?.as_slice())?), self.index))
    }
}

pub fn artifact(vendeur: &ScriptPublicKey, cle_vendeur: &[u8], proprietaire: &ScriptPublicKey, agent: &[u8], timeout: i64) -> Res<SilAbiArtifact> {
    if timeout < MIN_TIMEOUT {
        return Err(format!("délai d'ardoise trop court : {timeout} < {MIN_TIMEOUT} (le vendeur doit pouvoir clore)").into());
    }
    let args: Vec<ArtifactValue> = vec![
        spk_hash(vendeur).to_vec().into(),
        cle_vendeur.to_vec().into(),
        spk_hash(proprietaire).to_vec().into(),
        agent.to_vec().into(),
        timeout.into(),
        MAX_FEE.into(),
    ];
    Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
}

fn message(a: &Ardoise, total: i64) -> Res<[u8; 32]> {
    let mut m = hex::decode(&a.txid)?;
    m.extend_from_slice(&a.index.to_le_bytes());
    m.extend_from_slice(&total.to_le_bytes());
    Ok(h(&m))
}

/// Bon cumulé signé par l'agent : « je dois au total `total` sompi sur cette ardoise ».
pub fn bon(agent: &Keypair, a: &Ardoise, total: i64) -> Res<Vec<u8>> {
    Ok(agent.sign_schnorr(Message::from_digest(message(a, total)?)).as_ref().to_vec())
}

/// Côté vendeur, à chaque appel : le bon est-il valable et couvert par le dépôt ?
/// Attention : un bon valable n'est pas forcément ENCAISSABLE (voir `encaissable`, R60). Le
/// vendeur garde le bon le plus élevé qu'il a reçu : le contrat accepte n'importe quel bon signé,
/// même ancien, et c'est le vendeur qui choisit lequel présenter.
pub fn bon_valable(agent: &[u8], a: &Ardoise, total: i64, signature: &[u8]) -> bool {
    let (Ok(cle), Ok(sig), Ok(m)) = (XOnlyPublicKey::from_slice(agent), schnorr::Signature::from_slice(signature), message(a, total)) else {
        return false;
    };
    total > 0 && total as u64 <= a.depot && secp256k1::SECP256K1.verify_schnorr(&sig, &Message::from_digest(m), &cle).is_ok()
}

/// Sorties d'une clôture : part du vendeur (total moins les frais), puis reste du propriétaire s'il
/// dépasse MAX_FEE. `None` si le bon ne couvre pas les frais ou dépasse le dépôt.
fn parts(a: &Ardoise, total: i64, frais: u64) -> Option<(u64, Option<u64>)> {
    let total = u64::try_from(total).ok().filter(|t| *t > 0)?;
    let reste = a.depot.checked_sub(total)?;
    let vendeur = total.checked_sub(frais).filter(|v| *v > 0)?;
    Some((vendeur, (reste as i64 > MAX_FEE).then_some(reste)))
}

/// R60 : la clôture de ce bon serait-elle acceptée par le réseau ? Une sortie trop petite pèse trop
/// lourd (masse de stockage KIP-9) : tant que le total dû ne dépasse pas les frais de clôture plus
/// environ 0,02 TKAS, le vendeur ne peut PAS encaisser, quel que soit le bon. Un vendeur qui sert
/// des appels en dessous de ce seuil fait crédit à l'agent ; à lui de le savoir et de le borner.
pub fn encaissable(a: &Ardoise, total: i64, frais: u64) -> bool {
    use kaspa_consensus_core::mass::{UtxoCell, calc_storage_mass};
    let Some((vendeur, reste)) = parts(a, total, frais) else { return false };
    if frais as i64 > MAX_FEE {
        return false; // le script borne les frais pris sur la part du vendeur
    }
    // Pluralité 1 partout : script P2SH en entrée, adresses ordinaires en sortie, sans covenant.
    let sorties = [Some(vendeur), reste].into_iter().flatten().map(|v| UtxoCell::new(1, v));
    calc_storage_mass(false, [UtxoCell::new(1, a.depot)].into_iter(), sorties, crate::masse::STORM).is_some_and(|m| m <= crate::masse::MAX_STANDARD_MASS)
}

/// Clôture par le vendeur : sa part (total moins les frais) et le reste au propriétaire.
pub fn build_close(art: &SilAbiArtifact, a: &Ardoise, vendeur: &Keypair, proprietaire: ScriptPublicKey, voucher: Vec<u8>, total: i64, frais: u64) -> Res<Transaction> {
    let (part, reste) = parts(a, total, frais).ok_or("clôture impossible : le total dû ne couvre pas les frais, ou dépasse le dépôt")?;
    let mut sorties = vec![TransactionOutput { value: part, script_public_key: crate::pay_to_address_script(&crate::address(vendeur)), covenant: None }];
    if let Some(reste) = reste {
        sorties.push(TransactionOutput { value: reste, script_public_key: proprietaire, covenant: None });
    }
    let input = TransactionInput::new_with_compute_budget(a.outpoint()?, vec![], 0, CB_CLOSE);
    let mut tx = Transaction::new(1, vec![input], sorties, 0, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(a.depot, pay_to_script_hash_script(&bytecode(art)), 0, false, None);
    let sig = crate::sign(&tx, &[utxo], 0, vendeur);
    tx.inputs[0].signature_script = vault_sigscript(art, "close", &[sig.into(), voucher.into(), total.into()])?;
    tx.finalize();
    Ok(tx)
}

/// Remboursement au propriétaire après le délai, par n'importe qui.
pub fn build_refund(art: &SilAbiArtifact, a: &Ardoise, proprietaire: ScriptPublicKey, frais: u64) -> Res<Transaction> {
    let input = TransactionInput::new_with_compute_budget(a.outpoint()?, vec![], a.timeout as u64, CB_REFUND);
    let out = TransactionOutput { value: a.depot.checked_sub(frais).ok_or("dépôt plus petit que les frais")?, script_public_key: proprietaire, covenant: None };
    let mut tx = Transaction::new(1, vec![input], vec![out], 0, Default::default(), 0, vec![]);
    tx.inputs[0].signature_script = vault_sigscript(art, "refund", &[])?;
    tx.finalize();
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::{PopulatedTransaction, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_address_script};

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }

    fn exec(tx: &Transaction, art: &SilAbiArtifact, valeur: u64, budget: u16) -> Result<(), String> {
        let utxo = UtxoEntry::new(valeur, pay_to_script_hash_script(&bytecode(art)), 0, false, None);
        let populated = PopulatedTransaction::new(tx, vec![utxo]);
        let cov = CovenantsContext::from_tx(&populated).unwrap();
        let cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        let input = populated.inputs()[0].clone();
        let mut vm = TxScriptEngine::from_transaction_input(&populated, &input, 0, populated.utxo(0).unwrap(),
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov), EngineFlags::default());
        vm.execute().map_err(|e| format!("{e:?}"))?;
        // Le budget de calcul déclaré par l'outil doit couvrir ce que le script consomme vraiment.
        let unites = vm.used_script_units().0.div_ceil(kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT);
        eprintln!("budget de calcul mesuré : {unites} unités");
        if unites > budget as u64 {
            return Err(format!("budget de calcul insuffisant : {unites} > {budget}"));
        }
        Ok(())
    }

    fn setup() -> (Keypair, Keypair, ScriptPublicKey, SilAbiArtifact, Ardoise) {
        let (vendeur, agent) = (k(3), k(2));
        let proprio = pay_to_address_script(&crate::address(&k(1)));
        let vspk = pay_to_address_script(&crate::address(&vendeur));
        let art = artifact(&vspk, &xonly(&vendeur), &proprio, &xonly(&agent), DEFAULT_TIMEOUT).unwrap();
        (vendeur, agent, proprio, art, Ardoise { txid: "cd".repeat(32), index: 1, depot: 100_000_000, timeout: DEFAULT_TIMEOUT })
    }

    #[test]
    fn cent_appels_puis_une_seule_cloture_acceptee() {
        let (vendeur, agent, proprio, art, a) = setup();
        // 100 appels à 0,0005 KAS : 100 bons signés hors chaîne, le vendeur vérifie chacun.
        let mut dernier = vec![];
        for n in 1..=100i64 {
            let total = n * 50_000;
            dernier = bon(&agent, &a, total).unwrap();
            assert!(bon_valable(&xonly(&agent), &a, total, &dernier));
        }
        let tx = build_close(&art, &a, &vendeur, proprio, dernier, 5_000_000, crate::FEE).unwrap();
        exec(&tx, &art, a.depot, CB_CLOSE).unwrap();
    }

    #[test]
    fn bons_invalides_refuses_par_le_vendeur() {
        let (_, agent, _, _, a) = setup();
        let b = bon(&agent, &a, 5_000_000).unwrap();
        assert!(!bon_valable(&xonly(&agent), &a, 6_000_000, &b)); // total gonflé
        assert!(!bon_valable(&xonly(&k(9)), &a, 5_000_000, &b)); // autre agent
        let autre = Ardoise { txid: "ef".repeat(32), ..a.clone() };
        assert!(!bon_valable(&xonly(&agent), &autre, 5_000_000, &b)); // autre ardoise
        let gros = bon(&agent, &a, 100_000_001).unwrap();
        assert!(!bon_valable(&xonly(&agent), &a, 100_000_001, &gros)); // au-delà du dépôt
    }

    #[test]
    fn remboursement_construit_par_l_outil_valide() {
        let (_, _, proprio, art, a) = setup();
        exec(&build_refund(&art, &a, proprio, crate::FEE).unwrap(), &art, a.depot, CB_REFUND).unwrap();
    }

    #[test]
    fn delai_trop_court_refuse() {
        let (vendeur, agent, proprio, _, _) = setup();
        let vspk = pay_to_address_script(&crate::address(&vendeur));
        assert!(artifact(&vspk, &xonly(&vendeur), &proprio, &xonly(&agent), MIN_TIMEOUT - 1).is_err());
    }
    // ------------------------------------------------ Red Team 26 nov. 2026 (rapport §6 et §8)

    /// Bons rejoués, bon plus petit après un plus grand. Le contrat accepte tout bon signé par
    /// l'agent pour CETTE ardoise, même ancien : seul le vendeur clôt, et il choisit le plus élevé.
    /// Un bon n'est rejouable sur aucune autre ardoise (autre transaction ou autre index).
    #[test]
    fn bons_rejoues_et_bon_plus_petit() {
        let (vendeur, agent, proprio, art, a) = setup();
        let petit = bon(&agent, &a, 5_000_000).unwrap();
        let grand = bon(&agent, &a, 40_000_000).unwrap();
        // L'agent envoie un bon PLUS PETIT après un plus grand : les deux restent valables ; le
        // vendeur garde le grand (c'est à lui de retenir le maximum, le contrat ne le fait pas).
        assert!(bon_valable(&xonly(&agent), &a, 40_000_000, &grand) && bon_valable(&xonly(&agent), &a, 5_000_000, &petit));
        exec(&build_close(&art, &a, &vendeur, proprio.clone(), grand.clone(), 40_000_000, crate::FEE).unwrap(), &art, a.depot, CB_CLOSE).unwrap();
        exec(&build_close(&art, &a, &vendeur, proprio.clone(), petit.clone(), 5_000_000, crate::FEE).unwrap(), &art, a.depot, CB_CLOSE).unwrap();
        // Un bon ne vaut que pour son total : le grand bon présenté avec un autre total est refusé.
        assert!(exec(&build_close(&art, &a, &vendeur, proprio.clone(), grand.clone(), 40_000_001, crate::FEE).unwrap(), &art, a.depot, CB_CLOSE).is_err());
        // Rejeu sur une autre ardoise du même agent chez le même vendeur : refusé (autre
        // transaction, ou même transaction mais autre index de sortie).
        for autre in [Ardoise { txid: "ef".repeat(32), ..a.clone() }, Ardoise { index: 0, ..a.clone() }, Ardoise { index: 257, ..a.clone() }] {
            assert!(!bon_valable(&xonly(&agent), &autre, 40_000_000, &grand));
            let tx = build_close(&art, &autre, &vendeur, proprio.clone(), grand.clone(), 40_000_000, crate::FEE).unwrap();
            assert!(exec(&tx, &art, autre.depot, CB_CLOSE).is_err(), "bon rejoué sur une autre ardoise");
        }
        // Un tiers (ou l'agent) ne peut pas clore à la place du vendeur avec le petit bon.
        let tx = build_close(&art, &a, &agent, proprio, petit, 5_000_000, crate::FEE).unwrap();
        assert!(exec(&tx, &art, a.depot, CB_CLOSE).is_err());
    }

    /// R60 : masse de la clôture aux limites. `encaissable` dit exactement si la clôture construite
    /// par l'outil est valide (script) ET diffusable (masse) ; en dessous du seuil, le bon est
    /// « valable » mais le vendeur ne peut pas l'encaisser. Avant correctif, un total inférieur aux
    /// frais faisait reboucler le calcul de la part du vendeur (montant absurde, refus du réseau).
    #[test]
    fn r60_cloture_aux_limites_de_masse() {
        let (vendeur, agent, proprio, art, a0) = setup();
        let diffusable = |a: &Ardoise, total: i64| -> bool {
            let Ok(tx) = build_close(&art, a, &vendeur, proprio.clone(), bon(&agent, a, total).unwrap(), total, crate::FEE) else { return false };
            let utxo = UtxoEntry::new(a.depot, pay_to_script_hash_script(&bytecode(&art)), 0, false, None);
            tx.outputs.iter().map(|o| o.value).sum::<u64>() <= a.depot
                && crate::masse::masses(&tx, &[utxo]).is_some_and(|m| m.standard())
                && exec(&tx, &art, a.depot, CB_CLOSE).is_ok()
        };
        // Total sous les frais : erreur propre, pas de montant absurde.
        assert!(build_close(&art, &a0, &vendeur, proprio.clone(), vec![0; 64], 1_000, crate::FEE).is_err());
        assert!(build_close(&art, &a0, &vendeur, proprio.clone(), vec![0; 64], crate::FEE as i64, crate::FEE).is_err());
        assert!(build_close(&art, &a0, &vendeur, proprio.clone(), vec![0; 64], a0.depot as i64 + 1, crate::FEE).is_err());
        for depot in [100_000_000u64, 20_000_000, 8_000_000, 5_000_000] {
            let a = Ardoise { depot, ..a0.clone() };
            let pas = if depot > 10_000_000 { 49_999 } else { 4_999 };
            let mut seuil = None;
            let bords = [1, 2, crate::FEE as i64, crate::FEE as i64 + 1, depot as i64 - MAX_FEE - 1, depot as i64 - MAX_FEE, depot as i64 - MAX_FEE + 1, depot as i64 - 1, depot as i64];
            for total in (1..=depot as i64).step_by(pas).chain(bords) {
                let e = encaissable(&a, total, crate::FEE);
                assert_eq!(e, diffusable(&a, total), "dépôt {depot}, total {total}");
                if e && seuil.is_none_or(|s| total < s) {
                    seuil = Some(total);
                }
            }
            eprintln!("dépôt {depot} : premier bon encaissable ≈ {seuil:?} sompi");
            // Le crédit que le vendeur fait à l'agent avant de pouvoir encaisser est borné.
            assert!(seuil.is_some_and(|s| s <= 4_400_000), "seuil d'encaissement trop haut : {seuil:?}");
            // Tout le dépôt reste toujours encaissable (une seule sortie).
            assert!(encaissable(&a, depot as i64, crate::FEE));
        }
        // Un bon valable n'est pas forcément encaissable : le vendeur doit vérifier les deux.
        let b = bon(&agent, &a0, 2_000_000).unwrap();
        assert!(bon_valable(&xonly(&agent), &a0, 2_000_000, &b) && !encaissable(&a0, 2_000_000, crate::FEE));
    }

    /// Cible 8 : pire cas du budget de calcul, branche par branche, sous la limite EXACTE du réseau
    /// (budget déclaré × 10 000 + 9 999 unités de script, `allowed_script_units`).
    #[test]
    fn budget_de_calcul_branche_par_branche() {
        let (vendeur, agent, proprio, art, a) = setup();
        let utxo = |v: u64| vec![UtxoEntry::new(v, pay_to_script_hash_script(&bytecode(&art)), 0, false, None)];
        // close, deux sorties (reste au propriétaire).
        let tx = build_close(&art, &a, &vendeur, proprio.clone(), bon(&agent, &a, 5_000_000).unwrap(), 5_000_000, crate::FEE).unwrap();
        assert_eq!(tx.outputs.len(), 2);
        let deux = crate::masse::unites_sous_la_limite_du_reseau(&tx, utxo(a.depot)).unwrap();
        // close, une seule sortie (reste infime) : l'autre branche du `if`.
        let total = a.depot as i64 - 1_000;
        let tx = build_close(&art, &a, &vendeur, proprio.clone(), bon(&agent, &a, total).unwrap(), total, crate::FEE).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        let une = crate::masse::unites_sous_la_limite_du_reseau(&tx, utxo(a.depot)).unwrap();
        // close avec le total maximal (8 octets significatifs pour la conversion du montant).
        let gros = Ardoise { depot: 2_900_000_000_000_000_000, ..a.clone() };
        let total = gros.depot as i64 - 5_000_000;
        let tx = build_close(&art, &gros, &vendeur, proprio.clone(), bon(&agent, &gros, total).unwrap(), total, crate::FEE).unwrap();
        let max = crate::masse::unites_sous_la_limite_du_reseau(&tx, utxo(gros.depot)).unwrap();
        // refund.
        let rembourse = crate::masse::unites_sous_la_limite_du_reseau(&build_refund(&art, &a, proprio, crate::FEE).unwrap(), utxo(a.depot)).unwrap();
        eprintln!("ardoise : close 2 sorties {deux}, close 1 sortie {une}, close montant maximal {max}, refund {rembourse} unités de script");
        let pire = deux.max(une).max(max);
        assert!(pire.div_ceil(10_000) <= CB_CLOSE as u64 && rembourse.div_ceil(10_000) <= CB_REFUND as u64);
        // Un budget trop court d'une unité est refusé par le réseau : la mesure est bien celle qui compte.
        let mut court = build_close(&art, &a, &vendeur, pay_to_address_script(&crate::address(&k(1))), bon(&agent, &a, 5_000_000).unwrap(), 5_000_000, crate::FEE).unwrap();
        court.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget((deux / 10_000) as u16 - 1).into();
        assert!(crate::masse::unites_sous_la_limite_du_reseau(&court, utxo(a.depot)).is_err());
    }
}

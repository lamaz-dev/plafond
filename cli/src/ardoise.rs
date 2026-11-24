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
pub fn bon_valable(agent: &[u8], a: &Ardoise, total: i64, signature: &[u8]) -> bool {
    let (Ok(cle), Ok(sig), Ok(m)) = (XOnlyPublicKey::from_slice(agent), schnorr::Signature::from_slice(signature), message(a, total)) else {
        return false;
    };
    total > 0 && total as u64 <= a.depot && secp256k1::SECP256K1.verify_schnorr(&sig, &Message::from_digest(m), &cle).is_ok()
}

/// Clôture par le vendeur : sa part (total moins les frais) et le reste au propriétaire.
pub fn build_close(art: &SilAbiArtifact, a: &Ardoise, vendeur: &Keypair, proprietaire: ScriptPublicKey, voucher: Vec<u8>, total: i64, frais: u64) -> Res<Transaction> {
    let reste = a.depot - total as u64;
    let mut sorties = vec![TransactionOutput { value: total as u64 - frais, script_public_key: crate::pay_to_address_script(&crate::address(vendeur)), covenant: None }];
    if reste as i64 > MAX_FEE {
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
    let out = TransactionOutput { value: a.depot - frais, script_public_key: proprietaire, covenant: None };
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
}

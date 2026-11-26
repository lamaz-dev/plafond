//! Paiement à la livraison : le coffre paie un séquestre DeliveryEscrow au lieu du vendeur.
//! Le vendeur n'encaisse que contre une preuve de livraison signée par le vérificateur ;
//! sinon, passé le délai, l'argent revient au propriétaire.

use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput};
use secp256k1::{Keypair, Message};
use serde::{Deserialize, Serialize};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use crate::{Res, bytecode, vault_sigscript, xonly};

pub const SOURCE: &str = include_str!("../../contracts/delivery_escrow.sil");

/// Délai minimal accepté par le vendeur (≈ 1 min à 10 blocs/s) : en dessous, le propriétaire
/// pourrait se rembourser pendant que le vendeur livre (R22).
pub const MIN_TIMEOUT: i64 = 600;
pub const DEFAULT_TIMEOUT: i64 = 600;
pub const MAX_FEE: i64 = 3_000_000;
/// Budgets de calcul mesurés : claim 11 unités, refund 1 unité (marge incluse).
pub const CB_CLAIM: u16 = 15;
pub const CB_REFUND: u16 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct Sequestre {
    pub txid: String,
    pub index: u32,
    pub valeur: u64,
    pub requete: String,
    pub timeout: i64,
}

pub fn h(data: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new().hash_length(32).hash(data).as_bytes().try_into().unwrap()
}

/// Empreinte d'un scriptPubKey telle que la calcule `blake2b(tx.outputs[i].scriptPubKey)` dans le script.
pub fn spk_hash(spk: &ScriptPublicKey) -> [u8; 32] {
    let bytes: Vec<u8> = spk.version().to_be_bytes().into_iter().chain(spk.script().iter().copied()).collect();
    h(&bytes)
}

pub fn artifact(merchant: &ScriptPublicKey, refund: &ScriptPublicKey, verifier: &Keypair, requete: &str, timeout: i64) -> Res<SilAbiArtifact> {
    if timeout < MIN_TIMEOUT {
        return Err(format!("délai de séquestre trop court : {timeout} blocs < {MIN_TIMEOUT} (règle du vendeur, R22)").into());
    }
    let args: Vec<ArtifactValue> = vec![
        spk_hash(merchant).to_vec().into(),
        spk_hash(refund).to_vec().into(),
        xonly(verifier).into(),
        h(requete.as_bytes()).to_vec().into(),
        timeout.into(),
        MAX_FEE.into(),
    ];
    Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
}

/// Preuve de livraison (v0.3) : signature Schnorr du vérificateur sur
/// blake2b(requestHash ‖ resultHash ‖ txid du séquestre ‖ index du séquestre, 4 octets petit-boutiste).
/// Liée à CE séquestre : elle ne peut pas encaisser un autre séquestre de la même commande (R40).
pub fn proof(verifier: &Keypair, s: &Sequestre, resultat: &str) -> Res<(Vec<u8>, [u8; 32])> {
    let result_hash = h(resultat.as_bytes());
    let mut m = h(s.requete.as_bytes()).to_vec();
    m.extend_from_slice(&result_hash);
    m.extend_from_slice(&<[u8; 32]>::try_from(hex::decode(&s.txid)?.as_slice())?);
    m.extend_from_slice(&s.index.to_le_bytes());
    let sig = verifier.sign_schnorr(Message::from_digest(h(&m)));
    Ok((sig.as_ref().to_vec(), result_hash))
}

fn spend(a: &SilAbiArtifact, s: &Sequestre, to: ScriptPublicKey, fee: u64, sequence: u64, cb: u16, entry: &str, args: &[ArtifactValue]) -> Res<Transaction> {
    let txid = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&s.txid)?.as_slice())?);
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid, s.index), vec![], sequence, cb);
    let out = TransactionOutput { value: s.valeur - fee, script_public_key: to, covenant: None };
    let mut tx = Transaction::new(1, vec![input], vec![out], 0, Default::default(), 0, vec![]);
    tx.inputs[0].signature_script = vault_sigscript(a, entry, args)?;
    tx.finalize();
    Ok(tx)
}

/// Réclamation du vendeur : sans signature du vendeur, l'argent ne peut aller qu'à son adresse.
pub fn build_claim(a: &SilAbiArtifact, s: &Sequestre, merchant: ScriptPublicKey, fee: u64, proof: Vec<u8>, result_hash: [u8; 32]) -> Res<Transaction> {
    spend(a, s, merchant, fee, 0, CB_CLAIM, "claim", &[proof.into(), result_hash.to_vec().into()])
}

/// Remboursement : possible par n'importe qui après le délai, l'argent ne peut aller qu'au propriétaire.
pub fn build_refund(a: &SilAbiArtifact, s: &Sequestre, refund: ScriptPublicKey, fee: u64) -> Res<Transaction> {
    spend(a, s, refund, fee, s.timeout as u64, CB_REFUND, "refund", &[])
}

pub fn script_size(a: &SilAbiArtifact) -> usize {
    bytecode(a).len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::{PopulatedTransaction, UtxoEntry, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_address_script, pay_to_script_hash_script};

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }

    fn exec(tx: &Transaction, a: &SilAbiArtifact, value: u64) -> Result<(), String> {
        let utxo = UtxoEntry::new(value, pay_to_script_hash_script(&bytecode(a)), 0, false, None);
        exec_at(tx, vec![utxo], 0)
    }

    fn exec_at(tx: &Transaction, utxos: Vec<UtxoEntry>, idx: usize) -> Result<(), String> {
        let populated = PopulatedTransaction::new(tx, utxos);
        let cov = CovenantsContext::from_tx(&populated).unwrap();
        let cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        let input = populated.inputs()[idx].clone();
        let mut vm = TxScriptEngine::from_transaction_input(&populated, &input, idx, populated.utxo(idx).unwrap(),
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov), EngineFlags::default());
        vm.execute().map_err(|e| format!("{e:?}"))
    }

    /// Deux séquestres échus fusionnés dans un seul remboursement : la sortie ne vaut qu'un séquestre,
    /// l'autre partirait en frais chez le mineur. Chaque séquestre doit refuser une transaction à plusieurs entrées.
    #[test]
    fn fusion_de_deux_sequestres_refusee() {
        let (merchant, refund, verifier, a1, s1) = setup();
        let a2 = artifact(&merchant, &refund, &verifier, "GET:/meteo#2", DEFAULT_TIMEOUT).unwrap();
        let mk = |b: u8| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([b; 32]), 0), vec![], DEFAULT_TIMEOUT as u64, CB_REFUND);
        let mut tx = Transaction::new(1, vec![mk(1), mk(2)], vec![TransactionOutput { value: s1.valeur - crate::FEE, script_public_key: refund.clone(), covenant: None }], 0, Default::default(), 0, vec![]);
        tx.inputs[0].signature_script = crate::vault_sigscript(&a1, "refund", &[]).unwrap();
        tx.inputs[1].signature_script = crate::vault_sigscript(&a2, "refund", &[]).unwrap();
        let utxos = vec![
            UtxoEntry::new(s1.valeur, pay_to_script_hash_script(&bytecode(&a1)), 0, false, None),
            UtxoEntry::new(s1.valeur, pay_to_script_hash_script(&bytecode(&a2)), 0, false, None),
        ];
        let r0 = exec_at(&tx, utxos.clone(), 0);
        let r1 = exec_at(&tx, utxos, 1);
        eprintln!("entrée 0 : {r0:?}, entrée 1 : {r1:?}");
        assert!(r0.is_err() && r1.is_err(), "fusion acceptée : un séquestre entier partirait en frais");
    }

    fn setup() -> (ScriptPublicKey, ScriptPublicKey, Keypair, SilAbiArtifact, Sequestre) {
        let merchant = pay_to_address_script(&crate::address(&k(3)));
        let refund = pay_to_address_script(&crate::address(&k(1)));
        let verifier = k(7);
        let a = artifact(&merchant, &refund, &verifier, "GET:/meteo#1", DEFAULT_TIMEOUT).unwrap();
        let s = Sequestre { txid: "ab".repeat(32), index: 0, valeur: 30_000_000, requete: "GET:/meteo#1".into(), timeout: DEFAULT_TIMEOUT };
        (merchant, refund, verifier, a, s)
    }

    #[test]
    fn reclamation_construite_par_l_outil_valide() {
        let (merchant, _, verifier, a, s) = setup();
        let (p, r) = proof(&verifier, &s, "contenu livre").unwrap();
        let tx = build_claim(&a, &s, merchant, crate::FEE, p, r).unwrap();
        exec(&tx, &a, s.valeur).unwrap();
    }

    #[test]
    fn fausse_preuve_refusee() {
        let (merchant, _, _, a, s) = setup();
        let (p, r) = proof(&k(2), &s, "contenu livre").unwrap();
        let tx = build_claim(&a, &s, merchant, crate::FEE, p, r).unwrap();
        assert!(exec(&tx, &a, s.valeur).is_err());
    }

    /// v0.3 : paramètres aberrants (frais négatifs, délai nul) : le vendeur ne peut jamais être payé.
    #[test]
    fn parametres_aberrants_refuses() {
        let (merchant, refund, verifier, _, s) = setup();
        for (timeout, max_fee) in [(0i64, MAX_FEE), (DEFAULT_TIMEOUT, -1)] { // délai négatif : refusé dès la compilation
            let args: Vec<ArtifactValue> = vec![
                spk_hash(&merchant).to_vec().into(),
                spk_hash(&refund).to_vec().into(),
                xonly(&verifier).into(),
                h(s.requete.as_bytes()).to_vec().into(),
                timeout.into(),
                max_fee.into(),
            ];
            let a = compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default()).unwrap();
            let (p, r) = proof(&verifier, &s, "contenu livre").unwrap();
            let tx = build_claim(&a, &s, merchant.clone(), 0, p, r).unwrap();
            assert!(exec(&tx, &a, s.valeur).is_err(), "délai {timeout}, frais max {max_fee}");
        }
    }

    #[test]
    fn remboursement_construit_par_l_outil_valide() {
        let (_, refund, _, a, s) = setup();
        let tx = build_refund(&a, &s, refund, crate::FEE).unwrap();
        exec(&tx, &a, s.valeur).unwrap();
    }

    #[test]
    fn delai_trop_court_refuse() {
        let (merchant, refund, verifier, _, _) = setup();
        assert!(artifact(&merchant, &refund, &verifier, "x", MIN_TIMEOUT - 1).is_err());
    }

    #[test]
    fn masses_du_sequestre() {
        let (merchant, refund, verifier, a, s) = setup();
        let (p, r) = proof(&verifier, &s, "contenu livre").unwrap();
        let utxo = UtxoEntry::new(s.valeur, pay_to_script_hash_script(&bytecode(&a)), 0, false, None);
        for tx in [build_claim(&a, &s, merchant, crate::FEE, p, r).unwrap(), build_refund(&a, &s, refund, crate::FEE).unwrap()] {
            let m = crate::masse::masses(&tx, std::slice::from_ref(&utxo)).unwrap();
            eprintln!("calcul {} g, transitoire {} g, stockage {} g, frais requis {} sompi", m.compute, m.transient, m.storage, m.compute * 100);
            assert!(m.standard() && m.compute * 100 <= crate::FEE);
        }
    }
    /// Cible 8 (Red Team, 26 nov. 2026) : pire cas du budget de calcul du séquestre, branche par
    /// branche, sous la limite exacte du réseau pour le budget déclaré par l'outil.
    #[test]
    fn budget_de_calcul_branche_par_branche() {
        let (merchant, refund, verifier, a, s) = setup();
        let utxo = |v: u64| vec![UtxoEntry::new(v, pay_to_script_hash_script(&bytecode(&a)), 0, false, None)];
        let (p, r) = proof(&verifier, &s, "contenu livre").unwrap();
        let claim = crate::masse::unites_sous_la_limite_du_reseau(&build_claim(&a, &s, merchant.clone(), crate::FEE, p.clone(), r).unwrap(), utxo(s.valeur)).unwrap();
        let rembourse = crate::masse::unites_sous_la_limite_du_reseau(&build_refund(&a, &s, refund, crate::FEE).unwrap(), utxo(s.valeur)).unwrap();
        // Séquestre de valeur maximale et index de sortie élevé : mêmes branches, opérandes les plus longs.
        // (Un index ≥ 2^31 ne tient pas dans `as byte[4]`, nombre signé : `claim` échouerait et seul
        // `refund` resterait. Sans portée : une transaction n'a jamais autant de sorties.)
        for index in [127u32, 128, 255, 256, 32_767, 32_768, 8_388_608] {
            let si = Sequestre { index, ..s.clone() };
            let (pi, ri) = proof(&verifier, &si, "x").unwrap();
            exec(&build_claim(&a, &si, merchant.clone(), crate::FEE, pi, ri).unwrap(), &a, si.valeur).unwrap_or_else(|e| panic!("index {index} : {e}"));
        }
        let gros = Sequestre { valeur: 2_900_000_000_000_000_000, index: i32::MAX as u32, ..s.clone() };
        let (p2, r2) = proof(&verifier, &gros, "x").unwrap();
        let claim_max = crate::masse::unites_sous_la_limite_du_reseau(&build_claim(&a, &gros, merchant.clone(), crate::FEE, p2, r2).unwrap(), utxo(gros.valeur)).unwrap();
        eprintln!("séquestre : claim {claim}, claim opérandes maximaux {claim_max}, refund {rembourse} unités de script");
        assert!(claim.max(claim_max).div_ceil(10_000) <= CB_CLAIM as u64 && rembourse.div_ceil(10_000) <= CB_REFUND as u64);
        // Budget trop court d'une unité : refusé, la mesure est bien celle du réseau.
        let mut court = build_claim(&a, &s, merchant, crate::FEE, p, r).unwrap();
        court.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget((claim / 10_000) as u16 - 1).into();
        assert!(crate::masse::unites_sous_la_limite_du_reseau(&court, utxo(s.valeur)).is_err());
    }
}

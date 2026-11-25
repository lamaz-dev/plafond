//! Cœur v0.6 (budget sans mémoire) : comportement du contrat contre le vrai moteur de script.
//! Le verrou relatif est donné par `sequence` : le script exige `sequence ≥ délai` (OpCheckSequenceVerify),
//! et le réseau exige que la pièce ait réellement cet âge (check_sequence_lock, testé côté outil).
mod common;
use common::{bytecode, compile_contract, encode_entry_sig_script, execute_input_with_covenants, push_redeem_script};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use secp256k1::{Keypair, Message};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::CompileOptions;

const SOURCE: &str = include_str!("coeur.sil");
const C: i64 = 200_000_000; // capacité : 2 KAS
const R: i64 = 86_400; // période de recharge
const V: u64 = 1_000_000_000; // 10 KAS dans la pièce
const FEE: u64 = 1_000_000;

fn kp(b: u8) -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
}
fn x(b: u8) -> Vec<u8> {
    kp(b).x_only_public_key().0.serialize().to_vec()
}
fn p2pk(k: &Keypair) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(k.x_only_public_key().0.serialize());
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}
fn art_avec(c: i64, r: i64) -> SilAbiArtifact {
    compile_contract(SOURCE, &[x(1).into(), x(2).into(), c.into(), r.into()], CompileOptions::default()).unwrap()
}
fn art() -> SilAbiArtifact {
    art_avec(C, R)
}
fn moi(a: &SilAbiArtifact) -> ScriptPublicKey {
    pay_to_script_hash_script(&bytecode(a))
}

/// Exécute l'entrée 0. `valeurs` : valeur de chaque pièce du coffre en entrée (toutes à la même adresse).
fn run_n(a: &SilAbiArtifact, signer: u8, entry: &str, valeurs: &[u64], outs: Vec<(u64, ScriptPublicKey)>, seq: u64) -> bool {
    let inputs = (0..valeurs.len())
        .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), i as u32), vec![], seq, 1000))
        .collect();
    let outputs = outs.into_iter().map(|(v, s)| TransactionOutput { value: v, script_public_key: s, covenant: None }).collect();
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let utxos: Vec<UtxoEntry> = valeurs.iter().map(|v| UtxoEntry::new(*v, moi(a), 0, false, None)).collect();
    let r = SigHashReusedValuesUnsync::new();
    let h = calc_schnorr_signature_hash(&PopulatedTransaction::new(&tx, utxos.clone()), 0, SIG_HASH_ALL, &r);
    let mut sig = kp(signer).sign_schnorr(Message::from_digest_slice(h.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut ss = encode_entry_sig_script(a, entry, &[ArtifactValue::from(sig)]).unwrap();
    ss.extend(push_redeem_script(&bytecode(a)));
    tx.inputs[0].signature_script = ss;
    execute_input_with_covenants(tx, utxos, 0).is_ok()
}
fn run(a: &SilAbiArtifact, signer: u8, entry: &str, outs: Vec<(u64, ScriptPublicKey)>, seq: u64) -> bool {
    run_n(a, signer, entry, &[V], outs, seq)
}
/// Délai exigé pour dépenser `spent` (paiement + frais).
fn attente(spent: u64) -> u64 {
    ((spent as i64 * R + C - 1) / C) as u64
}
fn vendeur() -> ScriptPublicKey {
    p2pk(&kp(9))
}

#[test]
fn paiement_au_rythme_permis() {
    let a = art();
    let pay = |montant: u64, seq: u64| run(&a, 2, "pay", vec![(montant, vendeur()), (V - montant - FEE, moi(&a))], seq);
    let w = attente(50_000_000 + FEE);
    assert!(pay(50_000_000, w), "paiement à l'heure accepté");
    assert!(pay(50_000_000, w + 1_000_000), "paiement après une longue attente accepté");
    assert!(!pay(50_000_000, w - 1), "paiement trop tôt refusé");
    assert!(!pay(50_000_000, 0), "paiement sans attente refusé");
    assert!(!pay(50_000_000, u64::MAX), "verrou relatif désactivé refusé");
    assert!(!pay(50_000_000, (1u64 << 63) | w), "bit « verrou désactivé » refusé même avec un délai suffisant");
    // Le réseau ne compte que 32 bits de verrou : une `sequence` au-delà n'achète aucune attente.
    assert!(!pay(50_000_000, 1u64 << 32), "sequence 2^32 (vue comme 0 par le réseau) refusée");
    assert!(pay(50_000_000, (1u64 << 32) | w), "bits hauts ignorés : seul le délai réel compte");
    assert!(pay(C as u64 - FEE, R as u64), "capacité exacte (paiement + frais) après une période entière");
    assert!(!pay(C as u64 - FEE + 1, R as u64 * 10), "un sompi au-delà de la capacité refusé, quelle que soit l'attente");
    // Le plus petit paiement exige quand même au moins une unité DAA : pas d'enchaînement dans un même bloc.
    assert_eq!(attente(1), 1);
    assert!(!run(&a, 2, "pay", vec![(1, vendeur()), (V - 1, moi(&a))], 0), "un sompi sans attente refusé");
    assert!(run(&a, 2, "pay", vec![(1, vendeur()), (V - 1, moi(&a))], 1), "un sompi après une unité accepté");
}

#[test]
fn seul_l_agent_paie_et_seul_le_proprietaire_controle() {
    let a = art();
    let w = attente(50_000_000 + FEE);
    let outs = vec![(50_000_000, vendeur()), (V - 50_000_000 - FEE, moi(&a))];
    assert!(!run(&a, 9, "pay", outs.clone(), w), "autre signataire refusé");
    assert!(!run(&a, 1, "pay", outs, w), "le propriétaire n'utilise pas l'entrée de l'agent");
    assert!(run(&a, 1, "ownerControl", vec![(V - FEE, p2pk(&kp(1)))], 0), "propriétaire : retrait total immédiat");
    assert!(run(&a, 1, "ownerControl", vec![(V / 2, p2pk(&kp(1))), (V / 2 - FEE, moi(&a))], 0), "propriétaire : retrait partiel");
    assert!(!run(&a, 2, "ownerControl", vec![(V - FEE, p2pk(&kp(2)))], R as u64), "l'agent ne peut pas utiliser ownerControl");
}

#[test]
fn forme_de_la_transaction_imposee() {
    let a = art();
    let w = attente(C as u64);
    let m = 50_000_000u64;
    assert!(!run(&a, 2, "pay", vec![(m, vendeur()), (V - m - FEE, vendeur())], w), "continuation détournée refusée");
    assert!(!run(&a, 2, "pay", vec![(m, moi(&a)), (V - m - FEE, moi(&a))], w), "paiement vers le coffre lui-même refusé");
    assert!(!run(&a, 2, "pay", vec![(V - m - FEE, moi(&a)), (m, vendeur())], w), "sorties inversées refusées");
    assert!(!run(&a, 2, "pay", vec![(m, vendeur())], w), "sans continuation refusé");
    assert!(!run(&a, 2, "pay", vec![(m, vendeur()), (V - 2 * m - FEE, moi(&a)), (m, p2pk(&kp(8)))], w), "troisième sortie refusée");
    // Petite troisième sortie, frais compris dans la capacité : refusée (un seul bénéficiaire).
    assert!(!run(&a, 2, "pay", vec![(m, vendeur()), (V - m - FEE - 1_000, moi(&a)), (1_000, p2pk(&kp(8)))], w), "troisième sortie, même minuscule, refusée");
    // Les frais sont comptés dans la dépense : de gros frais consomment la capacité comme un paiement.
    let gros_frais = 100_000_000u64;
    assert!(!run(&a, 2, "pay", vec![(m, vendeur()), (V - m - gros_frais, moi(&a))], attente(m + gros_frais) - 1), "frais comptés dans le délai");
    assert!(run(&a, 2, "pay", vec![(m, vendeur()), (V - m - gros_frais, moi(&a))], attente(m + gros_frais)), "frais comptés, puis acceptés à l'heure");
    assert!(!run(&a, 2, "pay", vec![(m, vendeur()), (V - C as u64 - 1, moi(&a))], R as u64 * 10), "frais faisant dépasser la capacité refusés");
}

#[test]
fn fusion_de_pieces_refusee() {
    // R26 : deux pièces du coffre en entrée, une seule continuation ; sans la règle « une entrée »,
    // la valeur de la seconde partirait en frais sans être comptée.
    let a = art();
    let m = 50_000_000u64;
    let outs = vec![(m, vendeur()), (V - m - FEE, moi(&a))];
    assert!(!run_n(&a, 2, "pay", &[V, V], outs, R as u64), "deux pièces fusionnées refusées");
}

#[test]
fn parametres_aberrants_refuses() {
    let m = 1_000_000u64;
    let essai = |c: i64, r: i64| {
        let a = art_avec(c, r);
        run(&a, 2, "pay", vec![(m, vendeur()), (V - m - 1_000, moi(&a))], u32::MAX as u64)
    };
    assert!(essai(C, R), "témoin : paramètres sains acceptés");
    assert!(!essai(0, R), "capacité nulle");
    assert!(!essai(-C, R), "capacité négative");
    assert!(!essai(C, 0), "période nulle");
    assert!(!essai(C, -R), "période négative");
    assert!(!essai(C, 1i64 << 32), "période au-delà du verrou 32 bits");
    assert!(essai(C, (1i64 << 32) - 1), "période maximale exacte acceptée");
    assert!(!essai(i64::MAX / 1000 + 1, 1000), "capacité × période déborderait");
}

/// Délai de 2^32 : avec period = 2^33, dépenser la moitié de la capacité exigerait 2^32 unités, que
/// le verrou 32 bits lirait comme 0. Double protection : la garde `period < 2^32` du contrat, et le
/// contrôle `délai ∈ [0, 2^32)` que le compilateur ajoute avant le verrou (spec/coeur-bytecode.md).
#[test]
fn delai_tronque_a_32_bits_impossible() {
    let a = art_avec(C, 1i64 << 33);
    let s = (C / 2) as u64;
    assert_eq!((s as i64 * (1i64 << 33) + C - 1) / C, 1i64 << 32);
    assert!(!run(&a, 2, "pay", vec![(s - FEE, vendeur()), (V - s, moi(&a))], 0), "délai tronqué refusé");
    assert!(!run(&a, 2, "pay", vec![(s - FEE, vendeur()), (V - s, moi(&a))], u32::MAX as u64), "et rien d'autre ne passe");
}

#[test]
fn taille_du_coeur() {
    let a = art();
    let n = bytecode(&a).len();
    eprintln!("Cœur v0.6 : {n} octets ; attente pour 0,5 KAS = {} DAA", attente(50_000_000 + FEE));
    assert!(n < 300, "le cœur doit rester minimal ({n} octets)");
}

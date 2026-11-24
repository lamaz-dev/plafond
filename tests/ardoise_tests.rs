mod common;

use blake2b_simd::Params;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Message};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::CompileOptions;

use common::{bytecode, compile_contract, encode_entry_sig_script, execute_input_with_covenants, push_redeem_script};

const SOURCE: &str = include_str!("ardoise.sil");
const DEPOT: u64 = 100_000_000; // 1 KAS déposé sur l'ardoise
const TIMEOUT: i64 = 864_000; // ~24 h
const MAX_FEE: i64 = 3_000_000;
const FEE: u64 = 1_000_000;
const ARDOISE_TXID: [u8; 32] = [5; 32];

fn kp(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[seed; 32]).unwrap()
}
fn p2pk(k: &Keypair) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(k.x_only_public_key().0.serialize());
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}
fn h(data: &[u8]) -> Vec<u8> {
    Params::new().hash_length(32).hash(data).as_bytes().to_vec()
}
fn spk_hash(spk: &ScriptPublicKey) -> Vec<u8> {
    let bytes: Vec<u8> = spk.version().to_be_bytes().into_iter().chain(spk.script().iter().copied()).collect();
    h(&bytes)
}
fn xonly(k: &Keypair) -> Vec<u8> {
    k.x_only_public_key().0.serialize().to_vec()
}

struct Ctx {
    vendeur: Keypair,
    agent: Keypair,
    proprietaire: ScriptPublicKey,
}

fn ctx() -> Ctx {
    Ctx { vendeur: kp(10), agent: kp(20), proprietaire: p2pk(&kp(1)) }
}

fn compile_avec(c: &Ctx, timeout: i64, max_fee: i64) -> SilAbiArtifact {
    let args: Vec<ArtifactValue> = vec![
        spk_hash(&p2pk(&c.vendeur)).into(),
        xonly(&c.vendeur).into(),
        spk_hash(&c.proprietaire).into(),
        xonly(&c.agent).into(),
        timeout.into(),
        max_fee.into(),
    ];
    compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile")
}
fn compile(c: &Ctx) -> SilAbiArtifact {
    compile_avec(c, TIMEOUT, MAX_FEE)
}

/// Bon cumulé : signature de l'agent sur blake2b(txid || index sur 4 octets || total sur 8 octets).
fn bon_pour(signataire: &Keypair, txid: [u8; 32], index: u32, total: i64) -> Vec<u8> {
    let mut m = txid.to_vec();
    m.extend_from_slice(&index.to_le_bytes());
    m.extend_from_slice(&total.to_le_bytes());
    let digest: [u8; 32] = h(&m).try_into().unwrap();
    signataire.sign_schnorr(Message::from_digest(digest)).as_ref().to_vec()
}
fn bon(c: &Ctx, total: i64) -> Vec<u8> {
    bon_pour(&c.agent, ARDOISE_TXID, 0, total)
}

fn out(value: u64, spk: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value, script_public_key: spk, covenant: None }
}

/// Dépense l'ardoise ; `signataire` signe la transaction pour `close` (None pour `refund`).
fn depenser(a: &SilAbiArtifact, sorties: Vec<TransactionOutput>, sequence: u64, entry: &str, signataire: Option<&Keypair>, args: Vec<ArtifactValue>) -> Result<(), TxScriptError> {
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes(ARDOISE_TXID), 0), vec![], sequence, 1000);
    let mut tx = Transaction::new(1, vec![input], sorties, 0, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(DEPOT, pay_to_script_hash_script(&bytecode(a)), 0, false, None);
    let mut tous: Vec<ArtifactValue> = vec![];
    if let Some(k) = signataire {
        let reused = SigHashReusedValuesUnsync::new();
        let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
        let sighash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
        let mut sig = k.sign_schnorr(Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        tous.push(sig.into());
    }
    tous.extend(args);
    let mut ss = encode_entry_sig_script(a, entry, &tous).expect("sigscript");
    ss.extend(push_redeem_script(&bytecode(a)));
    tx.inputs[0].signature_script = ss;
    execute_input_with_covenants(tx, vec![utxo], 0)
}

/// Clôture standard : le vendeur reçoit `total` moins les frais, le propriétaire le reste.
fn clore(c: &Ctx, a: &SilAbiArtifact, signataire: &Keypair, voucher: Vec<u8>, total: i64, pour_vendeur: u64, pour_proprio: u64) -> Result<(), TxScriptError> {
    let sorties = vec![out(pour_vendeur, p2pk(&c.vendeur)), out(pour_proprio, c.proprietaire.clone())];
    depenser(a, sorties, 0, "close", Some(signataire), vec![voucher.into(), total.into()])
}

#[test]
fn vendeur_encaisse_le_dernier_bon_et_le_reste_revient_au_proprietaire() {
    let c = ctx();
    let a = compile(&c);
    let total = 5_000_000; // 0,05 KAS cumulés sur des centaines d'appels
    let r = clore(&c, &a, &c.vendeur, bon(&c, total), total, total as u64 - FEE, DEPOT - total as u64);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn seul_le_vendeur_peut_clore() {
    // L'agent aurait intérêt à clore avec un ancien bon plus petit.
    let c = ctx();
    let a = compile(&c);
    assert!(clore(&c, &a, &c.agent, bon(&c, 1_000_000), 1_000_000, 0, DEPOT - 1_000_000).is_err());
}

#[test]
fn bon_signe_par_un_autre_refuse() {
    let c = ctx();
    let a = compile(&c);
    let faux = bon_pour(&kp(66), ARDOISE_TXID, 0, 5_000_000);
    assert!(clore(&c, &a, &c.vendeur, faux, 5_000_000, 4_000_000, DEPOT - 5_000_000).is_err());
}

#[test]
fn bon_d_une_autre_ardoise_refuse() {
    let c = ctx();
    let a = compile(&c);
    for (txid, index) in [([6u8; 32], 0u32), (ARDOISE_TXID, 1)] {
        let ailleurs = bon_pour(&c.agent, txid, index, 5_000_000);
        assert!(clore(&c, &a, &c.vendeur, ailleurs, 5_000_000, 4_000_000, DEPOT - 5_000_000).is_err(), "{index}");
    }
}

#[test]
fn total_gonfle_par_le_vendeur_refuse() {
    let c = ctx();
    let a = compile(&c);
    let r = clore(&c, &a, &c.vendeur, bon(&c, 5_000_000), 9_000_000, 8_000_000, DEPOT - 9_000_000);
    assert!(r.is_err());
}

#[test]
fn reste_du_proprietaire_protege() {
    let c = ctx();
    let a = compile(&c);
    let total = 5_000_000i64;
    // reste amputé
    assert!(clore(&c, &a, &c.vendeur, bon(&c, total), total, total as u64 - FEE, DEPOT - total as u64 - 1).is_err());
    // reste envoyé ailleurs
    let sorties = vec![out(total as u64 - FEE, p2pk(&c.vendeur)), out(DEPOT - total as u64, p2pk(&kp(99)))];
    assert!(depenser(&a, sorties, 0, "close", Some(&c.vendeur), vec![bon(&c, total).into(), total.into()]).is_err());
    // part du vendeur envoyée ailleurs
    let sorties = vec![out(total as u64 - FEE, p2pk(&kp(99))), out(DEPOT - total as u64, c.proprietaire.clone())];
    assert!(depenser(&a, sorties, 0, "close", Some(&c.vendeur), vec![bon(&c, total).into(), total.into()]).is_err());
}

#[test]
fn frais_bornes() {
    let c = ctx();
    let a = compile(&c);
    let total = 5_000_000i64;
    assert!(clore(&c, &a, &c.vendeur, bon(&c, total), total, total as u64 - MAX_FEE as u64 - 1, DEPOT - total as u64).is_err());
    assert!(clore(&c, &a, &c.vendeur, bon(&c, total), total, total as u64 - MAX_FEE as u64, DEPOT - total as u64).is_ok());
}

#[test]
fn une_seule_sortie_seulement_si_le_reste_est_infime() {
    let c = ctx();
    let a = compile(&c);
    let seul = |total: i64| depenser(&a, vec![out(DEPOT - FEE, p2pk(&c.vendeur))], 0, "close", Some(&c.vendeur), vec![bon(&c, total).into(), total.into()]);
    assert!(seul(DEPOT as i64 - MAX_FEE).is_ok()); // reste ≤ frais max : le vendeur prend tout
    assert!(seul(DEPOT as i64 - MAX_FEE - 1).is_err()); // reste plus grand : il revient au propriétaire
}

#[test]
fn total_nul_negatif_ou_superieur_au_depot_refuse() {
    let c = ctx();
    let a = compile(&c);
    // Sorties choisies pour satisfaire toutes les autres règles : seule la borne sur `total` refuse.
    for total in [0i64, -5, DEPOT as i64 + 1] {
        let (vendeur, proprio) = ((total - MAX_FEE).max(0) as u64, (DEPOT as i64 - total).max(0) as u64);
        assert!(clore(&c, &a, &c.vendeur, bon(&c, total), total, vendeur, proprio).is_err(), "{total}");
    }
}

#[test]
fn parametres_aberrants_refuses() {
    let c = ctx();
    // Sorties valables pour tout le reste (aucun frais) : seule la règle sur les paramètres refuse.
    let total = 5_000_000i64;
    for (timeout, max_fee) in [(TIMEOUT, -1i64), (0, MAX_FEE)] {
        let a = compile_avec(&c, timeout, max_fee);
        assert!(clore(&c, &a, &c.vendeur, bon(&c, total), total, total as u64, DEPOT - total as u64).is_err(), "{timeout} {max_fee}");
    }
}

#[test]
fn remboursement_au_proprietaire_apres_delai_seulement() {
    let c = ctx();
    let a = compile(&c);
    let rembourser = |seq: u64, vers: ScriptPublicKey| depenser(&a, vec![out(DEPOT - FEE, vers)], seq, "refund", None, vec![]);
    assert!(rembourser(TIMEOUT as u64, c.proprietaire.clone()).is_ok());
    assert!(rembourser(TIMEOUT as u64 - 1, c.proprietaire.clone()).is_err());
    assert!(rembourser(TIMEOUT as u64, p2pk(&kp(99))).is_err());
}

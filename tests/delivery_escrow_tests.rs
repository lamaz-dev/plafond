mod common;

use blake2b_simd::Params;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Message};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::CompileOptions;

use common::{bytecode, compile_contract, encode_entry_sig_script, execute_input_with_covenants, push_redeem_script};

const SOURCE: &str = include_str!("delivery_escrow.sil");
const VALUE: u64 = 20_000_000; // 0,2 KAS en séquestre
const TIMEOUT: i64 = 36_000; // ~1 h
const MAX_FEE: i64 = 3_000_000;
const FEE: u64 = 1_000_000;

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

struct Ctx {
    merchant: ScriptPublicKey,
    owner: ScriptPublicKey,
    verifier: Keypair,
    request: Vec<u8>,
}

fn ctx() -> Ctx {
    Ctx { merchant: p2pk(&kp(10)), owner: p2pk(&kp(1)), verifier: kp(77), request: h(b"GET /meteo-kaspa #commande-42") }
}

fn compile(c: &Ctx) -> SilAbiArtifact {
    let args: Vec<ArtifactValue> = vec![
        spk_hash(&c.merchant).into(),
        spk_hash(&c.owner).into(),
        c.verifier.x_only_public_key().0.serialize().to_vec().into(),
        c.request.clone().into(),
        TIMEOUT.into(),
        MAX_FEE.into(),
    ];
    compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile")
}

/// Sortie du séquestre dépensée par `spend` (v0.3 : la preuve la désigne).
const ESCROW_TXID: [u8; 32] = [9; 32];

/// Preuve de livraison (v0.3) : signature du vérificateur sur
/// blake2b(requestHash || resultHash || txid du séquestre || index sur 4 octets petit-boutiste).
fn proof(signer: &Keypair, request: &[u8], result: &[u8]) -> Vec<u8> {
    proof_pour(signer, request, result, ESCROW_TXID, 0)
}

fn proof_pour(signer: &Keypair, request: &[u8], result: &[u8], txid: [u8; 32], index: u32) -> Vec<u8> {
    let mut m = request.to_vec();
    m.extend_from_slice(result);
    m.extend_from_slice(&txid);
    m.extend_from_slice(&index.to_le_bytes());
    let digest: [u8; 32] = h(&m).try_into().unwrap();
    signer.sign_schnorr(Message::from_digest(digest)).as_ref().to_vec()
}

fn spend(escrow: &SilAbiArtifact, to: ScriptPublicKey, value: u64, sequence: u64, entry: &str, args: Vec<ArtifactValue>) -> Result<(), TxScriptError> {
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes(ESCROW_TXID), 0), vec![], sequence, 1000);
    let out = TransactionOutput { value, script_public_key: to, covenant: None };
    let mut tx = Transaction::new(1, vec![input], vec![out], 0, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(VALUE, pay_to_script_hash_script(&bytecode(escrow)), 0, false, None);
    let mut ss = encode_entry_sig_script(escrow, entry, &args).expect("sigscript");
    ss.extend(push_redeem_script(&bytecode(escrow)));
    tx.inputs[0].signature_script = ss;
    execute_input_with_covenants(tx, vec![utxo], 0)
}

fn claim(c: &Ctx, escrow: &SilAbiArtifact, to: ScriptPublicKey, value: u64, proof: Vec<u8>, result: Vec<u8>) -> Result<(), TxScriptError> {
    spend(escrow, to, value, 0, "claim", vec![proof.into(), result.into()])
        .inspect_err(|e| eprintln!("refus attendu: {e:?}"))
        .map(|_| { let _ = c; })
}

#[test]
fn vendeur_paye_contre_preuve_de_livraison() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"Meteo du reseau Kaspa : 10 blocs/s");
    let r = claim(&c, &e, c.merchant.clone(), VALUE - FEE, proof(&c.verifier, &c.request, &result), result);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn preuve_signee_par_un_autre_refusee() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"resultat");
    assert!(claim(&c, &e, c.merchant.clone(), VALUE - FEE, proof(&kp(66), &c.request, &result), result).is_err());
}

#[test]
fn preuve_d_une_autre_commande_refusee() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"resultat");
    let other = h(b"GET /meteo-kaspa #commande-43");
    assert!(claim(&c, &e, c.merchant.clone(), VALUE - FEE, proof(&c.verifier, &other, &result), result).is_err());
}

#[test]
fn preuve_valide_mais_argent_detourne_refuse() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"resultat");
    assert!(claim(&c, &e, p2pk(&kp(99)), VALUE - FEE, proof(&c.verifier, &c.request, &result), result).is_err());
}

#[test]
fn frais_excessifs_refuses() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"resultat");
    assert!(claim(&c, &e, c.merchant.clone(), VALUE - MAX_FEE as u64 - 1, proof(&c.verifier, &c.request, &result), result).is_err());
}

#[test]
fn remboursement_apres_delai() {
    let c = ctx();
    let e = compile(&c);
    let r = spend(&e, c.owner.clone(), VALUE - FEE, TIMEOUT as u64, "refund", vec![]);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn remboursement_avant_delai_refuse() {
    let c = ctx();
    let e = compile(&c);
    let r = spend(&e, c.owner.clone(), VALUE - FEE, TIMEOUT as u64 - 1, "refund", vec![]);
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn remboursement_vers_un_autre_refuse() {
    let c = ctx();
    let e = compile(&c);
    let r = spend(&e, p2pk(&kp(99)), VALUE - FEE, TIMEOUT as u64, "refund", vec![]);
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn mesure_budget_sequestre() {
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT;
    use kaspa_consensus_core::tx::{PopulatedTransaction, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    let c = ctx();
    let e = compile(&c);
    let result = h(b"resultat");
    let pr = proof(&c.verifier, &c.request, &result);
    for (seq, entry, args, to) in [
        (0u64, "claim", vec![ArtifactValue::from(pr.clone()), result.clone().into()], c.merchant.clone()),
        (TIMEOUT as u64, "refund", vec![], c.owner.clone()),
    ] {
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), 0), vec![], seq, 1000);
        let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput { value: VALUE - FEE, script_public_key: to, covenant: None }], 0, Default::default(), 0, vec![]);
        let utxo = UtxoEntry::new(VALUE, pay_to_script_hash_script(&bytecode(&e)), 0, false, None);
        let mut ss = encode_entry_sig_script(&e, entry, &args).unwrap();
        ss.extend(push_redeem_script(&bytecode(&e)));
        tx.inputs[0].signature_script = ss;
        let populated = PopulatedTransaction::new(&tx, vec![utxo]);
        let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
        let cache = Cache::new(100);
        let reused = SigHashReusedValuesUnsync::new();
        let input = populated.inputs()[0].clone();
        let mut vm = TxScriptEngine::from_transaction_input(&populated, &input, 0, populated.utxo(0).unwrap(),
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov_ctx), EngineFlags::default());
        vm.execute().expect("valide");
        let units = vm.used_script_units().0;
        eprintln!("{entry}: {units} unités => budget minimal {}", units.div_ceil(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT));
    }
}

#[test]
fn fusion_de_deux_sequestres_refusee() {
    // v0.2 : deux séquestres dépensés ensemble vers une seule sortie qui ne vaut qu'un séquestre.
    let c = ctx();
    let e1 = compile(&c);
    let c2 = Ctx { request: h(b"GET /meteo-kaspa #commande-43"), ..ctx() };
    let e2 = compile(&c2);
    let mk = |b: u8, e: &SilAbiArtifact| {
        let mut i = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([b; 32]), 0), vec![], TIMEOUT as u64, 1000);
        let mut ss = encode_entry_sig_script(e, "refund", &[]).unwrap();
        ss.extend(push_redeem_script(&bytecode(e)));
        i.signature_script = ss;
        i
    };
    let tx = Transaction::new(1, vec![mk(1, &e1), mk(2, &e2)], vec![TransactionOutput { value: VALUE - FEE, script_public_key: c.owner.clone(), covenant: None }], 0, Default::default(), 0, vec![]);
    let utxos = vec![
        UtxoEntry::new(VALUE, pay_to_script_hash_script(&bytecode(&e1)), 0, false, None),
        UtxoEntry::new(VALUE, pay_to_script_hash_script(&bytecode(&e2)), 0, false, None),
    ];
    assert!(execute_input_with_covenants(tx.clone(), utxos.clone(), 0).is_err());
    assert!(execute_input_with_covenants(tx, utxos, 1).is_err());
}

/// v0.3 (R40) : une preuve valide pour un autre séquestre de la même commande ne paie pas celui-ci.
#[test]
fn preuve_d_un_autre_sequestre_refusee() {
    let c = ctx();
    let e = compile(&c);
    let result = h(b"meteo: 24 degres");
    for (txid, index) in [([8u8; 32], 0u32), (ESCROW_TXID, 1)] {
        let p = proof_pour(&c.verifier, &c.request, &result, txid, index);
        assert!(claim(&c, &e, c.merchant.clone(), VALUE - FEE, p, result.clone()).is_err(), "preuve rejouée acceptée");
    }
}

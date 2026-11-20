mod common;

use blake2b_simd::Params;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript_errors::TxScriptError;
use secp256k1::{Keypair, Message};
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::CompileOptions;

use common::{COV_A, COV_B, bytecode, compile_contract, encode_entry_sig_script, execute_input_with_covenants, push_redeem_script};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::CovenantBinding;

const SOURCE: &str = include_str!("agent_budget.sil");

const CAPACITY: i64 = 2_000_000_000; // 20 KAS
const REFILL: i64 = 6_048_000; // ~1 semaine à 10 DAA/s
const MAX_FEE: i64 = 100_000;
const VAULT_VALUE: u64 = 10_000_000_000; // 100 KAS dans le coffre
const FEE_T: i64 = 50_000; // frais utilisés dans les tests (décomptés du budget)

thread_local! {
    /// v0.5 : score DAA auquel le réseau a inscrit le coffre dépensé (la recharge court depuis lui).
    /// Par défaut 1 000, l'instant `lastDaa` utilisé par la plupart des tests.
    static INSCRIPTION: std::cell::Cell<u64> = const { std::cell::Cell::new(1_000) };
}

fn kp(seed: u8) -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[seed; 32]).unwrap()
}
fn xonly(k: &Keypair) -> Vec<u8> {
    k.x_only_public_key().0.serialize().to_vec()
}
fn p2pk(k: &Keypair) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(xonly(k));
    s.push(0xac); // OpCheckSig
    ScriptPublicKey::new(0, s.into())
}
fn h(spk: &ScriptPublicKey) -> Vec<u8> {
    let bytes: Vec<u8> = spk.version().to_be_bytes().into_iter().chain(spk.script().iter().copied()).collect();
    Params::new().hash_length(32).hash(&bytes).as_bytes().to_vec()
}

struct Ctx {
    owner: Keypair,
    agent: Keypair,
    payee: ScriptPublicKey,
    payees: [Vec<u8>; 3],
}

fn ctx() -> Ctx {
    let payee = p2pk(&kp(10));
    Ctx { owner: kp(1), agent: kp(2), payees: [h(&payee), h(&p2pk(&kp(11))), h(&p2pk(&kp(12)))], payee }
}

/// Réglages d'un couloir.
#[derive(Clone, Copy)]
struct Cfg {
    lane: i64,
    max_per_payment: i64,
    use_allowlist: i64,
}
const DEFAULT: Cfg = Cfg { lane: 0, max_per_payment: CAPACITY, use_allowlist: 1 };

fn compile(c: &Ctx, tokens: i64, last: i64) -> SilAbiArtifact {
    compile_cfg(c, DEFAULT, tokens, last)
}

fn compile_cfg(c: &Ctx, cfg: Cfg, tokens: i64, last: i64) -> SilAbiArtifact {
    let args: Vec<ArtifactValue> = vec![
        xonly(&c.owner).into(),
        xonly(&c.agent).into(),
        cfg.lane.into(),
        CAPACITY.into(),
        REFILL.into(),
        cfg.max_per_payment.into(),
        MAX_FEE.into(),
        cfg.use_allowlist.into(),
        c.payees[0].clone().into(),
        c.payees[1].clone().into(),
        c.payees[2].clone().into(),
        tokens.into(),
        last.into(),
    ];
    compile_contract(SOURCE, &args, CompileOptions::default()).expect("compile")
}

/// Construit et exécute une dépense du coffre.
/// `outputs` : liste complète des sorties. `entry`/`args_fn` : point d'entrée et arguments (la signature est ajoutée en tête).
fn run(
    vault: &SilAbiArtifact,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    signer: &Keypair,
    entry: &str,
    extra_args: Vec<ArtifactValue>,
) -> Result<(), TxScriptError> {
    run_cov(vault, outputs, lock_time, signer, entry, extra_args, Some(COV_A))
}

/// Comme `run`, en précisant l'identifiant de covenant porté par l'UTXO du coffre (None = pas de lignée).
fn run_cov(
    vault: &SilAbiArtifact,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    signer: &Keypair,
    entry: &str,
    extra_args: Vec<ArtifactValue>,
    utxo_cov: Option<Hash>,
) -> Result<(), TxScriptError> {
    run_full(vault, outputs, lock_time, signer, entry, extra_args, utxo_cov, vec![])
}

fn run_full(
    vault: &SilAbiArtifact,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    signer: &Keypair,
    entry: &str,
    extra_args: Vec<ArtifactValue>,
    utxo_cov: Option<Hash>,
    payload: Vec<u8>,
) -> Result<(), TxScriptError> {
    let input = TransactionInput::new_with_compute_budget(
        TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), 0),
        vec![],
        0,
        1000,
    );
    let mut tx = Transaction::new(1, vec![input], outputs, lock_time, Default::default(), 0, payload);
    let utxo = UtxoEntry::new(VAULT_VALUE, pay_to_script_hash_script(&bytecode(vault)), INSCRIPTION.replace(1_000), false, utxo_cov);

    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let sighash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let sig = signer.sign_schnorr(Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap());
    let mut sig_bytes = sig.as_ref().to_vec();
    sig_bytes.push(SIG_HASH_ALL.to_u8());

    let mut args: Vec<ArtifactValue> = vec![sig_bytes.into()];
    args.extend(extra_args);
    let mut sigscript = encode_entry_sig_script(vault, entry, &args).expect("sigscript");
    sigscript.extend(push_redeem_script(&bytecode(vault)));
    tx.inputs[0].signature_script = sigscript;
    execute_input_with_covenants(tx, vec![utxo], 0)
}

fn out(value: u64, spk: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value, script_public_key: spk, covenant: None }
}

/// Sortie de continuation du coffre, liée à sa lignée (identifiant de covenant).
fn cont(value: u64, spk: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value, script_public_key: spk, covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: COV_A }) }
}

/// Paiement standard : `amount` vers `payee`, reste au coffre avec l'état attendu.
fn pay(c: &Ctx, tokens: i64, last: i64, amount: i64, now: i64, next_tokens: i64) -> Result<(), TxScriptError> {
    INSCRIPTION.set(last as u64); // coffre inscrit à l'instant de son dernier état
    let vault = compile(c, tokens, last);
    let next = compile(c, next_tokens - FEE_T, now); // les frais sont décomptés du budget
    let change = VAULT_VALUE - amount as u64 - FEE_T as u64;
    run(
        &vault,
        vec![out(amount as u64, c.payee.clone()), cont(change, pay_to_script_hash_script(&bytecode(&next)))],
        now as u64,
        &c.agent,
        "pay",
        vec![amount.into(), now.into()],
    )
}

#[test]
fn agent_peut_payer_dans_le_budget() {
    let c = ctx();
    // budget plein (20 KAS), paie 1 KAS
    let r = pay(&c, CAPACITY, 1_000, 100_000_000, 1_000, CAPACITY - 100_000_000);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn agent_ne_peut_pas_depasser_le_budget() {
    let c = ctx();
    // il reste 1 KAS, tente 2 KAS sans temps écoulé
    let r = pay(&c, 100_000_000, 1_000, 200_000_000, 1_000, 0);
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn le_budget_se_recharge_avec_le_temps() {
    let c = ctx();
    // budget à 0, la moitié de la période s'écoule => 10 KAS disponibles
    let half = REFILL / 2;
    let ok = pay(&c, 0, 1_000, 1_000_000_000 - FEE_T, 1_000 + half, FEE_T);
    assert!(ok.is_ok(), "{ok:?}");
    let ko = pay(&c, 0, 1_000, 1_000_000_000 - FEE_T + 1, 1_000 + half, 1_000_000_000 - FEE_T + 1);
    eprintln!("refus attendu: {:?}", ko.as_ref().err()); assert!(ko.is_err());
}

#[test]
fn le_budget_inutilise_ne_s_accumule_pas() {
    let c = ctx();
    // 10 périodes d'inactivité : le budget plafonne à 20 KAS, pas 200
    let r = pay(&c, CAPACITY, 1_000, CAPACITY + 1, 1_000 + 10 * REFILL, 0);
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
    let ok = pay(&c, CAPACITY, 1_000, CAPACITY - FEE_T, 1_000 + 10 * REFILL, FEE_T);
    assert!(ok.is_ok(), "{ok:?}");
}

#[test]
fn agent_ne_peut_pas_tricher_sur_l_etat() {
    let c = ctx();
    // paie 1 KAS mais déclare un budget restant plein
    let r = pay(&c, CAPACITY, 1_000, 100_000_000, 1_000, CAPACITY);
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn agent_ne_peut_pas_annoncer_un_instant_futur() {
    let c = ctx();
    let vault = compile(&c, 0, 1_000);
    let now = 1_000 + REFILL; // prétend qu'une semaine est passée…
    let next = compile(&c, 0, now);
    let r = run(
        &vault,
        vec![out(CAPACITY as u64, c.payee.clone()), cont(VAULT_VALUE - CAPACITY as u64 - 50_000, pay_to_script_hash_script(&bytecode(&next)))],
        2_000, // … mais la transaction n'est valable qu'à partir de DAA 2000
        &c.agent,
        "pay",
        vec![CAPACITY.into(), now.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn destinataire_non_autorise_refuse() {
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000, 1_000);
    let r = run(
        &vault,
        vec![out(100_000_000, p2pk(&kp(99))), cont(VAULT_VALUE - 100_000_000 - 50_000, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn agent_ne_peut_pas_detourner_le_reste() {
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000, 1_000);
    // le reste renvoyé au coffre est amputé de 50 KAS
    let r = run(
        &vault,
        vec![out(100_000_000, c.payee.clone()), cont(VAULT_VALUE - 100_000_000 - 5_000_000_000, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn sortie_supplementaire_refusee() {
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000, 1_000);
    let r = run(
        &vault,
        vec![
            out(100_000_000, c.payee.clone()),
            cont(VAULT_VALUE - 100_000_000 - 50_000, pay_to_script_hash_script(&bytecode(&next))),
            out(1_000, p2pk(&kp(99))),
        ],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn mauvaise_cle_refusee_pour_payer() {
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000, 1_000);
    let r = run(
        &vault,
        vec![out(100_000_000, c.payee.clone()), cont(VAULT_VALUE - 100_000_000 - 50_000, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &kp(99),
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err()); assert!(r.is_err());
}

#[test]
fn proprietaire_garde_la_main() {
    let c = ctx();
    let vault = compile(&c, 0, 1_000);
    // le propriétaire récupère tout vers une adresse quelconque, budget épuisé ou non
    let ok = run(&vault, vec![out(VAULT_VALUE - 50_000, p2pk(&kp(42)))], 0, &c.owner, "ownerControl", vec![]);
    assert!(ok.is_ok(), "{ok:?}");
    // l'agent ne peut pas utiliser ce chemin
    let ko = run(&vault, vec![out(VAULT_VALUE - 50_000, p2pk(&kp(42)))], 0, &c.agent, "ownerControl", vec![]);
    eprintln!("refus attendu: {:?}", ko.as_ref().err()); assert!(ko.is_err());
}

// ---------- v0.2 ----------

/// Paiement simple de `amount` vers `payee` avec une configuration donnée.
fn pay_cfg(c: &Ctx, cfg: Cfg, payee: ScriptPublicKey, amount: i64) -> Result<(), TxScriptError> {
    let vault = compile_cfg(c, cfg, CAPACITY, 1_000);
    let next = compile_cfg(c, cfg, CAPACITY - amount - FEE_T, 1_000);
    run(
        &vault,
        vec![out(amount as u64, payee), cont(VAULT_VALUE - amount as u64 - 50_000, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![amount.into(), 1_000i64.into()],
    )
}

#[test]
fn plafond_par_paiement_respecte() {
    let c = ctx();
    let cfg = Cfg { max_per_payment: 50_000_000, ..DEFAULT }; // 0,5 KAS max par paiement
    let ok = pay_cfg(&c, cfg, c.payee.clone(), 50_000_000);
    assert!(ok.is_ok(), "{ok:?}");
    // budget disponible (20 KAS) mais paiement de 1 KAS > plafond
    let ko = pay_cfg(&c, cfg, c.payee.clone(), 100_000_000);
    eprintln!("refus attendu: {:?}", ko.as_ref().err());
    assert!(ko.is_err());
}

#[test]
fn liste_blanche_desactivee_tout_destinataire_accepte() {
    let c = ctx();
    let cfg = Cfg { use_allowlist: 0, ..DEFAULT };
    let r = pay_cfg(&c, cfg, p2pk(&kp(99)), 100_000_000);
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn liste_blanche_activee_inconnu_refuse() {
    let c = ctx();
    let r = pay_cfg(&c, DEFAULT, p2pk(&kp(99)), 100_000_000);
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn couloirs_independants() {
    let c = ctx();
    // couloir 0 épuisé, couloir 1 plein : le couloir 1 peut toujours payer
    let lane0 = Cfg { lane: 0, ..DEFAULT };
    let lane1 = Cfg { lane: 1, ..DEFAULT };
    let a = compile_cfg(&c, lane0, 0, 1_000);
    let b = compile_cfg(&c, lane1, CAPACITY, 1_000);
    assert_ne!(bytecode(&a), bytecode(&b), "chaque couloir a son propre script");
    let ok = pay_cfg(&c, lane1, c.payee.clone(), 100_000_000);
    assert!(ok.is_ok(), "{ok:?}");
}

#[test]
fn impossible_de_combiner_deux_couloirs() {
    let c = ctx();
    let lane0 = compile_cfg(&c, Cfg { lane: 0, ..DEFAULT }, CAPACITY, 1_000);
    let lane1 = compile_cfg(&c, Cfg { lane: 1, ..DEFAULT }, CAPACITY, 1_000);
    let next0 = compile_cfg(&c, Cfg { lane: 0, ..DEFAULT }, CAPACITY - 100_000_000, 1_000);
    let mk_in = |b: u8| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([b; 32]), 0), vec![], 0, 1000);
    // L'agent tente de vider le couloir 1 en le glissant dans une dépense du couloir 0
    let mut tx = Transaction::new(
        1,
        vec![mk_in(7), mk_in(8)],
        vec![
            out(100_000_000, c.payee.clone()),
            cont(VAULT_VALUE - 100_000_000 - 50_000, pay_to_script_hash_script(&bytecode(&next0))),
        ],
        1_000,
        Default::default(),
        0,
        vec![],
    );
    let utxos = vec![
        UtxoEntry::new(VAULT_VALUE, pay_to_script_hash_script(&bytecode(&lane0)), 1_000, false, Some(COV_A)),
        UtxoEntry::new(VAULT_VALUE, pay_to_script_hash_script(&bytecode(&lane1)), 1_000, false, Some(COV_B)),
    ];
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(&tx, utxos.clone());
    let sighash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let mut sig = c.agent.sign_schnorr(Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut ss = encode_entry_sig_script(&lane0, "pay", &[sig.into(), 100_000_000i64.into(), 1_000i64.into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&lane0)));
    tx.inputs[0].signature_script = ss;
    let r = execute_input_with_covenants(tx, utxos, 0);
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

// ---------- v0.3 ----------

#[test]
fn vidage_par_les_frais_refuse() {
    let c = ctx();
    // Il reste 0,0004 KAS de budget : un paiement d'1 sompi avec 0,0005 KAS de frais dépasse le budget.
    let vault = compile(&c, 40_000, 1_000);
    let next = compile(&c, 0, 1_000);
    let r = run(
        &vault,
        vec![out(1, c.payee.clone()), cont(VAULT_VALUE - 1 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![1i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn frais_au_dessus_du_plafond_refuses() {
    let c = ctx();
    let fee = MAX_FEE + 1;
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 1_000 - fee, 1_000);
    let r = run(
        &vault,
        vec![out(1_000, c.payee.clone()), cont(VAULT_VALUE - 1_000 - fee as u64, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![1_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn clone_sans_lignee_refuse() {
    let c = ctx();
    // Mêmes script et état, mais UTXO envoyé à l'adresse sans identifiant de covenant.
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000 - FEE_T, 1_000);
    let r = run_cov(
        &vault,
        vec![out(100_000_000, c.payee.clone()), out(VAULT_VALUE - 100_000_000 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
        None,
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn continuation_hors_lignee_refusee() {
    let c = ctx();
    // Le reste part vers le bon script mais sans lien de lignée : le coffre « sortirait » de sa lignée.
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000 - FEE_T, 1_000);
    let r = run(
        &vault,
        vec![out(100_000_000, c.payee.clone()), out(VAULT_VALUE - 100_000_000 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

#[test]
fn proprietaire_recupere_meme_un_clone() {
    let c = ctx();
    // Des fonds envoyés par erreur à l'adresse (sans lignée) restent récupérables par le propriétaire.
    let vault = compile(&c, CAPACITY, 1_000);
    let r = run_cov(&vault, vec![out(VAULT_VALUE - 50_000, p2pk(&kp(42)))], 0, &c.owner, "ownerControl", vec![], None);
    assert!(r.is_ok(), "{r:?}");
}

/// Mesure le coût d'exécution d'un paiement, pour régler le budget de calcul des transactions v1.
#[test]
fn mesure_budget_de_calcul() {
    use kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT;
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000 - FEE_T, 1_000);
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), 0), vec![], 0, 1000);
    let outputs = vec![out(100_000_000, c.payee.clone()), cont(VAULT_VALUE - 100_000_000 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))];
    let mut tx = Transaction::new(1, vec![input], outputs, 1_000, Default::default(), 0, vec![]);
    let utxo = UtxoEntry::new(VAULT_VALUE, pay_to_script_hash_script(&bytecode(&vault)), 1_000, false, Some(COV_A));
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
    let sighash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
    let mut sig = c.agent.sign_schnorr(Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut ss = encode_entry_sig_script(&vault, "pay", &[sig.into(), 100_000_000i64.into(), 1_000i64.into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&vault)));
    tx.inputs[0].signature_script = ss;
    let populated = PopulatedTransaction::new(&tx, vec![utxo]);
    let cov_ctx = CovenantsContext::from_tx(&populated).unwrap();
    let cache = Cache::new(100);
    let reused = SigHashReusedValuesUnsync::new();
    use kaspa_consensus_core::tx::VerifiableTransaction;
    let input = populated.inputs()[0].clone();
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        0,
        populated.utxo(0).unwrap(),
        EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov_ctx),
        EngineFlags::default(),
    );
    vm.execute().expect("paiement valide");
    let units = vm.used_script_units().0;
    eprintln!("unités de script : {units} => budget de calcul minimal : {}", units.div_ceil(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT));
}

// ---------- v0.4 ----------

#[test]
fn instructions_de_bridge_refusees() {
    let c = ctx();
    // Destinataire autorisé (liste blanche) mais transaction porteuse d'une adresse EVM de destination.
    let vault = compile(&c, CAPACITY, 1_000);
    let next = compile(&c, CAPACITY - 100_000_000 - FEE_T, 1_000);
    let evm_dest = b"0xAttaquant000000000000000000000000000000".to_vec();
    let r = run_full(
        &vault,
        vec![out(100_000_000, c.payee.clone()), cont(VAULT_VALUE - 100_000_000 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))],
        1_000,
        &c.agent,
        "pay",
        vec![100_000_000i64.into(), 1_000i64.into()],
        Some(COV_A),
        evm_dest,
    );
    eprintln!("refus attendu: {:?}", r.as_ref().err());
    assert!(r.is_err());
}

// ---------- liste de contrôle d'avant-lancement ----------

#[test]
fn agent_ne_peut_pas_changer_les_regles() {
    // Le reste revient à un coffre au bon état mais avec d'autres règles (plafond 100 fois plus grand,
    // clé propriétaire remplacée) : refusé, le script de continuation doit être identique.
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let thief = Ctx { owner: kp(99), agent: kp(2), payee: c.payee.clone(), payees: c.payees.clone() };
    for next in [
        compile_cfg(&c, Cfg { max_per_payment: CAPACITY * 100, ..DEFAULT }, CAPACITY - 100_000_000 - FEE_T, 1_000),
        compile(&thief, CAPACITY - 100_000_000 - FEE_T, 1_000),
    ] {
        let r = run(
            &vault,
            vec![out(100_000_000, c.payee.clone()), cont(VAULT_VALUE - 100_000_000 - FEE_T as u64, pay_to_script_hash_script(&bytecode(&next)))],
            1_000,
            &c.agent,
            "pay",
            vec![100_000_000i64.into(), 1_000i64.into()],
        );
        eprintln!("refus attendu: {:?}", r.as_ref().err());
        assert!(r.is_err());
    }
}

#[test]
fn proprietaire_peut_ajouter_une_entree_pour_payer_les_frais() {
    // Reliquat trop petit pour couvrir les frais : le propriétaire ajoute une deuxième entrée.
    let c = ctx();
    let vault = compile(&c, CAPACITY, 1_000);
    let mk = |b: u8| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([b; 32]), 0), vec![], 0, 1000);
    let mut tx = Transaction::new(1, vec![mk(7), mk(8)], vec![out(VAULT_VALUE + 1_000_000, p2pk(&kp(42)))], 0, Default::default(), 0, vec![]);
    let utxos = vec![
        UtxoEntry::new(VAULT_VALUE, pay_to_script_hash_script(&bytecode(&vault)), 1_000, false, Some(COV_A)),
        UtxoEntry::new(2_000_000, p2pk(&c.owner), 0, false, None),
    ];
    let sighash = {
        let reused = SigHashReusedValuesUnsync::new();
        let populated = PopulatedTransaction::new(&tx, utxos.clone());
        calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused)
    };
    let mut sig = c.owner.sign_schnorr(Message::from_digest_slice(sighash.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
    sig.push(SIG_HASH_ALL.to_u8());
    let mut ss = encode_entry_sig_script(&vault, "ownerControl", &[sig.into()]).unwrap();
    ss.extend(push_redeem_script(&bytecode(&vault)));
    tx.inputs[0].signature_script = ss;
    let r = execute_input_with_covenants(tx, utxos, 0);
    assert!(r.is_ok(), "{r:?}");
}

/// v0.5 (R34) : la recharge court depuis l'inscription réelle, pas depuis l'instant annoncé.
/// Coffre vidé (jetons 0, lastDaa 1 000) mais inscrit bien plus tard : le temps écoulé entre
/// lastDaa et l'inscription ne rapporte rien.
#[test]
fn temps_mis_de_cote_ne_rapporte_rien() {
    let c = ctx();
    let inscription = 1_000 + 5 * REFILL;
    let vault = compile(&c, 0, 1_000);
    let essai = |amount: i64, now: i64| {
        INSCRIPTION.set(inscription as u64);
        let next = compile(&c, 0, now);
        let change = VAULT_VALUE - amount as u64 - FEE_T as u64;
        run(&vault, vec![out(amount as u64, c.payee.clone()), cont(change, pay_to_script_hash_script(&bytecode(&next)))], now as u64, &c.agent, "pay", vec![amount.into(), now.into()])
    };
    assert!(essai(10_000_000, inscription).is_err(), "aucune recharge au moment de l'inscription");
    // une période après l'inscription, la recharge complète est à nouveau disponible
    let now = inscription + REFILL;
    INSCRIPTION.set(inscription as u64);
    let next = compile(&c, CAPACITY - 10_000_000 - FEE_T, now);
    let change = VAULT_VALUE - 10_000_000 - FEE_T as u64;
    assert!(run(&vault, vec![out(10_000_000, c.payee.clone()), cont(change, pay_to_script_hash_script(&bytecode(&next)))], now as u64, &c.agent, "pay", vec![10_000_000i64.into(), now.into()]).is_ok());
}

/// v0.5 : coffre non confirmé (score inconnu, u64::MAX dans le mempool) : paiement refusé.
#[test]
fn coffre_non_confirme_refuse() {
    let c = ctx();
    INSCRIPTION.set(u64::MAX);
    let r = {
        let vault = compile(&c, CAPACITY, 1_000);
        let next = compile(&c, CAPACITY - 10_000_000 - FEE_T, 2_000);
        let change = VAULT_VALUE - 10_000_000 - FEE_T as u64;
        run(&vault, vec![out(10_000_000, c.payee.clone()), cont(change, pay_to_script_hash_script(&bytecode(&next)))], 2_000, &c.agent, "pay", vec![10_000_000i64.into(), 2_000i64.into()])
    };
    INSCRIPTION.set(1_000);
    assert!(r.is_err());
}

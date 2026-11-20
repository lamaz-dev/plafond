//! Tests à propriétés (fuzzing d'état) du coffre AgentBudget et du séquestre DeliveryEscrow.
//!
//! Principe : un modèle de référence (quelques lignes de Rust, lisibles par un auditeur) prédit si
//! chaque transaction doit être acceptée. `proptest` génère des séquences aléatoires d'actions honnêtes
//! et de tentatives de triche ; chaque transaction est exécutée par le vrai moteur de script de Kaspa
//! (`TxScriptEngine`, avec covenants). Toute divergence entre le moteur et le modèle est un bug, et
//! proptest réduit automatiquement la séquence fautive au plus petit contre-exemple.
//!
//! Invariants vérifiés après chaque transaction acceptée (voir spec/invariants.md) : I1 à I9.

#![cfg(test)]

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_address_script, pay_to_script_hash_script};
use proptest::prelude::*;
use secp256k1::Keypair;
use silverscript_abi::SilAbiArtifact;

use crate::*;

/// Nombre de cas : `FUZZ_CASES=5000 cargo test fuzz` pour une campagne longue.
fn cases(default: u32) -> u32 {
    std::env::var("FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn k(b: u8) -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
}

/// Exécute l'entrée 0 avec le moteur de script de Kaspa. Ok = la transaction serait acceptée par le script.
fn exec(tx: &Transaction, utxos: Vec<UtxoEntry>) -> bool {
    let populated = PopulatedTransaction::new(tx, utxos);
    let Ok(cov) = CovenantsContext::from_tx(&populated) else { return false };
    let cache = Cache::new(10);
    let reused = SigHashReusedValuesUnsync::new();
    let input = populated.inputs()[0].clone();
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        0,
        populated.utxo(0).unwrap(),
        EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov),
        EngineFlags::default(),
    );
    vm.execute().is_ok()
}

// ---------------------------------------------------------------- coffre

/// Modèle de référence : état d'un couloir.
#[derive(Clone, Debug)]
struct Model {
    value: u64,
    tokens: i64,
    last: i64,
    chain: i64,
}

impl Model {
    fn available(&self, now: i64) -> i64 {
        let elapsed = (now - self.last).clamp(0, REFILL);
        (self.tokens + elapsed * CAPACITY / REFILL).min(CAPACITY)
    }
}

/// Triches tentées par un agent compromis, ou par un tiers.
#[derive(Clone, Debug)]
enum Cheat {
    None,
    /// continuation annonçant plus de jetons que dû
    InflateTokens(i64),
    /// continuation annonçant un instant de dernier paiement plus ancien (recharge future gonflée)
    BackdateLast(i64),
    /// continuation compilée avec un plafond par paiement plus grand (changer les règles)
    LooserRules,
    /// continuation sans liaison de covenant (sortir de la lignée)
    DropCovenant,
    /// troisième sortie (combiner, détourner)
    ExtraOutput(u64),
    /// annoncer un instant plus récent que le verrou temporel de la transaction
    FutureNow(i64),
    /// signature d'une autre clé que celle de l'agent
    WrongKey,
    /// payload joint (instructions de bridge)
    Payload,
    /// sortie de paiement rattachée à la lignée du coffre (deuxième coffre, état ambigu)
    BindPayment,
}

#[derive(Clone, Debug)]
enum Action {
    Wait(i64),
    Pay { amount: i64, fee: i64, back: i64, cheat: Cheat },
}

fn cheat() -> impl Strategy<Value = Cheat> {
    prop_oneof![
        6 => Just(Cheat::None),
        1 => (1i64..CAPACITY).prop_map(Cheat::InflateTokens),
        1 => (1i64..REFILL).prop_map(Cheat::BackdateLast),
        1 => Just(Cheat::LooserRules),
        1 => Just(Cheat::DropCovenant),
        1 => (1u64..10_000_000).prop_map(Cheat::ExtraOutput),
        1 => (1i64..1_000).prop_map(Cheat::FutureNow),
        1 => Just(Cheat::WrongKey),
        1 => Just(Cheat::Payload),
        1 => Just(Cheat::BindPayment),
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        1 => (0i64..2 * REFILL).prop_map(Action::Wait),
        4 => (
            prop_oneof![3 => 1i64..=MAX_PER_PAYMENT, 1 => -10i64..=0, 1 => MAX_PER_PAYMENT..2 * MAX_PER_PAYMENT],
            prop_oneof![4 => 0i64..=MAX_FEE, 1 => MAX_FEE..2 * MAX_FEE],
            prop_oneof![4 => Just(0i64), 1 => 1i64..2_000],
            cheat(),
        )
            .prop_map(|(amount, fee, back, cheat)| Action::Pay { amount, fee, back, cheat }),
    ]
}

/// Prédiction du modèle pour un paiement honnête dans sa forme (sans triche).
fn model_accepts(m: &Model, amount: i64, fee: i64, now: i64) -> bool {
    amount > 0
        && amount <= MAX_PER_PAYMENT
        && fee <= MAX_FEE
        && now >= m.last
        && amount + fee <= m.available(now)
        && ((amount + fee) as u64) < m.value
}

fn vault(owner: &Keypair, agent: &Keypair, tokens: i64, last: i64) -> SilAbiArtifact {
    compile_unchecked(&VaultParams::ours(owner, agent, tokens, last)).unwrap()
}

/// Construit le paiement décrit par l'action, l'exécute, et renvoie (accepté, état suivant prédit).
fn try_pay(m: &Model, amount: i64, fee: i64, back: i64, cheat: &Cheat) -> (bool, bool, Model) {
    let (owner, agent) = (k(1), k(2));
    let cov = Hash::from_bytes([7; 32]);
    let now = m.chain - back;
    let honest = model_accepts(m, amount, fee, now) && matches!(cheat, Cheat::None);
    let next_tokens = m.available(now) - amount - fee;
    let next_last = now;
    let cur = vault(&owner, &agent, m.tokens, m.last);
    let next = match cheat {
        Cheat::InflateTokens(d) => vault(&owner, &agent, next_tokens + d, next_last),
        Cheat::BackdateLast(d) => vault(&owner, &agent, next_tokens, next_last - d),
        Cheat::LooserRules => {
            let mut p = VaultParams::ours(&owner, &agent, next_tokens, next_last);
            p.max_per_payment = CAPACITY;
            compile_unchecked(&p).unwrap()
        }
        _ => vault(&owner, &agent, next_tokens, next_last),
    };
    let rest = m.value as i64 - amount.max(0) - fee;
    if amount <= 0 || rest <= 0 {
        // Une sortie de valeur nulle ou négative n'est pas constructible : le modèle refuse aussi.
        return (false, honest, m.clone());
    }
    let entry = UtxoEntry::new(m.value, vault_spk(&cur), 0, false, Some(cov));
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
    let binding = if matches!(cheat, Cheat::DropCovenant) { None } else { Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }) };
    let pay_binding = if matches!(cheat, Cheat::BindPayment) { Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }) } else { None };
    let mut outputs = vec![
        TransactionOutput { value: amount as u64, script_public_key: pay_to_address_script(&address(&k(10))), covenant: pay_binding },
        TransactionOutput { value: rest as u64, script_public_key: vault_spk(&next), covenant: binding },
    ];
    if let Cheat::ExtraOutput(v) = cheat {
        outputs.push(TransactionOutput::new(*v, pay_to_address_script(&address(&k(66)))));
    }
    let lock = if let Cheat::FutureNow(d) = cheat { now - d } else { m.chain };
    let payload = if matches!(cheat, Cheat::Payload) { b"0x94 bridge vers 0xAttaquant".to_vec() } else { vec![] };
    let mut tx = Transaction::new(1, vec![input], outputs, lock.max(0) as u64, Default::default(), 0, payload);
    let signer = if matches!(cheat, Cheat::WrongKey) { k(66) } else { agent };
    let s = sign(&tx, std::slice::from_ref(&entry), 0, &signer);
    tx.inputs[0].signature_script = vault_sigscript(&cur, "pay", &[s.into(), amount.into(), now.into()]).unwrap();
    let ok = exec(&tx, vec![entry]);
    let after = Model { value: rest as u64, tokens: next_tokens, last: next_last, chain: m.chain };
    (ok, honest, after)
}

/// Pré-audit (R33) : paramètres aberrants qu'un déploiement fait hors de l'outil pourrait produire
/// (période de recharge nulle, plafond par paiement supérieur à la capacité). Le contrat n'a pas de
/// garde dédiée ; on vérifie qu'ils ne mettent aucun fonds en danger : l'outil et le vendeur les
/// refusent, l'agent ne dépasse jamais la capacité, et le propriétaire récupère toujours tout.
#[test]
fn parametres_aberrants_sans_danger_pour_les_fonds() {
    let (owner, agent) = (k(1), k(2));
    let cov = Hash::from_bytes([7; 32]);
    let payer = |p: &VaultParams, amount: i64, now: i64| -> bool {
        let cur = compile_unchecked(p).unwrap();
        let mut n = p.clone();
        n.tokens = p.capacity.min(p.tokens) - amount - 1_000_000;
        n.last_daa = now;
        let next = compile_unchecked(&n).unwrap();
        let entry = UtxoEntry::new(500_000_000, vault_spk(&cur), 0, false, Some(cov));
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
        let outputs = vec![
            TransactionOutput::new(amount as u64, pay_to_address_script(&address(&k(10)))),
            TransactionOutput { value: 500_000_000 - amount as u64 - 1_000_000, script_public_key: vault_spk(&next), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }) },
        ];
        let mut tx = Transaction::new(1, vec![input], outputs, now as u64, Default::default(), 0, vec![]);
        let s = sign(&tx, std::slice::from_ref(&entry), 0, &agent);
        tx.inputs[0].signature_script = vault_sigscript(&cur, "pay", &[s.into(), amount.into(), now.into()]).unwrap();
        exec(&tx, vec![entry])
    };
    let recuperer = |p: &VaultParams| -> bool {
        let cur = compile_unchecked(p).unwrap();
        let entry = UtxoEntry::new(500_000_000, vault_spk(&cur), 0, false, Some(cov));
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
        let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(499_000_000, pay_to_address_script(&address(&owner)))], 0, Default::default(), 0, vec![]);
        let s = sign(&tx, std::slice::from_ref(&entry), 0, &owner);
        tx.inputs[0].signature_script = vault_sigscript(&cur, "ownerControl", &[s.into()]).unwrap();
        exec(&tx, vec![entry])
    };

    // Période de recharge nulle : tout paiement échoue (division par zéro), les fonds restent récupérables.
    let mut p = VaultParams::ours(&owner, &agent, CAPACITY, 1_000);
    p.refill_period = 0;
    assert!(check_params(&p).is_err());
    assert!(!payer(&p, 10_000_000, 2_000));
    assert!(recuperer(&p));

    // Plafond par paiement supérieur à la capacité : la capacité borne toujours la dépense.
    let mut p = VaultParams::ours(&owner, &agent, CAPACITY, 1_000);
    p.max_per_payment = CAPACITY * 2;
    assert!(check_params(&p).is_err());
    assert!(payer(&p, 10_000_000, 2_000), "témoin : un paiement normal passe");
    assert!(!payer(&p, CAPACITY + 1, 2_000));
    assert!(recuperer(&p));
}

/// Contrôle du banc : sans ce test, un harnais qui refuserait tout passerait les propriétés.
#[test]
fn banc_de_test_discriminant() {
    let m = Model { value: 500_000_000, tokens: CAPACITY, last: 1_000_000, chain: 1_000_000 };
    let (ok, predicted, _) = try_pay(&m, 10_000_000, 1_500_000, 0, &Cheat::None);
    assert!(ok && predicted, "un paiement honnête doit passer");
    for c in [
        Cheat::InflateTokens(1),
        Cheat::BackdateLast(1),
        Cheat::LooserRules,
        Cheat::DropCovenant,
        Cheat::ExtraOutput(1_000),
        Cheat::FutureNow(1),
        Cheat::WrongKey,
        Cheat::Payload,
        Cheat::BindPayment,
    ] {
        let (ok, _, _) = try_pay(&m, 10_000_000, 1_500_000, 0, &c);
        assert!(!ok, "triche acceptée : {c:?}");
    }
    // Limites exactes : budget épuisé au sompi près, frais au plafond.
    let (ok, _, _) = try_pay(&m, MAX_PER_PAYMENT, MAX_FEE, 0, &Cheat::None);
    assert!(ok);
    let low = Model { tokens: 10_000_000, ..m.clone() };
    assert!(try_pay(&low, 8_500_000, 1_500_000, 0, &Cheat::None).0, "budget exact");
    assert!(!try_pay(&low, 8_500_001, 1_500_000, 0, &Cheat::None).0, "budget dépassé d'un sompi");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(256), max_shrink_iters: 500, .. ProptestConfig::default() })]

    /// Le moteur de script et le modèle de référence décident toujours pareil, et les invariants tiennent.
    #[test]
    fn coffre_moteur_egal_modele(actions in prop::collection::vec(action(), 1..20), value in 30_000_000u64..1_000_000_000) {
        let mut m = Model { value, tokens: CAPACITY, last: 1_000_000, chain: 1_000_000 };
        for a in actions {
            match a {
                Action::Wait(d) => m.chain += d,
                Action::Pay { amount, fee, back, cheat } => {
                    let before = m.clone();
                    let (ok, predicted, after) = try_pay(&m, amount, fee, back, &cheat);
                    prop_assert_eq!(ok, predicted, "divergence moteur/modèle : {:?} sur {:?}", (amount, fee, back, &cheat), before);
                    if ok {
                        // I1 conservation, I2 plafond, I3 frais, I4 état honnête, I8 pas d'accumulation
                        let now = before.chain - back;
                        prop_assert!((before.value - after.value) as i64 <= before.available(now));
                        prop_assert!(amount <= MAX_PER_PAYMENT && fee <= MAX_FEE);
                        prop_assert!(after.tokens >= 0 && after.tokens <= CAPACITY);
                        prop_assert!(after.available(after.chain + 10 * REFILL) <= CAPACITY);
                        m = after;
                    }
                }
            }
        }
    }

    /// I13 : la clé de l'agent n'ouvre jamais l'entrée du propriétaire ; la clé du propriétaire l'ouvre toujours.
    #[test]
    fn seul_le_proprietaire_ouvre_owner_control(tokens in 0i64..=CAPACITY, last in 0i64..10_000_000, out in 1u64..400_000_000) {
        let (owner, agent) = (k(1), k(2));
        let cur = vault(&owner, &agent, tokens, last);
        let entry = UtxoEntry::new(500_000_000, vault_spk(&cur), 0, false, Some(Hash::from_bytes([7; 32])));
        for (signer, expected) in [(&agent, false), (&k(66), false), (&owner, true)] {
            let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
            let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(out, pay_to_address_script(&address(&k(42))))], 0, Default::default(), 0, vec![]);
            let s = sign(&tx, std::slice::from_ref(&entry), 0, signer);
            tx.inputs[0].signature_script = vault_sigscript(&cur, "ownerControl", &[s.into()]).unwrap();
            prop_assert_eq!(exec(&tx, vec![entry.clone()]), expected);
        }
    }
}

// ---------------------------------------------------------------- séquestre

const ESCROW_VALUE: u64 = 30_000_000;

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(128), .. ProptestConfig::default() })]

    /// Séquestre : E1 à E4, moteur et modèle décident pareil pour des réclamations et remboursements aléatoires.
    #[test]
    fn sequestre_moteur_egal_modele(
        claim in any::<bool>(),
        good_signer in prop::bool::weighted(0.7),
        same_request in prop::bool::weighted(0.7),
        to_expected in prop::bool::weighted(0.7),
        fee in prop_oneof![4 => 0i64..=sequestre::MAX_FEE, 1 => sequestre::MAX_FEE + 1..2 * sequestre::MAX_FEE],
        seq in prop_oneof![1 => 0u64..sequestre::DEFAULT_TIMEOUT as u64, 1 => sequestre::DEFAULT_TIMEOUT as u64..4 * sequestre::DEFAULT_TIMEOUT as u64],
        result in "[a-z]{0,24}",
        extra_input in prop::bool::weighted(0.2),
    ) {
        let merchant = pay_to_address_script(&address(&k(3)));
        let refund = pay_to_address_script(&address(&k(1)));
        let other = pay_to_address_script(&address(&k(66)));
        let verifier = k(7);
        let requete = "GET:/meteo/commande-1";
        let a = sequestre::artifact(&merchant, &refund, &verifier, requete, sequestre::DEFAULT_TIMEOUT).unwrap();
        let s = sequestre::Sequestre { txid: "ab".repeat(32), index: 0, valeur: ESCROW_VALUE, requete: requete.into(), timeout: sequestre::DEFAULT_TIMEOUT };
        let expected_to = if claim { merchant.clone() } else { refund.clone() };
        let to: ScriptPublicKey = if to_expected { expected_to } else { other };
        let mut tx = if claim {
            let signer = if good_signer { verifier } else { k(2) };
            let (p, r) = sequestre::proof(&signer, if same_request { requete } else { "GET:/meteo/commande-2" }, &result);
            sequestre::build_claim(&a, &s, to, fee as u64, p, r).unwrap()
        } else {
            sequestre::build_refund(&a, &s, to, fee as u64).unwrap()
        };
        tx.inputs[0].sequence = if claim { 0 } else { seq };
        let mut utxos = vec![UtxoEntry::new(ESCROW_VALUE, pay_to_script_hash_script(&bytecode(&a)), 0, false, None)];
        if extra_input {
            // E5 : un second séquestre fusionné dans la même transaction (sa valeur partirait en frais).
            let a2 = sequestre::artifact(&merchant, &refund, &verifier, "GET:/meteo/commande-9", sequestre::DEFAULT_TIMEOUT).unwrap();
            let mut i2 = tx.inputs[0].clone();
            i2.previous_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([5; 32]), 0);
            i2.signature_script = vault_sigscript(&a2, "refund", &[]).unwrap();
            tx.inputs.push(i2);
            utxos.push(UtxoEntry::new(ESCROW_VALUE, pay_to_script_hash_script(&bytecode(&a2)), 0, false, None));
        }
        let predicted = !extra_input && to_expected && fee <= sequestre::MAX_FEE
            && if claim { good_signer && same_request } else { seq >= sequestre::DEFAULT_TIMEOUT as u64 };
        prop_assert_eq!(exec(&tx, utxos), predicted);
    }
}

// ---------------------------------------------------------------- diffusion

/// Garde-fou : une entrée v1 sans budget de calcul n'est jamais diffusée.
#[test]
fn garde_bloque_un_budget_nul() {
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, 0);
    let tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(1_000, pay_to_address_script(&address(&k(10))))], 0, Default::default(), 0, vec![]);
    assert!(garde_diffusion(&tx).is_err());
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
    let tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(1_000, pay_to_address_script(&address(&k(10))))], 0, Default::default(), 0, vec![]);
    assert_eq!(garde_diffusion(&tx).unwrap().inputs[0].compute_budget, CB_VAULT);
}

/// Le risque signalé existe bien : un JSON sans le champ `computeBudget` se relit avec un budget nul.
#[test]
fn json_sans_budget_relu_a_zero() {
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_VAULT);
    let tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(1_000, pay_to_address_script(&address(&k(10))))], 0, Default::default(), 0, vec![]);
    let rpc = garde_diffusion(&tx).unwrap();
    let mut v = serde_json::to_value(&rpc).unwrap();
    let inp = v["inputs"][0].as_object_mut().unwrap();
    let key = inp.keys().find(|k| k.to_lowercase().contains("budget")).cloned().expect("champ budget en JSON");
    inp.remove(&key);
    let back: kaspa_rpc_core::RpcTransaction = serde_json::from_value(v).unwrap();
    assert_eq!(back.inputs[0].compute_budget, 0, "le champ manquant est relu à 0");
}

// ---------------------------------------------------------------- vecteur officiel KIP-20

/// Vecteur de test de kaspanet/kips#49 (« KIP-20: specify CovenantIDHash keying and add a test
/// vector », 20 octobre 2026) : notre calcul de l'identifiant de lignée doit donner exactement le
/// même résultat que la spécification.
#[test]
fn identifiant_de_covenant_conforme_au_vecteur_kip20() {
    use kaspa_consensus_core::hashing::covenant_id::covenant_id;
    let txid: [u8; 32] = hex::decode("206a0c31dbe45384b86de451a177fd7c8e986d278f2a86724d941937443113ef").unwrap().try_into().unwrap();
    let outpoint = TransactionOutpoint::new(TransactionId::from_bytes(txid), 0);
    let out = TransactionOutput::new(90_000_000, ScriptPublicKey::new(0, vec![0x51].into()));
    let id = covenant_id(outpoint, std::iter::once((0u32, &out)));
    assert_eq!(id.to_string(), "c86366cec738e9a1578b2d871ee493dcaabfd79156810f13f3b62429859e394e");
}

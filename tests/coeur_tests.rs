//! Cœur v0.9.1 (budget sans mémoire, adresse de retour, rechargement sans clé, lignée KIP-20,
//! retrait partiel) : comportement du contrat contre le vrai moteur de script. Les règles de `pay`
//! et `ownerControl` sont celles de la v0.7, celles de `absorb` celles de la v0.8 ; la v0.9 a ajouté
//! la règle de lignée (une pièce de la lignée a au plus une héritière, sa propre sortie) ; la v0.9.1
//! ajoute l'entrée `ownerWithdraw` (retrait partiel, frais au rythme du contrat).
//! Dans ces essais, les pièces du coffre portent la lignée `LIGNEE` et, sauf mention contraire, toute
//! sortie à l'adresse du coffre est déclarée dans cette lignée (voir `sorties`).
//! Le verrou relatif est donné par `sequence` : le script exige `sequence ≥ délai` (OpCheckSequenceVerify),
//! et le réseau exige que la pièce ait réellement cet âge (check_sequence_lock, testé côté outil).
mod common;
use blake2b_simd::Params;
use common::{bytecode, compile_contract, encode_entry_sig_script, execute_input_with_covenants, push_redeem_script};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
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
/// Empreinte d'un scriptPubKey telle que la calcule `blake2b(tx.outputs[i].scriptPubKey)`.
fn spk_hash(spk: &ScriptPublicKey) -> Vec<u8> {
    let bytes: Vec<u8> = spk.version().to_be_bytes().into_iter().chain(spk.script().iter().copied()).collect();
    Params::new().hash_length(32).hash(&bytes).as_bytes().to_vec()
}
/// Adresse de retour des tests : une adresse du propriétaire distincte (clé 11).
fn retour() -> ScriptPublicKey {
    p2pk(&kp(11))
}
fn art_avec(c: i64, r: i64) -> SilAbiArtifact {
    compile_contract(SOURCE, &[x(1).into(), x(2).into(), c.into(), r.into(), spk_hash(&retour()).into()], CompileOptions::default()).unwrap()
}
fn art() -> SilAbiArtifact {
    art_avec(C, R)
}
fn moi(a: &SilAbiArtifact) -> ScriptPublicKey {
    pay_to_script_hash_script(&bytecode(a))
}
/// Lignée du coffre d'essai (identifiant de covenant porté par ses pièces).
const LIGNEE: Hash = Hash::from_bytes([0xA1; 32]);
fn liee(valeur: u64, spk: ScriptPublicKey, entree: u16) -> TransactionOutput {
    TransactionOutput { value: valeur, script_public_key: spk, covenant: Some(CovenantBinding { authorizing_input: entree, covenant_id: LIGNEE }) }
}
fn libre(valeur: u64, spk: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value: valeur, script_public_key: spk, covenant: None }
}
/// Forme ordinaire : une sortie à l'adresse du coffre reste dans la lignée, autorisée par l'entrée
/// de même indice (entrée i -> sortie i), ou par l'entrée 0 s'il n'y a pas d'entrée de cet indice
/// (le reste d'un paiement, sortie 1 d'une transaction à une entrée).
fn sorties(a: &SilAbiArtifact, outs: Vec<(u64, ScriptPublicKey)>, n_entrees: usize) -> Vec<TransactionOutput> {
    let m = moi(a);
    outs.into_iter().enumerate().map(|(j, (v, s))| if s == m { liee(v, s, if j < n_entrees { j as u16 } else { 0 }) } else { libre(v, s) }).collect()
}

/// Exécute l'entrée 0. `valeurs` : valeur de chaque pièce du coffre en entrée (toutes à la même adresse).
fn run_n(a: &SilAbiArtifact, signer: u8, entry: &str, valeurs: &[u64], outs: Vec<(u64, ScriptPublicKey)>, seq: u64) -> bool {
    let outputs = sorties(a, outs, valeurs.len());
    run_brut(a, signer, entry, &valeurs.iter().map(|v| (*v, Some(LIGNEE))).collect::<Vec<_>>(), outputs, seq)
}
/// Forme libre : lignée de chaque pièce en entrée et de chaque sortie choisies par l'essai.
fn run_brut(a: &SilAbiArtifact, signer: u8, entry: &str, entrees: &[(u64, Option<Hash>)], outputs: Vec<TransactionOutput>, seq: u64) -> bool {
    let inputs = (0..entrees.len())
        .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), i as u32), vec![], seq, 1000))
        .collect();
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let utxos: Vec<UtxoEntry> = entrees.iter().map(|(v, l)| UtxoEntry::new(*v, moi(a), 0, false, *l)).collect();
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
    assert!(run(&a, 1, "ownerControl", vec![(V - FEE, retour())], 0), "propriétaire : gel vers l'adresse de retour");
    assert!(run(&a, 1, "ownerControl", vec![(V + 5, moi(&a))], 0), "propriétaire : rechargement");
    assert!(!run(&a, 2, "ownerControl", vec![(V - FEE, retour())], R as u64), "l'agent ne peut pas utiliser ownerControl");
}

#[test]
fn le_proprietaire_ne_peut_rien_envoyer_ailleurs() {
    // v0.7 : même avec la clé du propriétaire, la pièce ne va qu'au coffre ou à l'adresse de retour.
    let a = art();
    assert!(!run(&a, 1, "ownerControl", vec![(V - FEE, p2pk(&kp(1)))], 0), "vers l'adresse ordinaire du propriétaire : refusé");
    assert!(!run(&a, 1, "ownerControl", vec![(V - FEE, p2pk(&kp(9)))], 0), "vers une adresse étrangère : refusé");
    assert!(!run(&a, 1, "ownerControl", vec![(V / 2, retour()), (V / 2 - FEE, moi(&a))], 0), "retrait partiel hors règle : refusé");
    assert!(run(&a, 1, "ownerControl", vec![(V - C as u64, retour())], 0), "frais égaux à la capacité : acceptés");
    assert!(!run(&a, 1, "ownerControl", vec![(V - C as u64 - 1, retour())], 0), "frais au-delà de la capacité : refusés");
    assert!(!run(&a, 1, "ownerControl", vec![(V - 1, moi(&a))], 0), "rechargement qui fait fondre la pièce : refusé");
    // Gel par lot (entrée i -> sortie i) ; le refus de deux pièces sur une seule sortie se joue sur
    // l'entrée 1, vérifié entrée par entrée côté outil (coeur::tests::retour_cle_proprietaire_volee_…).
    assert!(run_n(&a, 1, "ownerControl", &[V, V], vec![(V - FEE, retour()), (V - FEE, retour())], 0), "gel par lot : accepté");
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

/// Exécute l'entrée `idx` d'une transaction dont toutes les entrées sont des pièces du coffre
/// dépensées par `absorb` (aucune signature).
fn absorb_n(a: &SilAbiArtifact, valeurs: &[u64], outs: Vec<(u64, ScriptPublicKey)>, idx: usize) -> bool {
    let outputs = sorties(a, outs, valeurs.len());
    absorb_brut(a, &valeurs.iter().map(|v| (*v, Some(LIGNEE))).collect::<Vec<_>>(), outputs, idx)
}
fn absorb_brut(a: &SilAbiArtifact, entrees: &[(u64, Option<Hash>)], outputs: Vec<TransactionOutput>, idx: usize) -> bool {
    let mut ss = encode_entry_sig_script(a, "absorb", &[]).unwrap();
    ss.extend(push_redeem_script(&bytecode(a)));
    let inputs = (0..entrees.len())
        .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), i as u32), ss.clone(), 0, 1000))
        .collect();
    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let utxos: Vec<UtxoEntry> = entrees.iter().map(|(v, l)| UtxoEntry::new(*v, moi(a), 0, false, *l)).collect();
    execute_input_with_covenants(tx, utxos, idx).is_ok()
}

#[test]
fn regonflement_sans_cle() {
    // v0.8 : sans signature, la pièce ne peut que revenir au coffre, grossie d'au moins la capacité
    // (et, depuis la v0.9, dans la lignée : `sorties` le déclare).
    let a = art();
    let c = C as u64;
    assert!(absorb_n(&a, &[V], vec![(V + c, moi(&a))], 0), "pièce grossie de la capacité : acceptée");
    assert!(absorb_n(&a, &[V], vec![(V + 10 * c, moi(&a))], 0), "pièce grossie davantage : acceptée");
    assert!(!absorb_n(&a, &[V], vec![(V + c - 1, moi(&a))], 0), "un sompi sous le minimum : refusé");
    assert!(!absorb_n(&a, &[V], vec![(V, moi(&a))], 0), "regonflement nul (gêne gratuite) : refusé");
    assert!(!absorb_n(&a, &[V], vec![(V - FEE, moi(&a))], 0), "pièce qui fond : refusé");
    assert!(!absorb_n(&a, &[V], vec![(V + c, vendeur())], 0), "vers un tiers : refusé");
    assert!(!absorb_n(&a, &[V], vec![(V + c, retour())], 0), "vers l'adresse de retour sans signature : refusé");
    assert!(!absorb_n(&a, &[V], vec![(c, vendeur()), (V + c, moi(&a))], 0), "sortie d'un autre indice : refusé");
    assert!(!absorb_n(&a, &[V], vec![], 0), "sans sortie : refusé");
    // Entrée i -> sortie i : pas de fusion de deux pièces.
    assert!(absorb_n(&a, &[V, V], vec![(V + c, moi(&a)), (V + c, moi(&a))], 0) && absorb_n(&a, &[V, V], vec![(V + c, moi(&a)), (V + c, moi(&a))], 1), "deux pièces, deux sorties : accepté");
    assert!(!absorb_n(&a, &[V, V], vec![(2 * V + 2 * c, moi(&a))], 1), "deux pièces sur une sortie : refusé pour la seconde");
    assert!(!absorb_n(&a, &[V, V], vec![(V + c, moi(&a)), (V, moi(&a))], 1), "seconde pièce non grossie : refusé");
    // Une sortie supplémentaire (rendu de celui qui apporte les fonds) reste libre.
    assert!(absorb_n(&a, &[V], vec![(V + c, moi(&a)), (123_456, vendeur())], 0), "rendu de l'apporteur : accepté");
    // Réglages aberrants : jamais de regonflement sans clé.
    for cap in [0, -1, -C] {
        let a = art_avec(cap, R);
        for v in [V, V + 1, (V as i64 + cap) as u64, V + c] {
            assert!(!absorb_n(&a, &[V], vec![(v, moi(&a))], 0), "capacité {cap} : absorb refusé");
        }
    }
}

/// v0.9 : une pièce de la lignée a au plus une héritière, sa propre sortie. Le nombre de pièces du
/// coffre ne peut pas augmenter, quelle que soit la clé ; une pièce hors lignée (envoyée par un
/// tiers à l'adresse du coffre) n'est ni dépensable par l'agent, ni regonflable.
#[test]
fn lignee_une_seule_heritiere() {
    let a = art();
    let (m, c, w) = (moi(&a), C as u64, R as u64);
    let x = Some(LIGNEE);
    let autre = Hash::from_bytes([0xB2; 32]);
    let liee_a = |v: u64, s: ScriptPublicKey, id: Hash| TransactionOutput { value: v, script_public_key: s, covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: id }) };

    // pay : le reste (sortie 1) est la seule héritière.
    let pay = |entree: Option<Hash>, outs: Vec<TransactionOutput>| run_brut(&a, 2, "pay", &[(V, entree)], outs, w);
    assert!(pay(x, vec![libre(c - FEE, vendeur()), liee(V - c, m.clone(), 0)]), "paiement dans la lignée : accepté");
    assert!(!pay(x, vec![libre(c - FEE, vendeur()), libre(V - c, m.clone())]), "le reste sort de la lignée : refusé");
    assert!(!pay(x, vec![liee(c - FEE, vendeur(), 0), liee(V - c, m.clone(), 0)]), "bénéficiaire rattaché à la lignée : refusé");
    assert!(!pay(x, vec![liee(c - FEE, vendeur(), 0), libre(V - c, m.clone())]), "lignée déplacée sur le bénéficiaire : refusé");
    assert!(!pay(None, vec![libre(c - FEE, vendeur()), libre(V - c, m.clone())]), "pièce sans lignée (poussière d'un tiers) : l'agent ne peut pas la dépenser");
    assert!(!pay(None, vec![libre(c - FEE, vendeur()), liee(V - c, m.clone(), 0)]), "pièce sans lignée déclarée dans la lignée : refusé par le réseau");
    // Une autre lignée à la même adresse (genèse d'un tiers, avec son argent) est un autre coffre :
    // elle se dépense dans SA lignée, jamais dans celle du coffre.
    assert!(pay(Some(autre), vec![libre(c - FEE, vendeur()), liee_a(V - c, m.clone(), autre)]), "autre lignée : dépensable dans sa propre lignée");
    assert!(!pay(Some(autre), vec![libre(c - FEE, vendeur()), liee(V - c, m.clone(), 0)]), "autre lignée rebaptisée : refusé par le réseau");

    // ownerControl : même avec la clé du propriétaire, pas de pièce de plus dans la lignée.
    let ctrl = |entree: Option<Hash>, outs: Vec<TransactionOutput>| run_brut(&a, 1, "ownerControl", &[(V, entree)], outs, 0);
    assert!(ctrl(x, vec![liee(V, m.clone(), 0)]), "rechargement dans la lignée : accepté");
    assert!(!ctrl(x, vec![libre(V, m.clone())]), "rechargement hors lignée : refusé");
    assert!(!ctrl(x, vec![liee(V, m.clone(), 0), liee(1_000, m.clone(), 0)]), "seconde pièce dans la lignée : refusé");
    assert!(!ctrl(x, vec![liee(V, m.clone(), 0), liee(1_000, vendeur(), 0)]), "pièce de la lignée vers un tiers : refusé");
    assert!(!ctrl(x, vec![libre(V, m.clone()), liee(1_000, m.clone(), 0)]), "la lignée part sur une autre sortie : refusé");
    assert!(ctrl(x, vec![libre(V - FEE, retour())]), "gel : la pièce quitte la lignée");
    assert!(!ctrl(x, vec![liee(V - FEE, retour(), 0)]), "gel : la lignée suit la pièce à l'adresse de retour : refusé");
    assert!(!ctrl(x, vec![libre(V - FEE, retour()), liee(1_000, m.clone(), 0)]), "gel : une héritière reste au coffre : refusé");
    assert!(ctrl(None, vec![libre(V - FEE, retour())]), "pièce sans lignée : le propriétaire la rapatrie");
    assert!(!ctrl(None, vec![libre(V, m.clone())]), "pièce sans lignée : pas de rechargement");

    // absorb : sans clé, la pièce reste dans la lignée, seule.
    assert!(absorb_brut(&a, &[(V, x)], vec![liee(V + c, m.clone(), 0)], 0), "regonflement dans la lignée : accepté");
    assert!(!absorb_brut(&a, &[(V, x)], vec![libre(V + c, m.clone())], 0), "regonflement hors lignée : refusé");
    assert!(!absorb_brut(&a, &[(V, x)], vec![liee(V + c, m.clone(), 0), liee(c, m.clone(), 0)], 0), "seconde pièce dans la lignée : refusé");
    assert!(!absorb_brut(&a, &[(V, x)], vec![libre(V + c, m.clone()), liee(c, m.clone(), 0)], 0), "la lignée part sur une autre sortie : refusé");
    assert!(!absorb_brut(&a, &[(V, None)], vec![libre(V + c, m.clone())], 0), "pièce sans lignée : pas de regonflement");
    assert!(!absorb_brut(&a, &[(V, None)], vec![liee(V + c, m.clone(), 0)], 0), "pièce sans lignée déclarée dans la lignée : refusé par le réseau");
}

/// v0.9.1 : retrait partiel. Le propriétaire reprend une partie d'une pièce vers l'adresse de
/// retour (sortie 0) ; le reste revient au coffre, seule héritière (sortie 1). Une entrée, deux
/// sorties. Les frais suivent la règle de `pay` : au plus la capacité, et au rythme du contrat.
#[test]
fn retrait_partiel() {
    let a = art();
    let (m, c, x) = (moi(&a), C as u64, Some(LIGNEE));
    let w = attente(FEE);
    let retrait = |outs: Vec<(u64, ScriptPublicKey)>, seq: u64| run(&a, 1, "ownerWithdraw", outs, seq);
    assert!(retrait(vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], w), "retrait partiel à l'heure : accepté");
    assert!(retrait(vec![(V - FEE - 1_000, retour()), (1_000, m.clone())], w), "presque tout repris : accepté");
    assert!(retrait(vec![(V / 2, retour()), (V / 2, m.clone())], 0), "sans frais, sans attente : accepté");
    assert!(retrait(vec![(V / 2, retour()), (V / 2 - c, m.clone())], R as u64), "frais à la capacité exacte après une période : accepté");
    // Frais : capacité et rythme.
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], w - 1), "frais un cran trop tôt : refusé");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], 0), "frais sans attente : refusé");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], (1u64 << 63) | w), "verrou désactivé : refusé");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], 1u64 << 32), "sequence 2^32 (vue comme 0 par le réseau) : refusée");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - c - 1, m.clone())], R as u64 * 10), "frais au-delà de la capacité : refusé, quelle que soit l'attente");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - c, m.clone())], R as u64 - 1), "frais à la capacité un cran avant la période : refusé");
    // Destination et signataire.
    assert!(!retrait(vec![(V / 2, vendeur()), (V / 2 - FEE, m.clone())], w), "vers un tiers : refusé");
    assert!(!retrait(vec![(V / 2, p2pk(&kp(1))), (V / 2 - FEE, m.clone())], w), "vers l'adresse ordinaire du propriétaire : refusé");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE, vendeur())], w), "le reste vers un tiers : refusé");
    assert!(!run(&a, 2, "ownerWithdraw", vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], R as u64), "signé par l'agent : refusé");
    assert!(!run(&a, 9, "ownerWithdraw", vec![(V / 2, retour()), (V / 2 - FEE, m.clone())], R as u64), "signé par un tiers : refusé");
    // Forme : une entrée, deux sorties, dans cet ordre.
    assert!(!retrait(vec![(V / 2 - FEE, m.clone()), (V / 2, retour())], w), "sorties inversées : refusé");
    assert!(!retrait(vec![(V - FEE, retour())], w), "sans reste : refusé (c'est un gel, par ownerControl)");
    assert!(!retrait(vec![(V / 2, retour()), (V / 2 - FEE - 1_000, m.clone()), (1_000, vendeur())], R as u64), "troisième sortie : refusé");
    assert!(!run_n(&a, 1, "ownerWithdraw", &[V, V], vec![(V, retour()), (V - FEE, m.clone())], R as u64), "deux pièces fusionnées : refusé");
    // Lignée : le reste est la seule héritière ; rien d'autre n'entre dans la lignée.
    let brut = |entree: Option<Hash>, outs: Vec<TransactionOutput>| run_brut(&a, 1, "ownerWithdraw", &[(V, entree)], outs, R as u64);
    assert!(brut(x, vec![libre(V / 2, retour()), liee(V / 2 - FEE, m.clone(), 0)]), "témoin : forme légitime");
    assert!(!brut(x, vec![liee(V / 2, retour(), 0), liee(V / 2 - FEE, m.clone(), 0)]), "retrait rattaché à la lignée (pièce de plus) : refusé");
    assert!(!brut(x, vec![liee(V / 2, retour(), 0), libre(V / 2 - FEE, m.clone())]), "lignée déplacée à l'adresse de retour : refusé");
    assert!(!brut(x, vec![libre(V / 2, retour()), libre(V / 2 - FEE, m.clone())]), "le reste sort de la lignée : refusé");
    assert!(!brut(None, vec![libre(V / 2, retour()), libre(V / 2 - FEE, m.clone())]), "pièce hors lignée : pas de retrait partiel");
    assert!(!brut(None, vec![libre(V / 2, retour()), liee(V / 2 - FEE, m.clone(), 0)]), "pièce hors lignée déclarée dans la lignée : refusé par le réseau");
    // Réglages aberrants : jamais de frais pris sur la pièce.
    for (cap, per) in [(0, R), (-C, R), (C, 0), (C, -R), (C, 1i64 << 32)] {
        let a = art_avec(cap, per);
        assert!(!run(&a, 1, "ownerWithdraw", vec![(V / 2, retour()), (V / 2 - FEE, moi(&a))], u32::MAX as u64), "capacité {cap}, période {per} : retrait avec frais refusé");
    }
}

#[test]
fn taille_du_coeur() {
    let a = art();
    let n = bytecode(&a).len();
    eprintln!("Cœur v0.9.1 : {n} octets ; attente pour 0,5 KAS = {} DAA", attente(50_000_000 + FEE));
    // v0.9 : 376 octets. L'entrée `ownerWithdraw` en ajoute 201 (la clé du propriétaire et
    // l'empreinte de l'adresse de retour y sont répétées : 66 octets à elles deux).
    assert!(n < 600, "le cœur doit rester minimal ({n} octets)");
}

//! Sas de rechargement v0.2.1 (contracts/sas.sil) avec le cœur v0.9.2 (contracts/coeur.sil) : comportement
//! des deux contrats ensemble contre le vrai moteur de script, compilateur figé. Chaque entrée de la
//! transaction est exécutée. Banc complet (attaques nommées, sabotages, fuzzing) : cli/src/lignee.rs.
//! Les pièces du coffre portent la lignée `LIGNEE` ; le sas est lié à cette lignée.
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

const COEUR: &str = include_str!("coeur.sil");
const SAS: &str = include_str!("sas.sil");
const C: i64 = 50_000_000; // capacité : 0,5 KAS
const R: i64 = 36_000;
const V: u64 = 300_000_000; // pièce du coffre
const D: u64 = 1_000_000_000; // dépôt au sas
const F: u64 = 6_000_000; // plafond de frais du sas
const FEE: u64 = 3_000_000;

fn kp(b: u8) -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
}
fn x(b: u8) -> Vec<u8> {
    kp(b).x_only_public_key().0.serialize().to_vec()
}
fn p2pk(b: u8) -> ScriptPublicKey {
    let mut s = vec![0x20];
    s.extend(x(b));
    s.push(0xac);
    ScriptPublicKey::new(0, s.into())
}
fn spk_hash(spk: &ScriptPublicKey) -> Vec<u8> {
    let bytes: Vec<u8> = spk.version().to_be_bytes().into_iter().chain(spk.script().iter().copied()).collect();
    Params::new().hash_length(32).hash(&bytes).as_bytes().to_vec()
}
fn spk(a: &SilAbiArtifact) -> ScriptPublicKey {
    pay_to_script_hash_script(&bytecode(a))
}
/// Lignée du coffre d'essai, et lignée d'un attaquant (sa propre genèse à la même adresse).
const LIGNEE: Hash = Hash::from_bytes([0xA1; 32]);
const FAUSSE: Hash = Hash::from_bytes([0xB2; 32]);
/// Coffre v0.9 : propriétaire 1, agent `agent`, adresse de retour = clé 11.
fn coffre(agent: u8) -> SilAbiArtifact {
    compile_contract(COEUR, &[x(1).into(), x(agent).into(), C.into(), R.into(), spk_hash(&p2pk(11)).into()], CompileOptions::default()).unwrap()
}
fn sas(c: &SilAbiArtifact) -> SilAbiArtifact {
    compile_contract(
        SAS,
        &[spk_hash(&spk(c)).into(), LIGNEE.as_bytes().to_vec().into(), spk_hash(&p2pk(11)).into(), x(1).into(), (F as i64).into()],
        CompileOptions::default(),
    )
    .unwrap()
}

/// Entrée d'essai : (contrat, valeur, entrée appelée, signataire éventuel).
type In<'a> = (&'a SilAbiArtifact, u64, &'static str, Option<u8>);

fn liee(valeur: u64, s: ScriptPublicKey, id: Hash, entree: u16) -> TransactionOutput {
    TransactionOutput { value: valeur, script_public_key: s, covenant: Some(CovenantBinding { authorizing_input: entree, covenant_id: id }) }
}
fn libre(valeur: u64, s: ScriptPublicKey) -> TransactionOutput {
    TransactionOutput { value: valeur, script_public_key: s, covenant: None }
}
/// Forme ordinaire : les pièces d'un coffre (entrées `absorb`, `ownerControl`, `pay`) portent la
/// lignée ; les dépôts du sas n'en portent pas ; une sortie au script de l'entrée 0, si celle-ci
/// porte la lignée, reste dans la lignée, autorisée par l'entrée 0.
fn passe(entrees: &[In], outs: Vec<(u64, ScriptPublicKey)>) -> bool {
    let lignees: Vec<Option<Hash>> = entrees.iter().map(|e| if matches!(e.2, "recharger" | "retour") { None } else { Some(LIGNEE) }).collect();
    let coffre = lignees[0].map(|_| spk(entrees[0].0));
    let outputs = outs.into_iter().map(|(v, s)| if Some(&s) == coffre.as_ref() { liee(v, s, LIGNEE, 0) } else { libre(v, s) }).collect();
    passe_brut(entrees, &lignees, outputs)
}
/// Forme libre : lignée de chaque pièce en entrée et de chaque sortie choisies par l'essai.
/// Vrai si le script de CHAQUE entrée accepte la transaction.
fn passe_brut(entrees: &[In], lignees: &[Option<Hash>], outputs: Vec<TransactionOutput>) -> bool {
    let inputs = (0..entrees.len())
        .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), i as u32), vec![], 0, 1000))
        .collect();
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let utxos: Vec<UtxoEntry> = entrees.iter().zip(lignees).map(|((a, v, _, _), l)| UtxoEntry::new(*v, spk(a), 0, false, *l)).collect();
    for (i, (a, _, entree, signe)) in entrees.iter().enumerate() {
        let args: Vec<ArtifactValue> = match signe {
            Some(cle) => {
                let r = SigHashReusedValuesUnsync::new();
                let h = calc_schnorr_signature_hash(&PopulatedTransaction::new(&tx, utxos.clone()), i, SIG_HASH_ALL, &r);
                let mut sig = kp(*cle).sign_schnorr(Message::from_digest_slice(h.as_bytes().as_slice()).unwrap()).as_ref().to_vec();
                sig.push(SIG_HASH_ALL.to_u8());
                vec![ArtifactValue::from(sig)]
            }
            None => vec![],
        };
        let mut ss = encode_entry_sig_script(a, entree, &args).unwrap();
        ss.extend(push_redeem_script(&bytecode(a)));
        tx.inputs[i].signature_script = ss;
    }
    (0..entrees.len()).all(|i| execute_input_with_covenants(tx.clone(), utxos.clone(), i).is_ok())
}

#[test]
fn le_depot_regonfle_une_piece_du_coffre_sans_cle() {
    let c = coffre(2);
    let s = sas(&c);
    let m = spk(&c);
    let (absorb, depot): (In, In) = ((&c, V, "absorb", None), (&s, D, "recharger", None));
    assert!(passe(&[absorb, depot], vec![(V + D - FEE, m.clone())]), "rechargement sans clé accepté");
    assert!(passe(&[absorb, depot], vec![(V + D - F, m.clone())]), "frais au plafond acceptés");
    assert!(!passe(&[absorb, depot], vec![(V + D - F - 1, m.clone())]), "un sompi de frais au-delà du plafond : refusé");
    assert!(!passe(&[absorb, depot], vec![(V + C as u64, m.clone())]), "dépôt brûlé en frais : refusé");
    assert!(!passe(&[absorb, depot], vec![(V + D - FEE, p2pk(9))]), "vers un tiers : refusé");
    assert!(!passe(&[absorb, depot], vec![(V + C as u64, m.clone()), (D - C as u64 - FEE, m.clone())]), "pièce supplémentaire au coffre : refusé");
    assert!(!passe(&[absorb, depot], vec![(V + D - F, m.clone()), (F - FEE, p2pk(9))]), "frais détournés vers un tiers : refusé");
    assert!(!passe(&[depot, absorb], vec![(V + D - FEE, m.clone())]), "sas en entrée 0 : refusé");
    assert!(!passe(&[depot], vec![(D - FEE, m.clone())]), "dépôt seul (nouvelle pièce au coffre) : refusé");
    assert!(!passe(&[absorb, depot, depot], vec![(V + D - FEE, m.clone())]), "deux dépôts, un seul compté : refusé");
    assert!(!passe(&[absorb, absorb, depot], vec![(2 * V + D - FEE, m.clone())]), "fusion de deux pièces du coffre : refusé");
    // Minimum : la pièce du coffre doit grossir d'au moins la capacité.
    assert!(passe(&[absorb, (&s, C as u64 + FEE, "recharger", None)], vec![(V + C as u64, m.clone())]), "dépôt minimal exact accepté");
    assert!(!passe(&[absorb, (&s, C as u64 + FEE - 1, "recharger", None)], vec![(V + C as u64 - 1, m.clone())]), "dépôt sous le minimum, sans clé : refusé");
    assert!(passe(&[(&c, V, "ownerControl", Some(1)), (&s, 1_000_000 + FEE, "recharger", None)], vec![(V + 1_000_000, m.clone())]), "petit dépôt avec le propriétaire : accepté");
    // Le sas est lié à UN coffre.
    let autre = coffre(3);
    assert!(!passe(&[(&autre, V, "absorb", None), depot], vec![(V + D - FEE, spk(&autre))]), "autre coffre : refusé");
    // L'agent ne peut pas se servir du dépôt.
    assert!(!passe(&[(&c, V, "pay", Some(2)), depot], vec![(1_000_000, p2pk(9)), (V + D - 1_000_000 - FEE, m.clone())]), "paiement de l'agent avec le dépôt : refusé");
}

#[test]
fn le_depot_ne_revient_qu_a_l_adresse_de_retour() {
    let c = coffre(2);
    let s = sas(&c);
    let rt = p2pk(11);
    assert!(passe(&[(&s, D, "retour", Some(1))], vec![(D - FEE, rt.clone())]), "retour par le propriétaire accepté");
    assert!(passe(&[(&s, D, "retour", Some(1))], vec![(D - F, rt.clone())]), "frais au plafond acceptés");
    assert!(!passe(&[(&s, D, "retour", Some(1))], vec![(D - F - 1, rt.clone())]), "frais au-delà du plafond : refusé");
    assert!(!passe(&[(&s, D, "retour", Some(1))], vec![(D - FEE, p2pk(1))]), "vers l'adresse ordinaire du propriétaire : refusé");
    assert!(!passe(&[(&s, D, "retour", Some(1))], vec![(D - FEE, p2pk(9))]), "vers un tiers : refusé");
    assert!(!passe(&[(&s, D, "retour", Some(2))], vec![(D - FEE, rt.clone())]), "signé par l'agent : refusé");
    assert!(passe(&[(&s, D, "retour", Some(1)), (&s, D, "retour", Some(1))], vec![(D - FEE, rt.clone()), (D - FEE, rt.clone())]), "retour par lot accepté");
    assert!(!passe(&[(&s, D, "retour", Some(1)), (&s, D, "retour", Some(1))], vec![(2 * D - FEE, rt.clone())]), "deux dépôts sur une sortie : refusé");
    assert!(passe(&[(&c, V, "ownerControl", Some(1)), (&s, D, "retour", Some(1))], vec![(V - FEE, rt.clone()), (D - FEE, rt.clone())]), "gel du coffre et retour du dépôt ensemble");
    // v0.2.1 (W10) : le dépôt renvoyé est une pièce ordinaire. Une lignée neuve (genèse autorisée
    // par l'entrée du dépôt, valide pour le réseau) est refusée par le sas.
    let neuve = {
        let out = libre(D - FEE, rt.clone());
        let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), std::iter::once((0u32, &out)));
        liee(D - FEE, rt.clone(), id, 0)
    };
    assert!(passe_brut(&[(&s, D, "retour", Some(1))], &[None], vec![libre(D - FEE, rt.clone())]), "témoin : retour ordinaire");
    assert!(!passe_brut(&[(&s, D, "retour", Some(1))], &[None], vec![neuve]), "dépôt renvoyé marqué d'une lignée neuve : refusé");
}

/// S3 (note du sas v0.1) : un attaquant crée une pièce de poussière à l'adresse du coffre et y fait
/// verser le dépôt. Avec la lignée, toutes les présentations de cette pièce sont refusées.
#[test]
fn le_depot_ne_va_que_dans_la_lignee_du_coffre() {
    let c = coffre(2);
    let s = sas(&c);
    let m = spk(&c);
    const P: u64 = 20_000_000; // poussière de l'attaquant
    let (poussiere, depot): (In, In) = ((&c, P, "absorb", None), (&s, D, "recharger", None));
    let t = P + D - FEE;
    // Témoin : la vraie pièce du coffre, dans la lignée.
    assert!(passe_brut(&[(&c, V, "absorb", None), depot], &[Some(LIGNEE), None], vec![liee(V + D - FEE, m.clone(), LIGNEE, 0)]));
    // Poussière sans lignée.
    assert!(!passe_brut(&[poussiere, depot], &[None, None], vec![libre(t, m.clone())]), "poussière sans lignée : refusé");
    assert!(!passe_brut(&[poussiere, depot], &[None, None], vec![liee(t, m.clone(), LIGNEE, 0)]), "lignée du coffre usurpée en sortie : refusé par le réseau");
    assert!(!passe_brut(&[poussiere, depot], &[None, None], vec![liee(t, m.clone(), LIGNEE, 1)]), "lignée autorisée par le dépôt : refusé par le réseau");
    // Poussière portant une fausse lignée (genèse de l'attaquant).
    assert!(!passe_brut(&[poussiere, depot], &[Some(FAUSSE), None], vec![liee(t, m.clone(), FAUSSE, 0)]), "fausse lignée : refusé par le sas");
    assert!(!passe_brut(&[poussiere, depot], &[Some(FAUSSE), None], vec![liee(t, m.clone(), LIGNEE, 0)]), "fausse lignée rebaptisée : refusé par le réseau");
    assert!(!passe_brut(&[poussiere, depot], &[Some(FAUSSE), None], vec![libre(t, m.clone())]), "fausse lignée, sortie sans lignée : refusé");
    // Même avec la clé du propriétaire (volée) : pas de versement dans une pièce hors lignée.
    let vole: In = (&c, P, "ownerControl", Some(1));
    assert!(!passe_brut(&[vole, depot], &[None, None], vec![libre(t, m.clone())]), "clé du propriétaire, poussière sans lignée : refusé");
    assert!(!passe_brut(&[vole, depot], &[Some(FAUSSE), None], vec![liee(t, m.clone(), FAUSSE, 0)]), "clé du propriétaire, fausse lignée : refusé");
    // Le dépôt versé reste dans la lignée, et n'y ajoute pas de pièce.
    assert!(!passe_brut(&[(&c, V, "absorb", None), depot], &[Some(LIGNEE), None], vec![libre(V + D - FEE, m.clone())]), "pièce sortie de la lignée : refusé");
    // Une pièce de la lignée sous un autre script (genèse mal faite) : le sas vérifie aussi le script.
    let autre = coffre(3);
    assert!(!passe_brut(&[(&autre, V, "absorb", None), depot], &[Some(LIGNEE), None], vec![liee(V + D - FEE, spk(&autre), LIGNEE, 0)]), "lignée sous un autre script : refusé");
}

#[test]
fn taille_du_sas() {
    let n = bytecode(&sas(&coffre(2))).len();
    eprintln!("Sas v0.2.1 : {n} octets");
    // v0.2 : 227 octets ; la règle « retour sans lignée » en ajoute 37 (l'identifiant nul, 33 octets).
    assert!(n < 270, "le sas doit rester minimal ({n} octets)");
}

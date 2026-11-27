//! Sas de rechargement v0.1 (contracts/archive/sas-v0.1.sil) : une adresse sans clé de dépense où
//! l'on dépose de l'argent pour UN coffre (cœur v0.8, contracts/archive/coeur-v0.8.sil).
//!
//! ARCHIVÉ : remplacé par le cœur v0.9 et le sas v0.2 à lignée KIP-20 (src/lignee.rs), qui ferment
//! la limite S3 figée ici par `limite_depot_verse_dans_la_piece_d_un_tiers`. Ce banc reste pour
//! comparer les deux versions ; rien de ce fichier n'a été déployé.
//!
//! Un dépôt au sas ne peut que regonfler une pièce existante du coffre (`recharger`, sans clé :
//! la pièce du coffre est dépensée par son entrée `absorb`) ou revenir à l'adresse de retour
//! (`retour`, clé du propriétaire). Plafond ne détient jamais l'argent, et la clé du propriétaire
//! n'a pas besoin d'être en ligne pour recharger.
//!
//! Preuve : spec/borne-de-perte-v0.6.md §8 ; analyse d'attaque : spec/red-team/sas-2026-11-27.md.
//! Pas encore branché sur les commandes de l'outil : à essayer d'abord sur le testnet.
#![allow(dead_code)]

use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use secp256k1::Keypair;
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use crate::coeur::Coeur;
use crate::{FEE, Res, sign, vault_sigscript, vault_spk};

pub const SOURCE: &str = include_str!("../../contracts/archive/sas-v0.1.sil");
/// Budgets de calcul déclarés (marge incluse), mesurés par `tests::rechargement_sans_cle`.
/// `absorb` et `recharger` ne vérifient aucune signature.
pub const CB_ABSORB: u16 = 2;
pub const CB_RECHARGER: u16 = 2;
pub const CB_RETOUR: u16 = 12;
/// Frais d'un rechargement (deux entrées), pris sur le dépôt.
pub const FRAIS_RECHARGE: u64 = 2 * FEE;
/// Plafond de frais par défaut inscrit dans le sas : le double des frais ordinaires. C'est aussi le
/// plus qu'un tiers malveillant peut faire brûler en frais sur un dépôt.
pub const FRAIS_MAX_DEFAUT: i64 = 2 * FRAIS_RECHARGE as i64;

/// Paramètres d'un sas : tout est public, n'importe qui peut recompiler le script et vérifier
/// l'adresse où il s'apprête à payer.
#[derive(Clone, Debug, PartialEq)]
pub struct Sas {
    /// Empreinte blake2b (32 octets) du script du coffre v0.8 rechargé par ce sas.
    pub coffre: Vec<u8>,
    /// Empreinte de l'adresse de retour : celle du coffre.
    pub retour: Vec<u8>,
    pub owner: Vec<u8>,
    pub max_frais: i64,
}

impl Sas {
    /// Le sas d'un coffre v0.8 : lié à l'empreinte de son script et à son adresse de retour.
    pub fn pour(coeur: &Coeur, max_frais: i64) -> Res<Sas> {
        let art = coeur.artifact_v08()?;
        let retour = coeur.retour.clone().ok_or("le sas exige un coffre avec adresse de retour")?;
        let s = Sas { coffre: crate::sequestre::spk_hash(&vault_spk(&art)).to_vec(), retour, owner: coeur.owner.clone(), max_frais };
        s.verifier(coeur)?;
        Ok(s)
    }

    /// Refuse les réglages absurdes. Frais négatifs : aucun rechargement possible, dépôt bloqué.
    /// Frais au-delà de la capacité : un tiers pourrait brûler plus qu'un achat sur chaque dépôt.
    pub fn verifier(&self, coeur: &Coeur) -> Res<()> {
        if self.coffre.len() != 32 || self.retour.len() != 32 || self.owner.len() != 32 {
            return Err("paramètres du sas invalides (32 octets attendus)".into());
        }
        if self.max_frais < 0 || self.max_frais > coeur.capacite {
            return Err("plafond de frais du sas hors de 0..=capacité".into());
        }
        Ok(())
    }

    pub fn artifact(&self) -> Res<SilAbiArtifact> {
        let args: Vec<ArtifactValue> = vec![self.coffre.clone().into(), self.retour.clone().into(), self.owner.clone().into(), self.max_frais.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
    }

    /// Plus petit dépôt qu'on peut verser SANS clé : la pièce du coffre doit grossir d'au moins la
    /// capacité (règle `absorb`), et les frais sont pris sur le dépôt.
    pub fn depot_minimal(coeur: &Coeur, frais: u64) -> u64 {
        coeur.capacite as u64 + frais
    }
}

/// Rechargement sans clé : [pièce du coffre, dépôt du sas] -> [pièce du coffre regonflée].
/// Aucune signature : n'importe qui peut construire et diffuser cette transaction.
pub fn build_recharger(
    coeur: &Coeur,
    sas: &Sas,
    piece: (TransactionOutpoint, u64),
    depot: (TransactionOutpoint, u64),
    frais: u64,
) -> Res<Transaction> {
    let (art_c, art_s) = (coeur.artifact_v08()?, sas.artifact()?);
    if frais as i128 > sas.max_frais as i128 {
        return Err(format!("frais {frais} au-delà du plafond du sas {}", sas.max_frais).into());
    }
    if depot.1 < Sas::depot_minimal(coeur, frais) {
        return Err(format!("dépôt {} trop petit : il faut au moins {} (capacité + frais)", depot.1, Sas::depot_minimal(coeur, frais)).into());
    }
    let inputs = vec![
        TransactionInput::new_with_compute_budget(piece.0, vault_sigscript(&art_c, "absorb", &[])?, 0, CB_ABSORB),
        TransactionInput::new_with_compute_budget(depot.0, vault_sigscript(&art_s, "recharger", &[])?, 0, CB_RECHARGER),
    ];
    let outputs = vec![TransactionOutput::new(piece.1 + depot.1 - frais, vault_spk(&art_c))];
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    tx.finalize();
    Ok(tx)
}

/// Retour des dépôts en attente vers l'adresse de retour, signé par le propriétaire :
/// dépôt i -> sortie i, `frais` pris sur chaque dépôt.
pub fn build_retour(sas: &Sas, depots: &[(TransactionOutpoint, u64)], retour: &ScriptPublicKey, frais: u64, owner: &Keypair) -> Res<Transaction> {
    let art = sas.artifact()?;
    if crate::sequestre::spk_hash(retour).as_slice() != sas.retour.as_slice() {
        return Err("ce n'est pas l'adresse de retour du sas".into());
    }
    if frais as i128 > sas.max_frais as i128 || depots.iter().any(|d| d.1 <= frais) {
        return Err("frais au-delà du plafond du sas ou d'un dépôt".into());
    }
    let inputs = depots.iter().map(|d| TransactionInput::new_with_compute_budget(d.0, vec![], 0, CB_RETOUR)).collect();
    let outputs = depots.iter().map(|d| TransactionOutput::new(d.1 - frais, retour.clone())).collect();
    let entries: Vec<UtxoEntry> = depots.iter().map(|d| UtxoEntry::new(d.1, vault_spk(&art), 0, false, None)).collect();
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..depots.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = vault_sigscript(&art, "retour", &[s.into()])?;
    }
    tx.finalize();
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::constants::{SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK};
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::{PopulatedTransaction, TransactionId, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::script_builder::ScriptBuilder;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_address_script};
    use proptest::prelude::*;

    const C: u64 = 50_000_000; // capacité : 0,5 KAS par achat
    const R: u64 = 36_000; // période : une heure
    const V: u64 = 300_000_000; // pièce du coffre : 3 KAS
    const D: u64 = 1_000_000_000; // dépôt au sas : 10 KAS
    const F: u64 = FRAIS_MAX_DEFAUT as u64; // plafond de frais du sas
    const FR: u64 = FRAIS_RECHARGE; // frais ordinaires

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }
    fn p2pk(b: u8) -> ScriptPublicKey {
        pay_to_address_script(&crate::address(&k(b)))
    }
    fn empreinte(spk: &ScriptPublicKey) -> Vec<u8> {
        crate::sequestre::spk_hash(spk).to_vec()
    }
    fn cases(n: u32) -> u32 {
        std::env::var("FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(n)
    }
    /// Propriétaire : clé 1 ; agent : clé 2 ; adresse de retour : clé 11 ; attaquant : clé 10.
    fn coeur_avec(agent: u8, capacite: i64) -> Coeur {
        Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(agent)), capacite, periode: R as i64, retour: Some(empreinte(&p2pk(11))) }
    }
    fn compiler_coeur(source: &str, c: &Coeur) -> SilAbiArtifact {
        let args: Vec<ArtifactValue> =
            vec![c.owner.clone().into(), c.agent.clone().into(), c.capacite.into(), c.periode.into(), c.retour.clone().unwrap().into()];
        compile_to_sil_abi_artifact_with_options(source, &args, CompileOptions::default()).unwrap()
    }
    fn compiler_sas(source: &str, coffre: &ScriptPublicKey, max_frais: i64) -> SilAbiArtifact {
        let args: Vec<ArtifactValue> = vec![empreinte(coffre).into(), empreinte(&p2pk(11)).into(), crate::xonly(&k(1)).into(), max_frais.into()];
        compile_to_sil_abi_artifact_with_options(source, &args, CompileOptions::default()).unwrap()
    }

    /// Un banc d'essai : un coffre et son sas, compilés depuis des sources données (les vraies, ou
    /// des sources sabotées pour vérifier que chaque règle est utile).
    struct Banc {
        coffre: SilAbiArtifact,
        sas: SilAbiArtifact,
        /// Un autre coffre v0.8 (autre agent) et le coffre v0.7 des mêmes réglages.
        autre: SilAbiArtifact,
        v07: SilAbiArtifact,
    }
    fn banc(source_coeur: &str, source_sas: &str) -> Banc {
        let coffre = compiler_coeur(source_coeur, &coeur_avec(2, C as i64));
        let sas = compiler_sas(source_sas, &vault_spk(&coffre), F as i64);
        Banc { coffre, sas, autre: compiler_coeur(source_coeur, &coeur_avec(3, C as i64)), v07: coeur_avec(2, C as i64).artifact().unwrap() }
    }
    fn vrai() -> Banc {
        banc(crate::coeur::SOURCE_V08, SOURCE)
    }

    /// Une entrée d'une transaction d'essai.
    #[derive(Clone)]
    enum In<'a> {
        /// Pièce d'un contrat, dépensée par l'entrée `entree`, signée ou non.
        Script { art: &'a SilAbiArtifact, valeur: u64, entree: &'static str, signe: Option<u8> },
        /// Pièce ordinaire d'un tiers.
        Tiers { cle: u8, valeur: u64 },
    }
    fn sc<'a>(art: &'a SilAbiArtifact, valeur: u64, entree: &'static str) -> In<'a> {
        In::Script { art, valeur, entree, signe: None }
    }
    fn sg<'a>(art: &'a SilAbiArtifact, valeur: u64, entree: &'static str, cle: u8) -> In<'a> {
        In::Script { art, valeur, entree, signe: Some(cle) }
    }

    fn monter(entrees: &[In], sorties: &[(u64, ScriptPublicKey)], seq: u64) -> (Transaction, Vec<UtxoEntry>) {
        let inputs = (0..entrees.len())
            .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), i as u32), vec![], seq, 20))
            .collect();
        let entries: Vec<UtxoEntry> = entrees
            .iter()
            .map(|e| match e {
                In::Script { art, valeur, .. } => UtxoEntry::new(*valeur, vault_spk(art), 1_000, false, None),
                In::Tiers { cle, valeur } => UtxoEntry::new(*valeur, p2pk(*cle), 1_000, false, None),
            })
            .collect();
        let outputs = sorties.iter().map(|(v, spk)| TransactionOutput::new(*v, spk.clone())).collect();
        let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        for (i, e) in entrees.iter().enumerate() {
            tx.inputs[i].signature_script = match e {
                In::Script { art, entree, signe: None, .. } => vault_sigscript(art, entree, &[]).unwrap(),
                In::Script { art, entree, signe: Some(cle), .. } => vault_sigscript(art, entree, &[sign(&tx, &entries, i, &k(*cle)).into()]).unwrap(),
                In::Tiers { cle, .. } => ScriptBuilder::new().add_data(&sign(&tx, &entries, i, &k(*cle))).unwrap().drain(),
            };
        }
        (tx, entries)
    }

    /// Script de l'entrée `idx` : le vrai moteur de Kaspa. Renvoie les unités de calcul consommées.
    fn script_entree(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> Option<u64> {
        let populated = PopulatedTransaction::new(tx, entries.to_vec());
        let cov = CovenantsContext::from_tx(&populated).ok()?;
        let cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        let input = populated.inputs()[idx].clone();
        let mut vm = TxScriptEngine::from_transaction_input(
            &populated,
            &input,
            idx,
            populated.utxo(idx).unwrap(),
            EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov),
            EngineFlags::default(),
        );
        if let Err(e) = vm.execute() {
            if std::env::var("PLAFOND_DEBUG_SCRIPT").is_ok() {
                eprintln!("entrée {idx} refusée : {e}");
            }
            return None;
        }
        Some(vm.used_script_units().0.div_ceil(kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT))
    }

    /// Le réseau accepte : le script de CHAQUE entrée accepte, les sorties ne dépassent pas les
    /// entrées, et le verrou relatif de chaque entrée est échu au score `pov` (règle de consensus
    /// copiée de rusty-kaspa 2.1.0, comme dans coeur.rs).
    fn acceptee_a(tx: &Transaction, entries: &[UtxoEntry], pov: u64) -> bool {
        let entrees: u128 = entries.iter().map(|e| e.amount as u128).sum();
        let sorties: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
        let verrous = tx.inputs.iter().zip(entries).all(|(i, e)| {
            i.sequence & SEQUENCE_LOCK_TIME_DISABLED == SEQUENCE_LOCK_TIME_DISABLED
                || (e.block_daa_score as i64 + (i.sequence & SEQUENCE_LOCK_TIME_MASK) as i64 - 1) < pov as i64
        });
        verrous && sorties <= entrees && (0..entries.len()).all(|i| script_entree(tx, entries, i).is_some())
    }
    /// Longtemps après la création des pièces : seuls les scripts et les montants décident.
    fn acceptee(essai: &(Transaction, Vec<UtxoEntry>)) -> bool {
        acceptee_a(&essai.0, &essai.1, u32::MAX as u64 * 2)
    }

    type Essai = (Transaction, Vec<UtxoEntry>);

    /// Ce qui doit passer : le rechargement sans clé et les gestes du propriétaire.
    fn legitimes(b: &Banc) -> Vec<(&'static str, Essai)> {
        let (m, rt, x) = (vault_spk(&b.coffre), p2pk(11), p2pk(10));
        vec![
            ("rechargement sans clé", monter(&[sc(&b.coffre, V, "absorb"), sc(&b.sas, D, "recharger")], &[(V + D - FR, m.clone())], 0)),
            ("frais exactement au plafond du sas", monter(&[sc(&b.coffre, V, "absorb"), sc(&b.sas, D, "recharger")], &[(V + D - F, m.clone())], 0)),
            ("dépôt minimal exact (capacité + frais)", monter(&[sc(&b.coffre, V, "absorb"), sc(&b.sas, C + FR, "recharger")], &[(V + C, m.clone())], 0)),
            ("petit dépôt, avec la signature du propriétaire", monter(&[sg(&b.coffre, V, "ownerControl", 1), sc(&b.sas, C / 2, "recharger")], &[(V + C / 2 - FR, m.clone())], 0)),
            ("don direct d'un tiers, au moins la capacité", monter(&[sc(&b.coffre, V, "absorb"), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C, m.clone()), (C - FR, x.clone())], 0)),
            (
                "deux pièces regonflées, chacune vers sa sortie (pas de fusion)",
                monter(&[sc(&b.coffre, V, "absorb"), sc(&b.coffre, V, "absorb"), In::Tiers { cle: 10, valeur: 3 * C }], &[(V + C, m.clone()), (V + C, m.clone()), (C - FR, x.clone())], 0),
            ),
            ("retour d'un dépôt par le propriétaire", monter(&[sg(&b.sas, D, "retour", 1)], &[(D - FR, rt.clone())], 0)),
            ("retour de deux dépôts, chacun vers sa sortie", monter(&[sg(&b.sas, D, "retour", 1), sg(&b.sas, D, "retour", 1)], &[(D - F, rt.clone()), (D - FR, rt.clone())], 0)),
            ("gel du coffre et retour du dépôt ensemble", monter(&[sg(&b.coffre, V, "ownerControl", 1), sg(&b.sas, D, "retour", 1)], &[(V - FR, rt.clone()), (D - FR, rt.clone())], 0)),
            ("paiement de l'agent (inchangé)", monter(&[sg(&b.coffre, V, "pay", 2)], &[(C - FR, x.clone()), (V - C, m.clone())], R)),
            ("gel par le propriétaire (inchangé)", monter(&[sg(&b.coffre, V, "ownerControl", 1)], &[(V - FR, rt.clone())], 0)),
        ]
    }

    /// Ce qui ne doit jamais passer. Chaque attaque a un nom ; les contrats sabotés (plus bas)
    /// doivent en laisser passer au moins une, ce qui prouve que la liste voit chaque règle.
    fn attaques(b: &Banc) -> Vec<(&'static str, Essai)> {
        let (m, rt, x) = (vault_spk(&b.coffre), p2pk(11), p2pk(10));
        let (absorb, depot) = (sc(&b.coffre, V, "absorb"), sc(&b.sas, D, "recharger"));
        vec![
            // Le dépôt ne va que dans CE coffre.
            ("autre coffre", monter(&[sc(&b.autre, V, "absorb"), depot.clone()], &[(V + D - FR, vault_spk(&b.autre))], 0)),
            ("coffre v0.7 des mêmes réglages", monter(&[sg(&b.v07, V, "ownerControl", 1), depot.clone()], &[(V + D - FR, vault_spk(&b.v07))], 0)),
            ("pièce d'un tiers en entrée 0 : nouvelle pièce au coffre", monter(&[In::Tiers { cle: 10, valeur: V }, depot.clone()], &[(V + D - FR, m.clone())], 0)),
            ("sortie vers un tiers", monter(&[absorb.clone(), depot.clone()], &[(V + D - FR, x.clone())], 0)),
            ("sas en entrée 0", monter(&[depot.clone(), absorb.clone()], &[(V + D - FR, m.clone())], 0)),
            ("dépôt seul, sans pièce du coffre", monter(&[depot.clone()], &[(D - FR, m.clone())], 0)),
            // Pas de pièce en plus, rien pour un tiers.
            ("pièce supplémentaire au coffre", monter(&[absorb.clone(), depot.clone()], &[(V + C, m.clone()), (D - C - FR, m.clone())], 0)),
            ("frais détournés vers un tiers", monter(&[absorb.clone(), depot.clone()], &[(V + D - F, m.clone()), (F - FR, x.clone())], 0)),
            // Frais bornés.
            ("vol par les frais, un sompi au-delà du plafond", monter(&[absorb.clone(), depot.clone()], &[(V + D - F - 1, m.clone())], 0)),
            ("dépôt brûlé en frais", monter(&[absorb.clone(), depot.clone()], &[(V + C, m.clone())], 0)),
            // Deux entrées, pas plus.
            ("deux dépôts, un seul compté", monter(&[absorb.clone(), depot.clone(), depot.clone()], &[(V + D - FR, m.clone())], 0)),
            ("fusion de deux pièces du coffre par le sas", monter(&[absorb.clone(), absorb.clone(), depot.clone()], &[(2 * V + D - FR, m.clone())], 0)),
            ("tiers en troisième entrée", monter(&[absorb.clone(), depot.clone(), In::Tiers { cle: 10, valeur: C }], &[(V + D + C - FR, m.clone())], 0)),
            // La pièce du coffre : pas de fusion, pas de gêne gratuite, pas de vol.
            ("fusion de deux pièces du coffre sans le sas", monter(&[absorb.clone(), absorb.clone(), In::Tiers { cle: 10, valeur: 2 * C }], &[(2 * V + C, m.clone()), (C - FR, x.clone())], 0)),
            ("regonflement un sompi sous le minimum", monter(&[absorb.clone(), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C - 1, m.clone()), (C + 1 - FR, x.clone())], 0)),
            ("regonflement nul (gêne gratuite)", monter(&[absorb.clone(), In::Tiers { cle: 10, valeur: C }], &[(V, m.clone()), (C - FR, x.clone())], 0)),
            ("petit dépôt sans clé", monter(&[absorb.clone(), sc(&b.sas, C + FR - 1, "recharger")], &[(V + C - 1, m.clone())], 0)),
            ("pièce du coffre prise par absorb", monter(&[absorb.clone(), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C, x.clone()), (C - FR, x.clone())], 0)),
            ("pièce du coffre brûlée par absorb", monter(&[absorb.clone()], &[(1_000, m.clone())], 0)),
            ("l'agent paie avec le dépôt", monter(&[sg(&b.coffre, V, "pay", 2), depot.clone()], &[(C - FR, x.clone()), (V + D - C, m.clone())], R)),
            // Même avec la clé du propriétaire (volée), rien ne part ailleurs.
            ("clé du propriétaire : pièce et dépôt vers un tiers", monter(&[sg(&b.coffre, V, "ownerControl", 1), depot.clone()], &[(V + D - FR, x.clone())], 0)),
            ("retour vers un tiers", monter(&[sg(&b.sas, D, "retour", 1)], &[(D - FR, x.clone())], 0)),
            ("retour signé par l'agent", monter(&[sg(&b.sas, D, "retour", 2)], &[(D - FR, rt.clone())], 0)),
            ("retour : frais au-delà du plafond", monter(&[sg(&b.sas, D, "retour", 1)], &[(D - F - 1, rt.clone())], 0)),
            ("retour : deux dépôts sur une sortie", monter(&[sg(&b.sas, D, "retour", 1), sg(&b.sas, D, "retour", 1)], &[(2 * D - FR, rt.clone())], 0)),
        ]
    }

    /// Les transactions légitimes passent, aucune attaque ne passe (vrai moteur de script, chaque
    /// entrée exécutée).
    #[test]
    fn le_depot_ne_peut_que_regonfler_le_coffre_ou_revenir() {
        let b = vrai();
        for (nom, essai) in legitimes(&b) {
            assert!(acceptee(&essai), "refusé à tort : {nom}");
        }
        for (nom, essai) in attaques(&b) {
            assert!(!acceptee(&essai), "attaque acceptée : {nom}");
        }
    }

    /// Chaque règle est sabotée à son tour (la ligne est retirée ou affaiblie, puis le contrat est
    /// recompilé). Une règle porteuse sabotée doit laisser passer l'attaque attendue ; cela prouve
    /// aussi que la liste d'attaques sait voir cette règle.
    #[test]
    fn chaque_regle_sabotee_est_detectee() {
        let (coeur, sas) = (crate::coeur::SOURCE_V08, SOURCE);
        // (contrat saboté : 0 = sas, 1 = cœur ; texte retiré ; remplacement ; attaque qui doit passer)
        let sabotages: [(u8, &str, &str, Option<&str>); 11] = [
            (0, "tx.inputs.length == 2 && tx.outputs.length == 1", "tx.outputs.length == 1", Some("deux dépôts, un seul compté")),
            (0, "tx.inputs.length == 2 && tx.outputs.length == 1", "tx.inputs.length == 2", Some("frais détournés vers un tiers")),
            (0, "require(blake2b(coffre) == coffreSpkHash);", "", Some("autre coffre")),
            (0, "require(tx.outputs[0].value >= tx.inputs[0].value + tx.inputs[1].value - maxFrais);", "", Some("dépôt brûlé en frais")),
            (0, "require(checkSig(ownerSig, ownerKey));", "", Some("retour signé par l'agent")),
            (0, "require(blake2b(tx.outputs[i].scriptPubKey) == retourSpkHash);", "", Some("retour vers un tiers")),
            (0, "require(tx.outputs[i].value >= tx.inputs[i].value - maxFrais);", "", Some("retour : frais au-delà du plafond")),
            // Non porteuse : le script du coffre impose déjà la destination de sa propre pièce.
            // Gardée pour que le sas ne dépende pas, sur ce point, de la lecture du cœur.
            (0, "require(tx.outputs[0].scriptPubKey == coffre);", "", None),
            (1, "require(tx.outputs[i].scriptPubKey == tx.inputs[i].scriptPubKey);", "", Some("pièce du coffre prise par absorb")),
            (1, "require(tx.outputs[i].value >= tx.inputs[i].value + capacity);", "", Some("pièce du coffre brûlée par absorb")),
            (1, "tx.inputs[i].value + capacity);", "tx.inputs[i].value);", Some("regonflement nul (gêne gratuite)")),
        ];
        for (lequel, texte, remplacement, attendue) in sabotages {
            let source = if lequel == 0 { sas } else { coeur };
            assert_eq!(source.matches(texte).count(), 1, "règle introuvable ou ambiguë dans le source : {texte}");
            let sabote = source.replace(texte, remplacement);
            let b = if lequel == 0 { banc(coeur, &sabote) } else { banc(&sabote, sas) };
            let passees: Vec<&str> = attaques(&b).into_iter().filter(|(_, e)| acceptee(e)).map(|(n, _)| n).collect();
            match attendue {
                Some(nom) => assert!(passees.contains(&nom), "sabotage non détecté : sans « {texte} », l'attaque « {nom} » devrait passer (passées : {passees:?})"),
                None => assert!(passees.is_empty(), "règle annoncée non porteuse, mais {passees:?} passe sans « {texte} »"),
            }
        }
    }

    /// Les transactions construites par l'outil : acceptées, dans les budgets de calcul déclarés,
    /// sous la masse standard, frais suffisants. Tailles des deux scripts.
    #[test]
    fn rechargement_sans_cle() {
        let c = coeur_avec(2, C as i64);
        let sas = Sas::pour(&c, FRAIS_MAX_DEFAUT).unwrap();
        let (art_c, art_s) = (c.artifact_v08().unwrap(), sas.artifact().unwrap());
        let op = |i: u32| TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), i);
        let tx = build_recharger(&c, &sas, (op(0), V), (op(1), D), FRAIS_RECHARGE).unwrap();
        let entries = vec![UtxoEntry::new(V, vault_spk(&art_c), 1_000, false, None), UtxoEntry::new(D, vault_spk(&art_s), 2_000, false, None)];
        let (u0, u1) = (script_entree(&tx, &entries, 0).expect("absorb accepté"), script_entree(&tx, &entries, 1).expect("recharger accepté"));
        assert!(u0 <= CB_ABSORB as u64 && u1 <= CB_RECHARGER as u64, "budgets de calcul : absorb {u0}, recharger {u1}");
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!((tx.outputs[0].value, &tx.outputs[0].script_public_key), (V + D - FRAIS_RECHARGE, &vault_spk(&art_c)));
        assert!(tx.inputs.iter().all(|i| i.sequence == 0), "aucune attente : le dépôt est versé dès qu'il est confirmé");
        let m = crate::masse::masses(&tx, &entries).unwrap();
        assert!(m.standard() && m.compute * 100 <= FRAIS_RECHARGE, "masse {} / {} / {}", m.compute, m.transient, m.storage);
        assert!(crate::garde_diffusion(&tx).is_ok());
        eprintln!(
            "cœur v0.8 : {} octets (v0.7 : {}) ; sas : {} octets ; absorb = {u0} unité(s), recharger = {u1} ; masse {} g calcul, {} g stockage",
            crate::bytecode(&art_c).len(),
            crate::bytecode(&c.artifact().unwrap()).len(),
            crate::bytecode(&art_s).len(),
            m.compute,
            m.storage
        );
        // L'outil refuse ce que le réseau refuserait.
        assert!(build_recharger(&c, &sas, (op(0), V), (op(1), Sas::depot_minimal(&c, FRAIS_RECHARGE) - 1), FRAIS_RECHARGE).is_err(), "dépôt trop petit");
        assert!(build_recharger(&c, &sas, (op(0), V), (op(1), D), F + 1).is_err(), "frais au-delà du plafond");
        assert!(build_recharger(&c, &sas, (op(0), V), (op(1), Sas::depot_minimal(&c, FRAIS_RECHARGE)), FRAIS_RECHARGE).is_ok());
        assert!(Sas::pour(&c, -1).is_err() && Sas::pour(&c, C as i64 + 1).is_err(), "plafond de frais absurde refusé");
        assert!(Sas::pour(&Coeur { retour: None, ..c.clone() }, 0).is_err(), "pas de sas pour un coffre v0.6");

        // Retour par le propriétaire.
        let tx = build_retour(&sas, &[(op(1), D), (op(2), 2 * D)], &p2pk(11), FRAIS_RECHARGE, &k(1)).unwrap();
        let entries = vec![UtxoEntry::new(D, vault_spk(&art_s), 0, false, None), UtxoEntry::new(2 * D, vault_spk(&art_s), 0, false, None)];
        for i in 0..2 {
            let u = script_entree(&tx, &entries, i).expect("retour accepté");
            assert!(u <= CB_RETOUR as u64, "budget du retour : {u}");
        }
        assert!(crate::masse::masses(&tx, &entries).unwrap().standard());
        assert!(build_retour(&sas, &[(op(1), D)], &p2pk(10), FRAIS_RECHARGE, &k(1)).is_err(), "l'outil refuse une autre adresse");
        let vole = build_retour(&sas, &[(op(1), D)], &p2pk(11), FRAIS_RECHARGE, &k(2)).unwrap();
        assert!(script_entree(&vole, &entries[..1], 0).is_none(), "retour signé par l'agent refusé");
    }

    /// Les coffres v0.7 ne changent pas (même script, même adresse, toujours gelables) et n'ont pas
    /// d'entrée sans clé. Le cœur v0.8 a une autre adresse.
    #[test]
    fn coffres_v07_inchanges_et_sans_absorb() {
        let ref07 = Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: crate::CAPACITY, periode: crate::JOUR_DAA, retour: Some(empreinte(&p2pk(1))) };
        let b2 = |code: &[u8]| hex::encode(blake2b_simd::Params::new().hash_length(32).hash(code).as_bytes());
        assert_eq!(b2(&crate::bytecode(&ref07.artifact().unwrap())), "b85e0c9df3a116287344ce7f0a11bc275758f14de64b62642fda39238b8122be", "bytecode v0.7 inchangé");
        assert_eq!(b2(crate::coeur::SOURCE.as_bytes()), "817f910f77087108678e9541892bc208c5790927356a733a028ee94e50b7f894", "source v0.7 archivé à l'identique");
        let b = vrai();
        assert_ne!(vault_spk(&b.coffre), vault_spk(&b.v07));
        // Gel d'un coffre v0.7 : toujours accepté.
        assert!(acceptee(&monter(&[sg(&b.v07, V, "ownerControl", 1)], &[(V - FR, p2pk(11))], 0)));
        // L'appel `absorb` (sélecteur du cœur v0.8) présenté à un script v0.7 : refusé.
        let (mut tx, entries) = monter(&[sg(&b.v07, V, "ownerControl", 1), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C, vault_spk(&b.v07)), (C - FR, p2pk(10))], 0);
        assert!(acceptee(&(tx.clone(), entries.clone())), "témoin : le propriétaire recharge un coffre v0.7");
        let mut appel = crate::encode_contract_entry_sig_script(&b.coffre, b.coffre.contracts.keys().next().unwrap(), "absorb", &[]).unwrap();
        appel.extend(ScriptBuilder::new().add_data(&crate::bytecode(&b.v07)).unwrap().drain());
        tx.inputs[0].signature_script = appel;
        assert!(script_entree(&tx, &entries, 0).is_none(), "un coffre v0.7 ne se regonfle pas sans clé");
    }

    /// Réglages aberrants : une capacité nulle ou négative ne doit pas ouvrir `absorb` (avec une
    /// capacité négative, « grossir d'au moins la capacité » laisserait fondre la pièce). L'outil
    /// refuse ces réglages ; le script les refuse aussi, par une garde explicite (R63).
    #[test]
    fn absorb_refuse_avec_une_capacite_aberrante() {
        for cap in [0i64, -1, -(C as i64)] {
            let art = compiler_coeur(crate::coeur::SOURCE_V08, &coeur_avec(2, cap));
            let m = vault_spk(&art);
            for sortie in [V, V + 1, (V as i64 + cap) as u64, V + C] {
                let essai = monter(&[sc(&art, V, "absorb"), In::Tiers { cle: 10, valeur: 2 * C }], &[(sortie, m.clone())], 0);
                assert!(!acceptee(&essai), "absorb accepté avec capacité {cap}, sortie {sortie}");
            }
            assert!(coeur_avec(2, cap).artifact_v08().is_err(), "l'outil refuse la capacité {cap}");
        }
        // Sans la garde, la pièce fondrait : la garde est porteuse pour ces réglages.
        let sabote = crate::coeur::SOURCE_V08.replace("require(capacity > 0);", "");
        assert_ne!(sabote, crate::coeur::SOURCE_V08);
        let art = compiler_coeur(&sabote, &coeur_avec(2, -(C as i64)));
        assert!(acceptee(&monter(&[sc(&art, V, "absorb")], &[(V - C, vault_spk(&art))], 0)), "témoin : sans la garde, la pièce fond");
    }

    /// Prix de la gêne. Regonfler remet l'âge de la pièce à zéro : le paiement que l'agent préparait
    /// est refusé par le réseau. Pour bloquer les achats de prix `p`, il faut regonfler avant chaque
    /// échéance ⌈p × R / C⌉, et chaque regonflement coûte au moins la capacité, DONNÉE au coffre.
    #[test]
    fn gene_payante_et_donnee_au_proprietaire() {
        let c = coeur_avec(2, C as i64);
        let b = vrai();
        let (m, x) = (vault_spk(&b.coffre), p2pk(10));
        let prix = C / 10; // l'agent veut payer un dixième de la capacité, frais compris
        let attente = c.attente(prix as i64);
        assert_eq!(attente, R / 10);
        // La pièce a l'âge voulu : le paiement passerait.
        let cree = 1_000u64;
        let (pay, e) = monter(&[sg(&b.coffre, V, "pay", 2)], &[(prix - FR, x.clone()), (V - prix, m.clone())], attente);
        assert!(acceptee_a(&pay, &e, cree + attente), "témoin : paiement à l'heure accepté");
        // L'attaquant regonfle juste avant : +C de sa poche. La pièce est remplacée, d'âge nul.
        let gene = monter(&[sc(&b.coffre, V, "absorb"), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C, m.clone()), (C - FR, x.clone())], 0);
        assert!(acceptee_a(&gene.0, &gene.1, cree + attente - 1));
        let t = cree + attente - 1;
        let (pay2, mut e2) = monter(&[sg(&b.coffre, V + C, "pay", 2)], &[(prix - FR, x.clone()), (V + C - prix, m.clone())], attente);
        e2[0].block_daa_score = t;
        assert!(!acceptee_a(&pay2, &e2, t + attente - 1), "après la gêne, l'agent doit attendre de nouveau");
        assert!(acceptee_a(&pay2, &e2, t + attente), "… mais pas plus que le délai ordinaire");
        // Coût pour bloquer ce prix pendant une période entière, par pièce : (R / attente) × C.
        let tours = R.div_ceil(attente);
        let cout = tours * C;
        assert_eq!(cout, 10 * C, "bloquer des achats de C/10 pendant une période coûte 10 capacités par pièce");
        assert_eq!(R.div_ceil(c.attente(C as i64)) * C, C, "bloquer seulement les achats au plafond : une capacité par période et par pièce");
        // Tout ce que l'attaquant a versé appartient au propriétaire : il le récupère par le gel.
        let gel = monter(&[sg(&b.coffre, V + cout, "ownerControl", 1)], &[(V + cout - FR, p2pk(11))], 0);
        assert!(acceptee(&gel), "le propriétaire récupère la pièce grossie des dons de l'attaquant");
    }

    /// LIMITE CONNUE (spec/red-team/sas-2026-11-27.md, S3). Le sas ne sait pas distinguer une pièce
    /// « d'origine » d'une pièce qu'un tiers vient de créer à l'adresse du coffre (n'importe qui peut
    /// envoyer de l'argent à une adresse). Un attaquant actif peut donc faire verser un dépôt dans
    /// SA pièce de poussière : le dépôt n'ajoute pas de pièce, mais l'ancienne pièce du propriétaire
    /// garde son solde et son rythme à côté. Ce test fige ce comportement et ce qu'il coûte.
    #[test]
    fn limite_depot_verse_dans_la_piece_d_un_tiers() {
        let c = coeur_avec(2, C as i64);
        let b = vrai();
        let m = vault_spk(&b.coffre);
        let poussiere = 20_000_000u64; // pièce créée par l'attaquant à l'adresse du coffre
        let essai = monter(&[sc(&b.coffre, poussiere, "absorb"), sc(&b.sas, D, "recharger")], &[(poussiere + D - FR, m.clone())], 0);
        assert!(acceptee(&essai), "comportement figé : le dépôt peut regonfler n'importe quelle pièce du coffre");
        // Pire cas sur une fenêtre d'une période, juste après : l'ancienne pièce (ancienne, V) et la
        // pièce regonflée (âge nul). Le rythme est celui de DEUX pièces tant que l'ancienne a du solde.
        let detourne = c.fenetre(V, R, R) + c.fenetre(poussiere + D - FR, 0, R);
        let honnete = c.fenetre(V + D - FR, 0, R);
        assert_eq!((detourne, honnete), (2 * C + C, C));
        // Borne de l'excès : ce que l'ancienne pièce pouvait déjà perdre seule, jamais plus que son solde.
        assert!(detourne - honnete <= c.fenetre(V, R, R).min(V));
        // La courbe promise (§1b) tient : le dépôt est une racine d'âge nul, comme tout apport.
        assert_eq!(c.fenetre(poussiere + D - FR, 0, 0), 0, "pas de rafale sur le dépôt");
    }

    /// Un tiers peut-il « marquer » la pièce du coffre en la regonflant (identifiant de covenant
    /// KIP-20 posé sur la sortie) pour la rendre inutilisable ? Non : le cœur ne lit pas cet
    /// identifiant, et la pièce marquée reste payable, gelable et regonflable. (L'agent ou un
    /// déposant pouvaient déjà créer une telle pièce en v0.7 ; `absorb` n'ajoute rien.)
    #[test]
    fn piece_marquee_par_un_tiers_reste_utilisable() {
        use kaspa_consensus_core::hashing::covenant_id::covenant_id;
        use kaspa_consensus_core::tx::CovenantBinding;
        let b = vrai();
        let (m, x, rt) = (vault_spk(&b.coffre), p2pk(10), p2pk(11));
        let (mut tx, entries) = monter(&[sc(&b.coffre, V, "absorb"), In::Tiers { cle: 10, valeur: 2 * C }], &[(V + C, m.clone()), (C - FR, x.clone())], 0);
        let id = covenant_id(tx.inputs[0].previous_outpoint, std::iter::once((0u32, &tx.outputs[0])));
        tx.outputs[0].covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: id });
        tx.inputs[1].signature_script = ScriptBuilder::new().add_data(&sign(&tx, &entries, 1, &k(10))).unwrap().drain();
        let marquage_accepte = acceptee(&(tx, entries));
        eprintln!("regonflement avec identifiant de covenant : {}", if marquage_accepte { "accepté" } else { "refusé" });
        // Que le réseau accepte ou non ce marquage, une pièce marquée se dépense comme une autre.
        let marquer = |mut essai: Essai| {
            essai.1[0].covenant_id = Some(id);
            essai
        };
        assert!(acceptee(&marquer(monter(&[sg(&b.coffre, V + C, "pay", 2)], &[(C - FR, x.clone()), (V, m.clone())], R))), "pièce marquée : paiement");
        assert!(acceptee(&marquer(monter(&[sg(&b.coffre, V + C, "ownerControl", 1)], &[(V + C - FR, rt.clone())], 0))), "pièce marquée : gel");
        assert!(acceptee(&marquer(monter(&[sc(&b.coffre, V + C, "absorb"), sc(&b.sas, D, "recharger")], &[(V + C + D - FR, m.clone())], 0))), "pièce marquée : rechargement par le sas");
    }

    #[derive(Clone, Debug)]
    enum Geste {
        /// L'agent dépense ce pourcentage du maximum permis à cet instant.
        Payer(u64),
        /// L'agent tente un sompi de plus que le maximum permis.
        Tricher,
        /// Un dépôt de ce montant est versé par le sas (sans clé).
        Recharger(u64),
        /// Un tiers regonfle la pièce de sa poche pour gêner l'agent.
        Gener,
    }
    fn geste() -> impl Strategy<Value = (u64, Geste)> {
        let g = prop_oneof![
            5 => (1u64..=100).prop_map(Geste::Payer),
            1 => Just(Geste::Tricher),
            2 => (C + FR..=20 * C).prop_map(Geste::Recharger),
            1 => Just(Geste::Gener),
        ];
        (prop_oneof![0u64..50, 0u64..R / 4, 0u64..3 * R], g)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(cases(200)))]
        /// Un coffre d'une pièce, un agent avide ou tricheur, des rechargements par le sas et des
        /// gênes de tiers, dans un ordre et à des instants quelconques. Chaque transaction passe par
        /// le vrai moteur et par la règle du verrou relatif. Vérifié à chaque pas :
        ///  - il y a toujours exactement une pièce au coffre (le sas n'ajoute pas de rythme) ;
        ///  - ce que l'agent a sorti depuis le début reste sous min(C, C·g/R) + C·t/R, quels que
        ///    soient les montants rechargés (la borne ne dépend pas de l'argent ajouté) ;
        ///  - les frais pris sur les dépôts restent sous le plafond du sas ;
        ///  - rien d'autre ne se perd : la valeur de la pièce est exactement expliquée.
        #[test]
        fn sas_et_agent_avide_sous_la_borne(age0 in prop_oneof![Just(0u64), 0u64..2 * R], gestes in proptest::collection::vec(geste(), 1..40)) {
            let c = coeur_avec(2, C as i64);
            let b = vrai();
            let (m, x) = (vault_spk(&b.coffre), p2pk(10));
            let debut = 10 * R;
            let (mut valeur, mut cree, mut now) = (V, debut - age0, debut);
            let (mut sorti, mut verse, mut frais_sas, mut depots) = (0u64, 0u64, 0u64, 0u64);
            for (dt, g) in gestes {
                now += dt;
                let age = now - cree;
                match g {
                    Geste::Payer(pct) => {
                        let spent = c.immediate(valeur, age) * pct / 100;
                        if spent <= FR {
                            continue;
                        }
                        let (tx, mut e) = monter(&[sg(&b.coffre, valeur, "pay", 2)], &[(spent - FR, x.clone()), (valeur - spent, m.clone())], c.attente(spent as i64));
                        e[0].block_daa_score = cree;
                        prop_assert!(acceptee_a(&tx, &e, now), "paiement permis refusé : {spent} à l'âge {age}");
                        prop_assert_eq!(tx.outputs.iter().filter(|o| o.script_public_key == m).count(), 1);
                        valeur -= spent;
                        sorti += spent;
                        cree = now;
                    }
                    Geste::Tricher => {
                        let spent = c.immediate(u64::MAX, age) + 1;
                        if spent > valeur || spent <= FR {
                            continue;
                        }
                        for seq in [c.attente(spent.min(C) as i64), age, 0] {
                            let (tx, mut e) = monter(&[sg(&b.coffre, valeur, "pay", 2)], &[(spent - FR, x.clone()), (valeur - spent, m.clone())], seq);
                            e[0].block_daa_score = cree;
                            prop_assert!(!acceptee_a(&tx, &e, now), "dépense {spent} au-delà du rythme acceptée à l'âge {age} (sequence {seq})");
                        }
                    }
                    Geste::Recharger(d) => {
                        let frais = if d % 2 == 0 { FR } else { F };
                        let op = |i: u32| TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), i);
                        let sas = Sas::pour(&c, FRAIS_MAX_DEFAUT).unwrap();
                        let Ok(tx) = build_recharger(&c, &sas, (op(0), valeur), (op(1), d), frais) else {
                            prop_assert!(d < C + frais, "l'outil refuse un dépôt suffisant");
                            continue;
                        };
                        let e = vec![UtxoEntry::new(valeur, m.clone(), cree, false, None), UtxoEntry::new(d, vault_spk(&b.sas), now, false, None)];
                        prop_assert!(acceptee_a(&tx, &e, now), "rechargement refusé : dépôt {d}");
                        prop_assert_eq!(tx.outputs.iter().filter(|o| o.script_public_key == m).count(), 1);
                        prop_assert_eq!(tx.outputs.len(), 1);
                        valeur = tx.outputs[0].value;
                        verse += d;
                        frais_sas += frais;
                        depots += 1;
                        cree = now;
                    }
                    Geste::Gener => {
                        let (tx, mut e) = monter(&[sc(&b.coffre, valeur, "absorb"), In::Tiers { cle: 10, valeur: 2 * C }], &[(valeur + C, m.clone()), (C - FR, x.clone())], 0);
                        e[0].block_daa_score = cree;
                        prop_assert!(acceptee_a(&tx, &e, now));
                        valeur += C;
                        verse += C;
                        cree = now;
                    }
                }
                prop_assert!(sorti <= c.fenetre(u64::MAX, age0, now - debut), "borne dépassée : sorti {sorti} en {} unités (âge initial {age0})", now - debut);
                prop_assert!(frais_sas <= depots * F);
                prop_assert_eq!(valeur, V + verse - sorti - frais_sas, "valeur inexpliquée");
            }
        }
    }
}

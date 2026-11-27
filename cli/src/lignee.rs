//! Coffre à lignée (cœur v0.9, contracts/coeur.sil) et sas de rechargement v0.2 (contracts/sas.sil).
//!
//! Le coffre est une LIGNÉE de pièces, suivie par le réseau (identifiant de covenant, KIP-20) :
//!  - l'identifiant naît à la création du coffre (genèse) ; le réseau le calcule à partir de la pièce
//!    dépensée et des pièces créées, personne ne peut le choisir ni le recopier sur une autre pièce ;
//!  - le cœur v0.9 impose qu'une pièce de la lignée ait au plus une héritière, sa propre sortie :
//!    le nombre de pièces du coffre ne peut plus jamais augmenter ;
//!  - le sas v0.2 ne verse un dépôt que dans une pièce de cette lignée.
//! Une pièce envoyée à l'adresse du coffre par un tiers n'est donc ni rechargeable, ni dépensable
//! par l'agent : la limite S3 du sas v0.1 (src/sas.rs) est fermée par construction.
//!
//! Preuve : spec/borne-de-perte-v0.9.md ; analyse d'attaque : spec/red-team/lignee-2026-11-27.md.
//! Pas encore branché sur les commandes de l'outil : à essayer d'abord sur le testnet.
#![allow(dead_code)]

use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_consensus_core::Hash;
use secp256k1::Keypair;
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use crate::coeur::Coeur;
use crate::{FEE, Res, sign, vault_sigscript, vault_spk};

/// Sas v0.2 : lié au coffre par l'empreinte de son script ET par l'identifiant de sa lignée.
pub const SOURCE: &str = include_str!("../../contracts/sas.sil");
/// Budgets de calcul déclarés (marge incluse), mesurés par `tests::transactions_de_l_outil`.
pub const CB_ABSORB: u16 = 2;
pub const CB_RECHARGER: u16 = 2;
pub const CB_RETOUR: u16 = 12;
pub const CB_PAY: u16 = 12;
pub const CB_OWNER: u16 = 12;
/// Frais d'un rechargement (deux entrées), pris sur le dépôt.
pub const FRAIS_RECHARGE: u64 = 2 * FEE;
/// Plafond de frais par défaut inscrit dans le sas : le double des frais ordinaires. C'est aussi le
/// plus qu'un tiers malveillant peut faire brûler en frais sur un dépôt.
pub const FRAIS_MAX_DEFAUT: i64 = 2 * FRAIS_RECHARGE as i64;
/// Nombre maximal de pièces d'un coffre à la genèse (comme `PIECES_MAX` pour les coffres v0.7).
pub const PIECES_MAX: usize = crate::PIECES_MAX as usize;

/// Sortie rattachée à une lignée, autorisée par l'entrée `entree`.
pub fn sortie_liee(valeur: u64, spk: ScriptPublicKey, lignee: Hash, entree: u16) -> TransactionOutput {
    TransactionOutput { value: valeur, script_public_key: spk, covenant: Some(CovenantBinding { authorizing_input: entree, covenant_id: lignee }) }
}

/// Paramètres d'un sas : tout est public, n'importe qui peut recompiler le script et vérifier
/// l'adresse où il s'apprête à payer.
#[derive(Clone, Debug, PartialEq)]
pub struct Sas {
    /// Empreinte blake2b (32 octets) du script du coffre v0.9 rechargé par ce sas.
    pub coffre: Vec<u8>,
    /// Identifiant de covenant (32 octets) de la lignée du coffre.
    pub lignee: Vec<u8>,
    /// Empreinte de l'adresse de retour : celle du coffre.
    pub retour: Vec<u8>,
    pub owner: Vec<u8>,
    pub max_frais: i64,
}

impl Sas {
    /// Le sas d'un coffre v0.9 : lié à l'empreinte de son script, à sa lignée et à son adresse de retour.
    pub fn pour(coeur: &Coeur, lignee: Hash, max_frais: i64) -> Res<Sas> {
        let art = coeur.artifact_v09()?;
        let retour = coeur.retour.clone().ok_or("le sas exige un coffre avec adresse de retour")?;
        let s = Sas {
            coffre: crate::sequestre::spk_hash(&vault_spk(&art)).to_vec(),
            lignee: lignee.as_bytes().to_vec(),
            retour,
            owner: coeur.owner.clone(),
            max_frais,
        };
        s.verifier(coeur)?;
        Ok(s)
    }

    /// Refuse les réglages absurdes. Frais négatifs : aucun rechargement possible, dépôt bloqué.
    /// Frais au-delà de la capacité : un tiers pourrait brûler plus qu'un achat sur chaque dépôt.
    /// Lignée nulle : c'est la valeur que le moteur rend pour une pièce SANS lignée ; aucun coffre
    /// réel ne la porte (le script du cœur refuserait de toute façon une telle pièce).
    pub fn verifier(&self, coeur: &Coeur) -> Res<()> {
        if self.coffre.len() != 32 || self.lignee.len() != 32 || self.retour.len() != 32 || self.owner.len() != 32 {
            return Err("paramètres du sas invalides (32 octets attendus)".into());
        }
        if self.lignee.iter().all(|b| *b == 0) {
            return Err("lignée nulle : ce n'est pas l'identifiant d'un coffre".into());
        }
        if self.max_frais < 0 || self.max_frais > coeur.capacite {
            return Err("plafond de frais du sas hors de 0..=capacité".into());
        }
        Ok(())
    }

    pub fn artifact(&self) -> Res<SilAbiArtifact> {
        let args: Vec<ArtifactValue> =
            vec![self.coffre.clone().into(), self.lignee.clone().into(), self.retour.clone().into(), self.owner.clone().into(), self.max_frais.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
    }

    pub fn id(&self) -> Hash {
        Hash::from_bytes(<[u8; 32]>::try_from(self.lignee.as_slice()).expect("vérifié : 32 octets"))
    }

    /// Plus petit dépôt qu'on peut verser SANS clé : la pièce du coffre doit grossir d'au moins la
    /// capacité (règle `absorb`), et les frais sont pris sur le dépôt.
    pub fn depot_minimal(coeur: &Coeur, frais: u64) -> u64 {
        coeur.capacite as u64 + frais
    }
}

/// Création d'un coffre à lignée (genèse KIP-20) : les `valeurs` deviennent les pièces du coffre,
/// sorties 0..k, toutes rattachées à la même lignée, autorisée par l'entrée 0. L'identifiant est
/// celui que le réseau recalcule : blake2b(« CovenantID », pièce dépensée en entrée 0, sorties du
/// coffre). Le nombre de pièces `k` est définitif : c'est le nombre de rythmes du coffre.
/// `fonds` : pièces ordinaires du propriétaire ; `rendu` : sa monnaie éventuelle (hors lignée).
pub fn build_genese(
    coeur: &Coeur,
    fonds: &[(TransactionOutpoint, UtxoEntry)],
    valeurs: &[u64],
    rendu: Option<(u64, ScriptPublicKey)>,
    owner: &Keypair,
) -> Res<(Transaction, Hash)> {
    let art = coeur.artifact_v09()?;
    if fonds.is_empty() || valeurs.is_empty() || valeurs.len() > PIECES_MAX {
        return Err(format!("un coffre a de 1 à {PIECES_MAX} pièces, et il faut au moins une pièce pour le financer").into());
    }
    let m = vault_spk(&art);
    let inputs = fonds.iter().map(|f| TransactionInput::new_with_compute_budget(f.0, vec![], 0, crate::CB_P2PK)).collect();
    let mut outputs: Vec<TransactionOutput> = valeurs.iter().map(|v| TransactionOutput::new(*v, m.clone())).collect();
    let lignee = covenant_id(fonds[0].0, outputs.iter().enumerate().map(|(i, o)| (i as u32, o)));
    for o in outputs.iter_mut() {
        o.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: lignee });
    }
    if let Some((v, spk)) = rendu {
        outputs.push(TransactionOutput::new(v, spk));
    }
    let entries: Vec<UtxoEntry> = fonds.iter().map(|f| f.1.clone()).collect();
    let (entrees, sorties): (u128, u128) = (entries.iter().map(|e| e.amount as u128).sum(), outputs.iter().map(|o| o.value as u128).sum());
    if sorties > entrees {
        return Err("fonds insuffisants pour créer le coffre".into());
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..fonds.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = kaspa_txscript::script_builder::ScriptBuilder::new().add_data(&s)?.drain();
    }
    tx.finalize();
    Ok((tx, lignee))
}

/// Paiement de l'agent depuis une pièce de la lignée : `montant` au bénéficiaire, le reste moins
/// les frais revient au coffre, dans la lignée. `sequence` = délai exigé, sauf valeur forcée.
#[allow(clippy::too_many_arguments)]
pub fn build_pay(
    c: &Coeur,
    piece: (TransactionOutpoint, u64),
    lignee: Hash,
    beneficiaire: ScriptPublicKey,
    montant: u64,
    frais: u64,
    agent: &Keypair,
    sequence: Option<u64>,
) -> Res<Transaction> {
    let art = c.artifact_v09()?;
    let spent = montant.checked_add(frais).filter(|s| *s <= piece.1).ok_or("montant + frais au-delà de la pièce")?;
    if spent as i64 > c.capacite {
        return Err(format!("dépense {spent} au-delà de la capacité {}", c.capacite).into());
    }
    let m = vault_spk(&art);
    let input = TransactionInput::new_with_compute_budget(piece.0, vec![], sequence.unwrap_or_else(|| c.attente(spent as i64)), CB_PAY);
    let outputs = vec![TransactionOutput::new(montant, beneficiaire), sortie_liee(piece.1 - spent, m.clone(), lignee, 0)];
    let mut tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
    let entree = UtxoEntry::new(piece.1, m, 0, false, Some(lignee));
    let s = sign(&tx, std::slice::from_ref(&entree), 0, agent);
    tx.inputs[0].signature_script = vault_sigscript(&art, "pay", &[s.into()])?;
    tx.finalize();
    Ok(tx)
}

/// Rechargement sans clé : [pièce de la lignée, dépôt du sas] -> [pièce regonflée, dans la lignée].
/// Aucune signature : n'importe qui peut construire et diffuser cette transaction.
pub fn build_recharger(c: &Coeur, sas: &Sas, piece: (TransactionOutpoint, u64), depot: (TransactionOutpoint, u64), frais: u64) -> Res<Transaction> {
    let (art_c, art_s) = (c.artifact_v09()?, sas.artifact()?);
    if frais as i128 > sas.max_frais as i128 {
        return Err(format!("frais {frais} au-delà du plafond du sas {}", sas.max_frais).into());
    }
    if depot.1 < Sas::depot_minimal(c, frais) {
        return Err(format!("dépôt {} trop petit : il faut au moins {} (capacité + frais)", depot.1, Sas::depot_minimal(c, frais)).into());
    }
    let inputs = vec![
        TransactionInput::new_with_compute_budget(piece.0, vault_sigscript(&art_c, "absorb", &[])?, 0, CB_ABSORB),
        TransactionInput::new_with_compute_budget(depot.0, vault_sigscript(&art_s, "recharger", &[])?, 0, CB_RECHARGER),
    ];
    let outputs = vec![sortie_liee(piece.1 + depot.1 - frais, vault_spk(&art_c), sas.id(), 0)];
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    tx.finalize();
    Ok(tx)
}

/// Gel ou retrait par le propriétaire : pièce i -> sortie i à l'adresse de retour, HORS lignée
/// (le contrat l'exige). `pieces` : pièces à l'adresse du coffre, de la lignée ou non (une pièce
/// envoyée par un tiers se rapatrie de la même façon). `frais` pris sur chaque pièce.
pub fn build_gel(c: &Coeur, pieces: &[(TransactionOutpoint, u64, Option<Hash>)], retour: &ScriptPublicKey, frais: u64, owner: &Keypair) -> Res<Transaction> {
    let art = c.artifact_v09()?;
    if c.retour.as_deref() != Some(crate::sequestre::spk_hash(retour).as_slice()) {
        return Err("ce n'est pas l'adresse de retour du coffre".into());
    }
    if frais as i128 > c.capacite as i128 || pieces.iter().any(|p| p.1 <= frais) {
        return Err("frais au-delà de la capacité ou d'une pièce".into());
    }
    let m = vault_spk(&art);
    let inputs = pieces.iter().map(|p| TransactionInput::new_with_compute_budget(p.0, vec![], 0, CB_OWNER)).collect();
    let outputs = pieces.iter().map(|p| TransactionOutput::new(p.1 - frais, retour.clone())).collect();
    let entries: Vec<UtxoEntry> = pieces.iter().map(|p| UtxoEntry::new(p.1, m.clone(), 0, false, p.2)).collect();
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..pieces.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = vault_sigscript(&art, "ownerControl", &[s.into()])?;
    }
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
    const P: u64 = 20_000_000; // pièce de poussière créée par l'attaquant à l'adresse du coffre
    const F: u64 = FRAIS_MAX_DEFAUT as u64; // plafond de frais du sas
    const FR: u64 = FRAIS_RECHARGE; // frais ordinaires

    /// Lignée du coffre d'essai, et lignée d'un attaquant (sa propre genèse, à la même adresse).
    fn x_id() -> Hash {
        Hash::from_bytes([0xA1; 32])
    }
    fn y_id() -> Hash {
        Hash::from_bytes([0xB2; 32])
    }
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
    fn compiler_sas(source: &str, coffre: &ScriptPublicKey, lignee: Hash, max_frais: i64) -> SilAbiArtifact {
        let args: Vec<ArtifactValue> =
            vec![empreinte(coffre).into(), lignee.as_bytes().to_vec().into(), empreinte(&p2pk(11)).into(), crate::xonly(&k(1)).into(), max_frais.into()];
        compile_to_sil_abi_artifact_with_options(source, &args, CompileOptions::default()).unwrap()
    }

    /// Un banc d'essai : un coffre et son sas, compilés depuis des sources données (les vraies, ou
    /// des sources sabotées pour vérifier que chaque règle est utile).
    struct Banc {
        coffre: SilAbiArtifact,
        sas: SilAbiArtifact,
        /// Un autre coffre v0.9 (autre agent), et les coffres v0.8 et v0.7 des mêmes réglages.
        autre: SilAbiArtifact,
        v08: SilAbiArtifact,
        v07: SilAbiArtifact,
    }
    fn banc(source_coeur: &str, source_sas: &str) -> Banc {
        let coffre = compiler_coeur(source_coeur, &coeur_avec(2, C as i64));
        let sas = compiler_sas(source_sas, &vault_spk(&coffre), x_id(), F as i64);
        Banc {
            coffre,
            sas,
            autre: compiler_coeur(source_coeur, &coeur_avec(3, C as i64)),
            v08: coeur_avec(2, C as i64).artifact_v08().unwrap(),
            v07: coeur_avec(2, C as i64).artifact().unwrap(),
        }
    }
    fn vrai() -> Banc {
        banc(crate::coeur::SOURCE_V09, SOURCE)
    }

    /// Une entrée d'une transaction d'essai : une pièce, la lignée qu'elle porte, et qui la dépense.
    #[derive(Clone)]
    enum Cle<'a> {
        /// Pièce d'un contrat, dépensée par l'entrée `entree`, signée ou non.
        Script { art: &'a SilAbiArtifact, entree: &'static str, signe: Option<u8> },
        /// Pièce ordinaire d'un tiers.
        Tiers(u8),
    }
    #[derive(Clone)]
    struct In<'a> {
        cle: Cle<'a>,
        valeur: u64,
        lignee: Option<Hash>,
    }
    impl<'a> In<'a> {
        /// La même pièce, portant cette lignée.
        fn dans(mut self, id: Hash) -> Self {
            self.lignee = Some(id);
            self
        }
        fn spk(&self) -> ScriptPublicKey {
            match &self.cle {
                Cle::Script { art, .. } => vault_spk(art),
                Cle::Tiers(cle) => p2pk(*cle),
            }
        }
    }
    /// Pièce d'un contrat SANS lignée (dépôt au sas, pièce envoyée par un tiers à une adresse).
    fn sc<'a>(art: &'a SilAbiArtifact, valeur: u64, entree: &'static str) -> In<'a> {
        In { cle: Cle::Script { art, entree, signe: None }, valeur, lignee: None }
    }
    fn sg<'a>(art: &'a SilAbiArtifact, valeur: u64, entree: &'static str, cle: u8) -> In<'a> {
        In { cle: Cle::Script { art, entree, signe: Some(cle) }, valeur, lignee: None }
    }
    fn tiers<'a>(cle: u8, valeur: u64) -> In<'a> {
        In { cle: Cle::Tiers(cle), valeur, lignee: None }
    }

    /// Une sortie d'essai : valeur, script, lignée déclarée (identifiant, entrée qui l'autorise).
    type Out = (u64, ScriptPublicKey, Option<(Hash, u16)>);
    /// Sortie sans lignée.
    fn o(valeur: u64, spk: &ScriptPublicKey) -> Out {
        (valeur, spk.clone(), None)
    }
    /// Sortie dans la lignée du coffre, autorisée par l'entrée 0.
    fn l(valeur: u64, spk: &ScriptPublicKey) -> Out {
        (valeur, spk.clone(), Some((x_id(), 0)))
    }
    /// Sortie dans une lignée donnée, autorisée par une entrée donnée.
    fn la(valeur: u64, spk: &ScriptPublicKey, id: Hash, entree: u16) -> Out {
        (valeur, spk.clone(), Some((id, entree)))
    }

    fn op_essai(i: u32) -> TransactionOutpoint {
        TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), i)
    }

    /// Monte une transaction sur des pièces données (référence et score de création choisis).
    fn monter_sur(entrees: &[(In, TransactionOutpoint, u64)], sorties: &[Out], seq: u64) -> (Transaction, Vec<UtxoEntry>) {
        let inputs = entrees.iter().map(|(_, op, _)| TransactionInput::new_with_compute_budget(*op, vec![], seq, 20)).collect();
        let entries: Vec<UtxoEntry> = entrees.iter().map(|(e, _, daa)| UtxoEntry::new(e.valeur, e.spk(), *daa, false, e.lignee)).collect();
        let outputs = sorties
            .iter()
            .map(|(v, spk, lien)| TransactionOutput {
                value: *v,
                script_public_key: spk.clone(),
                covenant: lien.map(|(id, entree)| CovenantBinding { authorizing_input: entree, covenant_id: id }),
            })
            .collect();
        let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        for (i, (e, _, _)) in entrees.iter().enumerate() {
            tx.inputs[i].signature_script = match &e.cle {
                Cle::Script { art, entree, signe: None } => vault_sigscript(art, entree, &[]).unwrap(),
                Cle::Script { art, entree, signe: Some(cle) } => vault_sigscript(art, entree, &[sign(&tx, &entries, i, &k(*cle)).into()]).unwrap(),
                Cle::Tiers(cle) => ScriptBuilder::new().add_data(&sign(&tx, &entries, i, &k(*cle))).unwrap().drain(),
            };
        }
        tx.finalize();
        (tx, entries)
    }
    fn monter(entrees: &[In], sorties: &[Out], seq: u64) -> (Transaction, Vec<UtxoEntry>) {
        let sur: Vec<(In, TransactionOutpoint, u64)> = entrees.iter().enumerate().map(|(i, e)| (e.clone(), op_essai(i as u32), 1_000)).collect();
        monter_sur(&sur, sorties, seq)
    }
    /// Lignée NEUVE et valide pour le réseau : celle qu'une genèse autorisée par l'entrée `entree`
    /// donnerait à la sortie `sortie` de cette transaction d'essai (KIP-20).
    fn genese(sortie: u32, valeur: u64, spk: &ScriptPublicKey, entree: u16) -> Out {
        let out = TransactionOutput::new(valeur, spk.clone());
        let id = covenant_id(op_essai(entree as u32), std::iter::once((sortie, &out)));
        (valeur, spk.clone(), Some((id, entree)))
    }

    /// Script de l'entrée `idx` : le vrai moteur de Kaspa, avec le contexte de lignées que le réseau
    /// construit lui-même (`CovenantsContext::from_tx` refuse une lignée déclarée sans droit).
    /// Renvoie les unités de calcul consommées.
    fn script_entree(tx: &Transaction, entries: &[UtxoEntry], idx: usize) -> Option<u64> {
        let populated = PopulatedTransaction::new(tx, entries.to_vec());
        let cov = match CovenantsContext::from_tx(&populated) {
            Ok(cov) => cov,
            Err(e) => {
                if std::env::var("PLAFOND_DEBUG_SCRIPT").is_ok() {
                    eprintln!("lignée refusée par le réseau : {e}");
                }
                return None;
            }
        };
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

    /// Le réseau accepte : les lignées déclarées sont valides (KIP-20), le script de CHAQUE entrée
    /// accepte, les sorties ne dépassent pas les entrées, et le verrou relatif de chaque entrée est
    /// échu au score `pov` (règles de consensus copiées de rusty-kaspa 2.1.0, comme dans coeur.rs).
    fn acceptee_a(tx: &Transaction, entries: &[UtxoEntry], pov: u64) -> bool {
        let entrees: u128 = entries.iter().map(|e| e.amount as u128).sum();
        let sorties: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
        let verrous = tx.inputs.iter().zip(entries).all(|(i, e)| {
            i.sequence & SEQUENCE_LOCK_TIME_DISABLED == SEQUENCE_LOCK_TIME_DISABLED
                || (e.block_daa_score as i64 + (i.sequence & SEQUENCE_LOCK_TIME_MASK) as i64 - 1) < pov as i64
        });
        verrous && sorties <= entrees && (0..entries.len()).all(|i| script_entree(tx, entries, i).is_some())
    }
    /// Longtemps après la création des pièces : seuls les scripts, les lignées et les montants décident.
    fn acceptee(essai: &Essai) -> bool {
        acceptee_a(&essai.0, &essai.1, u32::MAX as u64 * 2)
    }

    type Essai = (Transaction, Vec<UtxoEntry>);

    /// Ce qui doit passer : le rechargement sans clé, le paiement de l'agent, les gestes du propriétaire.
    fn legitimes(b: &Banc) -> Vec<(&'static str, Essai)> {
        let (m, rt, x) = (vault_spk(&b.coffre), p2pk(11), p2pk(10));
        let (absorb, depot) = (sc(&b.coffre, V, "absorb").dans(x_id()), sc(&b.sas, D, "recharger"));
        let ctrl = sg(&b.coffre, V, "ownerControl", 1).dans(x_id());
        vec![
            ("rechargement sans clé", monter(&[absorb.clone(), depot.clone()], &[l(V + D - FR, &m)], 0)),
            ("frais exactement au plafond du sas", monter(&[absorb.clone(), depot.clone()], &[l(V + D - F, &m)], 0)),
            ("dépôt minimal exact (capacité + frais)", monter(&[absorb.clone(), sc(&b.sas, C + FR, "recharger")], &[l(V + C, &m)], 0)),
            ("petit dépôt, avec la signature du propriétaire", monter(&[ctrl.clone(), sc(&b.sas, C / 2, "recharger")], &[l(V + C / 2 - FR, &m)], 0)),
            ("don direct d'un tiers, au moins la capacité", monter(&[absorb.clone(), tiers(10, 2 * C)], &[l(V + C, &m), o(C - FR, &x)], 0)),
            (
                "deux pièces regonflées, chacune vers sa sortie (pas de fusion)",
                monter(&[absorb.clone(), absorb.clone(), tiers(10, 3 * C)], &[l(V + C, &m), la(V + C, &m, x_id(), 1), o(C - FR, &x)], 0),
            ),
            ("retour d'un dépôt par le propriétaire", monter(&[sg(&b.sas, D, "retour", 1)], &[o(D - FR, &rt)], 0)),
            ("retour de deux dépôts, chacun vers sa sortie", monter(&[sg(&b.sas, D, "retour", 1), sg(&b.sas, D, "retour", 1)], &[o(D - F, &rt), o(D - FR, &rt)], 0)),
            ("gel du coffre et retour du dépôt ensemble", monter(&[ctrl.clone(), sg(&b.sas, D, "retour", 1)], &[o(V - FR, &rt), o(D - FR, &rt)], 0)),
            ("paiement de l'agent", monter(&[sg(&b.coffre, V, "pay", 2).dans(x_id())], &[o(C - FR, &x), la(V - C, &m, x_id(), 0)], R)),
            ("gel par le propriétaire (la pièce quitte la lignée)", monter(&[ctrl.clone()], &[o(V - FR, &rt)], 0)),
            ("gel de deux pièces, chacune vers sa sortie", monter(&[ctrl.clone(), ctrl.clone()], &[o(V - FR, &rt), o(V - FR, &rt)], 0)),
            ("rechargement par le propriétaire (dans la lignée)", monter(&[ctrl.clone(), tiers(1, 2 * C)], &[l(V + C, &m), o(C - FR, &p2pk(1))], 0)),
            ("poussière d'un tiers (sans lignée) rapatriée par le propriétaire", monter(&[sg(&b.coffre, P, "ownerControl", 1)], &[o(P - FR, &rt)], 0)),
            ("pièce d'une autre lignée rapatriée par le propriétaire", monter(&[sg(&b.coffre, P, "ownerControl", 1).dans(y_id())], &[o(P - FR, &rt)], 0)),
        ]
    }

    /// Ce qui ne doit jamais passer. Chaque attaque a un nom ; les contrats sabotés (plus bas)
    /// doivent en laisser passer au moins une, ce qui prouve que la liste voit chaque règle.
    fn attaques(b: &Banc) -> Vec<(&'static str, Essai)> {
        let (m, rt, x) = (vault_spk(&b.coffre), p2pk(11), p2pk(10));
        let (absorb, depot) = (sc(&b.coffre, V, "absorb").dans(x_id()), sc(&b.sas, D, "recharger"));
        let ctrl = sg(&b.coffre, V, "ownerControl", 1).dans(x_id());
        let pay = sg(&b.coffre, V, "pay", 2).dans(x_id());
        // Pièces de poussière créées par l'attaquant à l'adresse du coffre : sans lignée, ou avec
        // SA lignée (une genèse qu'il a faite lui-même, valide pour le réseau).
        let poussiere = sc(&b.coffre, P, "absorb");
        let fausse = sc(&b.coffre, P, "absorb").dans(y_id());
        vec![
            // ------------------------------------------------------------ attaques de la v0.8
            // Le dépôt ne va que dans CE coffre.
            ("autre coffre", monter(&[sc(&b.autre, V, "absorb").dans(x_id()), depot.clone()], &[l(V + D - FR, &vault_spk(&b.autre))], 0)),
            ("coffre v0.7 des mêmes réglages", monter(&[sg(&b.v07, V, "ownerControl", 1).dans(x_id()), depot.clone()], &[l(V + D - FR, &vault_spk(&b.v07))], 0)),
            ("coffre v0.8 des mêmes réglages", monter(&[sc(&b.v08, V, "absorb").dans(x_id()), depot.clone()], &[l(V + D - FR, &vault_spk(&b.v08))], 0)),
            ("pièce d'un tiers en entrée 0 : nouvelle pièce au coffre", monter(&[tiers(10, V), depot.clone()], &[o(V + D - FR, &m)], 0)),
            ("sortie vers un tiers", monter(&[absorb.clone(), depot.clone()], &[l(V + D - FR, &x)], 0)),
            ("sas en entrée 0", monter(&[depot.clone(), absorb.clone()], &[la(V + D - FR, &m, x_id(), 1)], 0)),
            ("dépôt seul, sans pièce du coffre", monter(&[depot.clone()], &[o(D - FR, &m)], 0)),
            // Pas de pièce en plus, rien pour un tiers.
            ("pièce supplémentaire au coffre", monter(&[absorb.clone(), depot.clone()], &[l(V + C, &m), o(D - C - FR, &m)], 0)),
            ("frais détournés vers un tiers", monter(&[absorb.clone(), depot.clone()], &[l(V + D - F, &m), o(F - FR, &x)], 0)),
            // Frais bornés.
            ("vol par les frais, un sompi au-delà du plafond", monter(&[absorb.clone(), depot.clone()], &[l(V + D - F - 1, &m)], 0)),
            ("dépôt brûlé en frais", monter(&[absorb.clone(), depot.clone()], &[l(V + C, &m)], 0)),
            // Deux entrées, pas plus.
            ("deux dépôts, un seul compté", monter(&[absorb.clone(), depot.clone(), depot.clone()], &[l(V + D - FR, &m)], 0)),
            ("fusion de deux pièces du coffre par le sas", monter(&[absorb.clone(), absorb.clone(), depot.clone()], &[l(2 * V + D - FR, &m)], 0)),
            ("tiers en troisième entrée", monter(&[absorb.clone(), depot.clone(), tiers(10, C)], &[l(V + D + C - FR, &m)], 0)),
            // La pièce du coffre : pas de fusion, pas de gêne gratuite, pas de vol.
            ("fusion de deux pièces du coffre sans le sas", monter(&[absorb.clone(), absorb.clone(), tiers(10, 2 * C)], &[l(2 * V + C, &m), o(C - FR, &x)], 0)),
            ("regonflement un sompi sous le minimum", monter(&[absorb.clone(), tiers(10, 2 * C)], &[l(V + C - 1, &m), o(C + 1 - FR, &x)], 0)),
            ("regonflement nul (gêne gratuite)", monter(&[absorb.clone(), tiers(10, C)], &[l(V, &m), o(C - FR, &x)], 0)),
            ("petit dépôt sans clé", monter(&[absorb.clone(), sc(&b.sas, C + FR - 1, "recharger")], &[l(V + C - 1, &m)], 0)),
            ("pièce du coffre prise par absorb", monter(&[absorb.clone(), tiers(10, 2 * C)], &[l(V + C, &x), o(C - FR, &x)], 0)),
            ("pièce du coffre brûlée par absorb", monter(&[absorb.clone()], &[l(1_000, &m)], 0)),
            ("l'agent paie avec le dépôt", monter(&[pay.clone(), depot.clone()], &[o(C - FR, &x), la(V + D - C, &m, x_id(), 0)], R)),
            // Même avec la clé du propriétaire (volée), rien ne part ailleurs.
            ("clé du propriétaire : pièce et dépôt vers un tiers", monter(&[ctrl.clone(), depot.clone()], &[l(V + D - FR, &x)], 0)),
            ("retour vers un tiers", monter(&[sg(&b.sas, D, "retour", 1)], &[o(D - FR, &x)], 0)),
            ("retour signé par l'agent", monter(&[sg(&b.sas, D, "retour", 2)], &[o(D - FR, &rt)], 0)),
            ("retour : frais au-delà du plafond", monter(&[sg(&b.sas, D, "retour", 1)], &[o(D - F - 1, &rt)], 0)),
            ("retour : deux dépôts sur une sortie", monter(&[sg(&b.sas, D, "retour", 1), sg(&b.sas, D, "retour", 1)], &[o(2 * D - FR, &rt)], 0)),
            // ------------------------------------------------------------ S3 : la pièce de poussière
            ("S3 : dépôt versé dans une poussière sans lignée", monter(&[poussiere.clone(), depot.clone()], &[o(P + D - FR, &m)], 0)),
            ("S3 : poussière sans lignée, sortie déclarée dans la lignée du coffre", monter(&[poussiere.clone(), depot.clone()], &[l(P + D - FR, &m)], 0)),
            ("S3 : poussière sans lignée, lignée autorisée par le dépôt", monter(&[poussiere.clone(), depot.clone()], &[la(P + D - FR, &m, x_id(), 1)], 0)),
            ("S3 : poussière adoptée par une genèse pendant le versement", monter(&[poussiere.clone(), depot.clone()], &[genese(0, P + D - FR, &m, 0)], 0)),
            ("S3 : poussière portant une fausse lignée", monter(&[fausse.clone(), depot.clone()], &[la(P + D - FR, &m, y_id(), 0)], 0)),
            ("S3 : fausse lignée en entrée, lignée du coffre déclarée en sortie", monter(&[fausse.clone(), depot.clone()], &[l(P + D - FR, &m)], 0)),
            ("S3 : fausse lignée en entrée, sortie sans lignée", monter(&[fausse.clone(), depot.clone()], &[o(P + D - FR, &m)], 0)),
            // Une pièce de la lignée sous un autre script n'existe que si la genèse a été mal faite ;
            // le sas ne s'en remet pas à cette hypothèse : il vérifie aussi le script.
            ("lignée du coffre sous le script d'un tiers : dépôt volé", monter(&[tiers(10, P).dans(x_id()), depot.clone()], &[l(P + D - FR, &x)], 0)),
            ("lignée du coffre sous le script d'un tiers : dépôt versé au coffre", monter(&[tiers(10, P).dans(x_id()), depot.clone()], &[l(P + D - FR, &m)], 0)),
            // ------------------------------------------------------------ la poussière n'est pas du budget
            ("l'agent paie avec une poussière sans lignée", monter(&[sg(&b.coffre, V, "pay", 2)], &[o(C - FR, &x), o(V - C, &m)], R)),
            ("l'agent paie avec une poussière en déclarant la lignée du coffre", monter(&[sg(&b.coffre, V, "pay", 2)], &[o(C - FR, &x), la(V - C, &m, x_id(), 0)], R)),
            ("l'agent paie avec une poussière en ouvrant une lignée neuve", monter(&[sg(&b.coffre, V, "pay", 2)], &[o(C - FR, &x), genese(1, V - C, &m, 0)], R)),
            ("poussière sans lignée regonflée sans clé", monter(&[poussiere.clone(), tiers(10, 2 * C)], &[o(P + C, &m), o(C - FR, &x)], 0)),
            ("poussière sans lignée adoptée par une genèse (sans clé)", monter(&[poussiere.clone(), tiers(10, 2 * C)], &[genese(0, P + C, &m, 0), o(C - FR, &x)], 0)),
            ("clé du propriétaire : poussière sans lignée regonflée", monter(&[sg(&b.coffre, P, "ownerControl", 1), tiers(10, 2 * C)], &[o(P + C, &m), o(C - FR, &x)], 0)),
            ("clé du propriétaire : poussière adoptée par une genèse", monter(&[sg(&b.coffre, P, "ownerControl", 1), tiers(10, 2 * C)], &[genese(0, P + C, &m, 0), o(C - FR, &x)], 0)),
            // ------------------------------------------------------------ scission : une pièce de plus dans la lignée
            ("scission par l'agent : bénéficiaire rattaché à la lignée", monter(&[pay.clone()], &[la(C - FR, &x, x_id(), 0), la(V - C, &m, x_id(), 0)], R)),
            ("scission par l'agent : seconde pièce du coffre comme bénéficiaire", monter(&[pay.clone()], &[la(C - FR, &m, x_id(), 0), la(V - C, &m, x_id(), 0)], R)),
            ("l'agent déplace la lignée sur le bénéficiaire", monter(&[pay.clone()], &[la(C - FR, &x, x_id(), 0), o(V - C, &m)], R)),
            ("l'agent sort le reste de la lignée", monter(&[pay.clone()], &[o(C - FR, &x), o(V - C, &m)], R)),
            ("scission sans clé : seconde pièce de la lignée au coffre", monter(&[absorb.clone(), tiers(10, 3 * C)], &[l(V + C, &m), l(C, &m), o(C - FR, &x)], 0)),
            ("scission sans clé : pièce de la lignée vers un tiers", monter(&[absorb.clone(), tiers(10, 3 * C)], &[l(V + C, &m), l(C, &x), o(C - FR, &x)], 0)),
            ("regonflement sans clé hors lignée", monter(&[absorb.clone(), tiers(10, 2 * C)], &[o(V + C, &m), o(C - FR, &x)], 0)),
            ("regonflement sans clé : la lignée part sur une autre sortie", monter(&[absorb.clone(), tiers(10, 3 * C)], &[o(V + C, &m), l(C, &m), o(C - FR, &x)], 0)),
            ("clé du propriétaire : seconde pièce dans la lignée", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[l(V, &m), l(C, &m), o(C - FR, &x)], 0)),
            ("clé du propriétaire : pièce de la lignée vers un tiers", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[l(V, &m), l(C, &x), o(C - FR, &x)], 0)),
            ("clé du propriétaire : regonflement hors lignée", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[o(V + C, &m), o(C - FR, &x)], 0)),
            ("clé du propriétaire : la lignée part sur une autre sortie", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[o(V, &m), l(C, &m), o(C - FR, &x)], 0)),
            ("gel : la lignée suit la pièce à l'adresse de retour", monter(&[ctrl.clone()], &[l(V - FR, &rt)], 0)),
            ("gel : une héritière de la lignée reste au coffre", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[o(V - FR, &rt), l(C, &m), o(C - FR, &x)], 0)),
            ("gel : une héritière de la lignée part chez un tiers", monter(&[ctrl.clone(), tiers(10, 2 * C)], &[o(V - FR, &rt), l(C, &x), o(C - FR, &x)], 0)),
            // ------------------------------------------------------------ dépôt détourné
            ("dépôt versé, pièce sortie de la lignée", monter(&[absorb.clone(), depot.clone()], &[o(V + D - FR, &m)], 0)),
            ("dépôt versé par la clé du propriétaire, pièce sortie de la lignée", monter(&[ctrl.clone(), depot.clone()], &[o(V + D - FR, &m)], 0)),
            ("dépôt versé dans une lignée neuve (genèse autorisée par le dépôt)", monter(&[absorb.clone(), depot.clone()], &[genese(0, V + D - FR, &m, 1)], 0)),
            ("gel du coffre avec le dépôt : dépôt fusionné vers l'adresse de retour, sans l'entrée retour", monter(&[ctrl.clone(), sc(&b.sas, D, "recharger")], &[o(V + D - FR, &rt)], 0)),
        ]
    }

    /// Les transactions légitimes passent, aucune attaque ne passe (vrai moteur de script, chaque
    /// entrée exécutée, lignées validées comme le fait le réseau).
    #[test]
    fn coffre_a_lignee_legitimes_acceptees_attaques_refusees() {
        let b = vrai();
        let legit = legitimes(&b);
        for (nom, essai) in &legit {
            assert!(acceptee(essai), "refusé à tort : {nom}");
        }
        let att = attaques(&b);
        for (nom, essai) in &att {
            assert!(!acceptee(essai), "attaque acceptée : {nom}");
        }
        let noms: std::collections::HashSet<&str> = att.iter().map(|a| a.0).collect();
        assert_eq!(noms.len(), att.len(), "deux attaques portent le même nom");
        eprintln!("{} transactions légitimes acceptées, {} attaques nommées refusées", legit.len(), att.len());
    }

    /// Chaque règle est sabotée à son tour (la ligne est retirée ou affaiblie, puis le contrat est
    /// recompilé). Une règle porteuse sabotée doit laisser passer l'attaque attendue ; cela prouve
    /// aussi que la liste d'attaques sait voir cette règle.
    #[test]
    fn chaque_regle_sabotee_est_detectee() {
        let (coeur, sas) = (crate::coeur::SOURCE_V09, SOURCE);
        const PAY: &str = "require(OpAuthOutputCount(this.activeInputIndex) == 1 && OpAuthOutputIdx(this.activeInputIndex, 0) == 1);";
        const HERITIERE: &str = "require(OpAuthOutputCount(i) == 1 && OpAuthOutputIdx(i, 0) == i);";
        const ABSORB_VALEUR: &str = "require(tx.outputs[i].value >= tx.inputs[i].value + capacity);\n";
        const CTRL_VALEUR: &str = "require(tx.outputs[i].value >= valeur);\n";
        // (contrat saboté : 0 = sas, 1 = cœur ; texte à trouver ; remplacement ; attaque qui doit passer)
        // Les deux règles « héritière » du cœur ont le même texte : on les distingue par la ligne
        // qui les précède (ownerControl : `>= valeur` ; absorb : `+ capacity`).
        let ctrl = format!("{CTRL_VALEUR}            // Lignée (v0.9) : une seule héritière, cette sortie. Aucune pièce ajoutée à la lignée.\n            {HERITIERE}");
        let absorb = format!("{ABSORB_VALEUR}        // Lignée (v0.9) : une seule héritière, cette sortie. Une pièce hors lignée ne se regonfle pas.\n        {HERITIERE}");
        let sabotages: Vec<(u8, String, String, Option<&str>)> = vec![
            // ---- règles de la v0.8, toujours porteuses
            (0, "tx.inputs.length == 2 && tx.outputs.length == 1".into(), "tx.outputs.length == 1".into(), Some("deux dépôts, un seul compté")),
            (0, "tx.inputs.length == 2 && tx.outputs.length == 1".into(), "tx.inputs.length == 2".into(), Some("frais détournés vers un tiers")),
            (0, "require(blake2b(coffre) == coffreSpkHash);".into(), "".into(), Some("lignée du coffre sous le script d'un tiers : dépôt volé")),
            (0, "require(tx.outputs[0].value >= tx.inputs[0].value + tx.inputs[1].value - maxFrais);".into(), "".into(), Some("dépôt brûlé en frais")),
            (0, "require(checkSig(ownerSig, ownerKey));".into(), "".into(), Some("retour signé par l'agent")),
            (0, "require(blake2b(tx.outputs[i].scriptPubKey) == retourSpkHash);".into(), "".into(), Some("retour vers un tiers")),
            (0, "require(tx.outputs[i].value >= tx.inputs[i].value - maxFrais);".into(), "".into(), Some("retour : frais au-delà du plafond")),
            // Annoncée « non porteuse » dans la note du sas v0.1 : c'était inexact. Sans elle, la clé
            // du propriétaire peut envoyer une pièce du coffre ET un dépôt, fusionnés, à l'adresse de
            // retour, sans passer par `retour`. Même destination et même clé que `retour` : pas de
            // vol, mais la règle porte bien « un dépôt versé reste au coffre ».
            (0, "require(tx.outputs[0].scriptPubKey == coffre);".into(), "".into(), Some("gel du coffre avec le dépôt : dépôt fusionné vers l'adresse de retour, sans l'entrée retour")),
            (1, "require(tx.outputs[i].scriptPubKey == tx.inputs[i].scriptPubKey);".into(), "".into(), Some("pièce du coffre prise par absorb")),
            (1, ABSORB_VALEUR.into(), "".into(), Some("pièce du coffre brûlée par absorb")),
            (1, "tx.inputs[i].value + capacity);".into(), "tx.inputs[i].value);".into(), Some("regonflement nul (gêne gratuite)")),
            // ---- règles de lignée (v0.9)
            // Le sas ne regarde plus la lignée : le dépôt est versé dans la pièce de l'attaquant (S3).
            (0, "require(OpInputCovenantId(0) == lignee);".into(), "".into(), Some("S3 : poussière portant une fausse lignée")),
            // pay sans lignée : la poussière redevient du budget, et l'agent peut scinder le coffre.
            (1, PAY.into(), "".into(), Some("l'agent paie avec une poussière sans lignée")),
            (1, PAY.into(), "".into(), Some("scission par l'agent : bénéficiaire rattaché à la lignée")),
            (1, PAY.into(), "require(OpAuthOutputCount(this.activeInputIndex) == 1);".into(), Some("l'agent déplace la lignée sur le bénéficiaire")),
            // Non porteuse dans `pay` : avec exactement deux sorties, « la première héritière est la
            // sortie 1 » implique déjà « une seule héritière » (le réseau les range par indice).
            // Gardée : la règle se lit seule, sans dépendre du nombre de sorties (R63).
            (1, PAY.into(), "require(OpAuthOutputIdx(this.activeInputIndex, 0) == 1);".into(), None),
            // absorb sans lignée : n'importe qui ajoute une pièce à la lignée, ou regonfle la poussière.
            (1, absorb.clone(), ABSORB_VALEUR.into(), Some("scission sans clé : seconde pièce de la lignée au coffre")),
            (1, absorb.clone(), ABSORB_VALEUR.into(), Some("poussière sans lignée regonflée sans clé")),
            (1, absorb.clone(), format!("{ABSORB_VALEUR}require(OpAuthOutputCount(i) == 1);"), Some("regonflement sans clé : la lignée part sur une autre sortie")),
            (1, absorb.clone(), format!("{ABSORB_VALEUR}require(OpAuthOutputIdx(i, 0) == i);"), Some("scission sans clé : pièce de la lignée vers un tiers")),
            // ownerControl sans lignée : une clé de propriétaire volée multiplie les pièces du coffre.
            (1, ctrl.clone(), CTRL_VALEUR.into(), Some("clé du propriétaire : seconde pièce dans la lignée")),
            (1, ctrl.clone(), format!("{CTRL_VALEUR}require(OpAuthOutputCount(i) == 1);"), Some("clé du propriétaire : la lignée part sur une autre sortie")),
            (1, ctrl.clone(), format!("{CTRL_VALEUR}require(OpAuthOutputIdx(i, 0) == i);"), Some("clé du propriétaire : pièce de la lignée vers un tiers")),
            (1, "require(OpAuthOutputCount(i) == 0);".into(), "".into(), Some("gel : une héritière de la lignée reste au coffre")),
            (1, "require(OpAuthOutputCount(i) == 0);".into(), "".into(), Some("gel : la lignée suit la pièce à l'adresse de retour")),
        ];
        for (lequel, texte, remplacement, attendue) in &sabotages {
            let source = if *lequel == 0 { sas } else { coeur };
            assert_eq!(source.matches(texte.as_str()).count(), 1, "règle introuvable ou ambiguë dans le source : {texte}");
            let sabote = source.replace(texte.as_str(), remplacement);
            let b = if *lequel == 0 { banc(coeur, &sabote) } else { banc(&sabote, sas) };
            for (nom, essai) in legitimes(&b) {
                assert!(acceptee(&essai), "le sabotage « {texte} » casse une transaction légitime : {nom}");
            }
            let passees: Vec<&str> = attaques(&b).into_iter().filter(|(_, e)| acceptee(e)).map(|(n, _)| n).collect();
            match attendue {
                Some(nom) => assert!(passees.contains(nom), "sabotage non détecté : sans « {texte} », l'attaque « {nom} » devrait passer (passées : {passees:?})"),
                None => assert!(passees.is_empty(), "règle annoncée non porteuse, mais {passees:?} passe sans « {texte} »"),
            }
        }
        eprintln!("{} sabotages, tous détectés", sabotages.len());
    }

    /// S3, avant et après. La MÊME attaque (un dépôt versé dans la pièce de poussière de
    /// l'attaquant) passe sur le cœur v0.8 et son sas v0.1, et ne passe plus sur le cœur v0.9 et
    /// son sas v0.2, quelle que soit la façon de présenter la poussière.
    #[test]
    fn s3_ouvert_en_v08_ferme_en_v09() {
        // Avant : cœur v0.8 + sas v0.1 (archives).
        let c = coeur_avec(2, C as i64);
        let v08 = c.artifact_v08().unwrap();
        let sas01 = crate::sas::Sas::pour(&c, crate::sas::FRAIS_MAX_DEFAUT).unwrap().artifact().unwrap();
        let avant = monter(&[sc(&v08, P, "absorb"), sc(&sas01, D, "recharger")], &[o(P + D - FR, &vault_spk(&v08))], 0);
        assert!(acceptee(&avant), "témoin : en v0.8, le dépôt se verse dans la poussière de l'attaquant");
        // Après : toutes les présentations de la poussière sont refusées.
        let b = vrai();
        let s3: Vec<(&str, Essai)> = attaques(&b).into_iter().filter(|a| a.0.starts_with("S3")).collect();
        assert_eq!(s3.len(), 7);
        for (nom, essai) in &s3 {
            assert!(!acceptee(essai), "S3 rouvert : {nom}");
        }
        // Et le dépôt reste disponible pour la vraie pièce du coffre.
        let m = vault_spk(&b.coffre);
        assert!(acceptee(&monter(&[sc(&b.coffre, V, "absorb").dans(x_id()), sc(&b.sas, D, "recharger")], &[l(V + D - FR, &m)], 0)));
    }

    /// LIMITE ASSUMÉE (spec/red-team/lignee-2026-11-27.md, L1). Le script ne contient pas
    /// l'identifiant de sa lignée (il ne peut pas : l'identifiant dépend du script). Un tiers peut
    /// donc faire SA PROPRE genèse à la même adresse, avec SON argent : c'est un autre coffre, aux
    /// mêmes règles, que l'agent peut dépenser au rythme permis. Ce n'est pas l'argent du
    /// propriétaire : aucun dépôt du sas ne peut y entrer, aucune pièce de la lignée du coffre ne
    /// peut y passer. Le propriétaire peut le rapatrier (c'est un don).
    #[test]
    fn autre_lignee_a_la_meme_adresse_argent_du_tiers_seulement() {
        let b = vrai();
        let (m, x, rt) = (vault_spk(&b.coffre), p2pk(10), p2pk(11));
        let chez_lui = sg(&b.coffre, V, "pay", 2).dans(y_id());
        assert!(acceptee(&monter(&[chez_lui], &[o(C - FR, &x), la(V - C, &m, y_id(), 0)], R)), "l'agent dépense l'argent du tiers, au rythme du contrat");
        // Aucune passerelle entre les deux lignées.
        let passerelles = [
            ("dépôt du sas vers l'autre lignée", monter(&[sc(&b.coffre, V, "absorb").dans(y_id()), sc(&b.sas, D, "recharger")], &[la(V + D - FR, &m, y_id(), 0)], 0)),
            ("pièce du coffre rebaptisée dans l'autre lignée (agent)", monter(&[sg(&b.coffre, V, "pay", 2).dans(x_id())], &[o(C - FR, &x), la(V - C, &m, y_id(), 0)], R)),
            ("pièce du coffre rebaptisée dans l'autre lignée (sans clé)", monter(&[sc(&b.coffre, V, "absorb").dans(x_id()), tiers(10, 2 * C)], &[la(V + C, &m, y_id(), 0), o(C - FR, &x)], 0)),
            ("pièce de l'autre lignée rebaptisée dans celle du coffre", monter(&[sc(&b.coffre, V, "absorb").dans(y_id()), tiers(10, 2 * C)], &[l(V + C, &m), o(C - FR, &x)], 0)),
            (
                "fusion des deux lignées",
                monter(&[sc(&b.coffre, V, "absorb").dans(x_id()), sc(&b.coffre, V, "absorb").dans(y_id()), tiers(10, 3 * C)], &[l(2 * V + C, &m), la(C, &m, y_id(), 1), o(C - FR, &x)], 0),
            ),
        ];
        for (nom, essai) in &passerelles {
            assert!(!acceptee(essai), "passerelle entre lignées : {nom}");
        }
        assert!(acceptee(&monter(&[sg(&b.coffre, V, "ownerControl", 1).dans(y_id())], &[o(V - FR, &rt)], 0)), "le propriétaire rapatrie le don");
    }

    /// Ce que le RÉSEAU garantit (KIP-20), vérifié contre `CovenantsContext::from_tx`, la fonction
    /// que le nœud appelle avant d'exécuter les scripts : une sortie ne porte une lignée existante
    /// que si l'entrée qui l'autorise la porte déjà ; sinon c'est une genèse, et l'identifiant doit
    /// être celui que le réseau recalcule (il dépend de la pièce dépensée : unique, non choisi).
    #[test]
    fn le_reseau_refuse_une_lignee_usurpee() {
        let b = vrai();
        let m = vault_spk(&b.coffre);
        let valide = |essai: &Essai| CovenantsContext::from_tx(&PopulatedTransaction::new(&essai.0, essai.1.clone())).is_ok();
        // Usurpations : la lignée du coffre déclarée sans entrée qui la porte.
        assert!(!valide(&monter(&[tiers(10, V)], &[l(V - FR, &m)], 0)), "pièce ordinaire -> lignée du coffre");
        assert!(!valide(&monter(&[tiers(10, V).dans(y_id())], &[l(V - FR, &m)], 0)), "autre lignée -> lignée du coffre");
        assert!(!valide(&monter(&[sc(&b.coffre, V, "absorb").dans(x_id()), tiers(10, V)], &[la(V, &m, x_id(), 1)], 0)), "autorisée par une entrée qui ne la porte pas");
        assert!(!valide(&monter(&[tiers(10, V)], &[la(V - FR, &m, x_id(), 5)], 0)), "autorisée par une entrée qui n'existe pas");
        // Continuation : l'entrée porte la lignée. C'est AU SCRIPT de cette entrée de dire combien
        // d'héritières elle accepte (le réseau n'en limite pas le nombre) : d'où la règle du cœur.
        assert!(valide(&monter(&[sc(&b.coffre, V, "absorb").dans(x_id())], &[l(V / 2, &m), l(V / 2 - FR, &m)], 0)), "le réseau, seul, laisserait scinder");
        // Genèse : identifiant recalculé par le réseau ; un sompi ou un indice de différence le change.
        let bonne = genese(0, V - FR, &m, 0);
        assert!(valide(&monter(&[tiers(10, V)], std::slice::from_ref(&bonne), 0)));
        let (id, _) = bonne.2.unwrap();
        assert!(!valide(&monter(&[tiers(10, V)], &[la(V - FR - 1, &m, id, 0)], 0)), "même identifiant, autre valeur");
        assert!(!valide(&monter(&[tiers(10, V)], &[o(1, &m), la(V - FR - 1, &m, id, 0)], 0)), "même identifiant, autre sortie");
        assert!(!valide(&monter(&[tiers(10, V), tiers(10, V)], &[la(V - FR, &m, id, 1)], 0)), "même identifiant, autre pièce dépensée");
        assert_ne!(id, x_id());
    }

    /// Les transactions construites par l'outil : acceptées, dans les budgets de calcul déclarés,
    /// sous la masse standard, frais suffisants. Création du coffre (genèse), paiement, rechargement
    /// sans clé, gel, retour. Tailles des deux scripts.
    #[test]
    fn transactions_de_l_outil() {
        let c = coeur_avec(2, C as i64);
        let (art_c, m, rt) = (c.artifact_v09().unwrap(), vault_spk(&c.artifact_v09().unwrap()), p2pk(11));
        let op = |i: u32| TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), i);
        // Genèse : trois pièces, une lignée, la monnaie du propriétaire hors lignée.
        let fonds = [(op(0), UtxoEntry::new(4 * V, p2pk(1), 500, false, None))];
        let (genese, lignee) = build_genese(&c, &fonds, &[V, V, V], Some((V - FEE, p2pk(1))), &k(1)).unwrap();
        let entries: Vec<UtxoEntry> = fonds.iter().map(|f| f.1.clone()).collect();
        assert!(acceptee_a(&genese, &entries, 1_000), "genèse acceptée");
        assert_eq!(genese.outputs.iter().filter(|o| o.covenant.map(|b| b.covenant_id) == Some(lignee)).count(), 3);
        assert!(genese.outputs[..3].iter().all(|o| o.script_public_key == m) && genese.outputs[3].covenant.is_none());
        let mg = crate::masse::masses(&genese, &entries).unwrap();
        assert!(mg.standard() && crate::garde_diffusion(&genese).is_ok());
        assert!(build_genese(&c, &fonds, &[], None, &k(1)).is_err() && build_genese(&c, &fonds, &[V; 5], None, &k(1)).is_err(), "1 à 4 pièces");
        assert!(build_genese(&c, &fonds, &[5 * V], None, &k(1)).is_err(), "fonds insuffisants");

        // Le sas de ce coffre : son adresse dépend de la lignée, donc de la genèse.
        let sas = Sas::pour(&c, lignee, FRAIS_MAX_DEFAUT).unwrap();
        let art_s = sas.artifact().unwrap();
        assert_ne!(vault_spk(&art_s), vault_spk(&Sas::pour(&c, y_id(), FRAIS_MAX_DEFAUT).unwrap().artifact().unwrap()), "une lignée, un sas");
        assert!(Sas::pour(&c, Hash::from_bytes([0; 32]), FRAIS_MAX_DEFAUT).is_err(), "lignée nulle refusée");
        assert!(Sas::pour(&c, lignee, -1).is_err() && Sas::pour(&c, lignee, C as i64 + 1).is_err(), "plafond de frais absurde refusé");
        assert!(Sas::pour(&Coeur { retour: None, ..c.clone() }, lignee, 0).is_err(), "pas de sas pour un coffre v0.6");

        // Paiement de l'agent : le reste reste dans la lignée.
        let piece = UtxoEntry::new(V, m.clone(), 1_000, false, Some(lignee));
        let pay = build_pay(&c, (op(1), V), lignee, p2pk(10), C - FEE, FEE, &k(2), None).unwrap();
        let u_pay = script_entree(&pay, std::slice::from_ref(&piece), 0).expect("paiement accepté");
        assert!(u_pay <= CB_PAY as u64, "budget du paiement : {u_pay}");
        assert!(!acceptee_a(&pay, std::slice::from_ref(&piece), 1_000 + R - 1) && acceptee_a(&pay, std::slice::from_ref(&piece), 1_000 + R), "verrou relatif");
        assert_eq!(pay.outputs[1].covenant.map(|b| (b.covenant_id, b.authorizing_input)), Some((lignee, 0)));
        let mp = crate::masse::masses(&pay, std::slice::from_ref(&piece)).unwrap();
        assert!(mp.standard() && mp.compute * 100 <= FEE && crate::garde_diffusion(&pay).is_ok(), "masse du paiement {} / {} / {}", mp.compute, mp.transient, mp.storage);
        assert!(build_pay(&c, (op(1), V), lignee, p2pk(10), C, 1, &k(2), None).is_err(), "au-delà de la capacité");
        // Masse de stockage (KIP-9) : une pièce à lignée pèse deux unités (identifiant de 32 octets).
        // Le plus petit paiement possible et le plancher d'une pièce sont ceux de `masse.rs`, qui
        // compte déjà deux unités pour le coffre ; on le vérifie sur la transaction réelle.
        let petit = crate::masse::min_payment(V, FEE).unwrap();
        let masse_de = |montant: u64| {
            let tx = build_pay(&c, (op(1), V), lignee, p2pk(10), montant, FEE, &k(2), None).unwrap();
            crate::masse::masses(&tx, std::slice::from_ref(&piece)).unwrap()
        };
        assert!(masse_de(petit).standard() && !masse_de(petit - 1).standard(), "plus petit paiement : {petit}");
        let plancher = crate::masse::survival_floor(FEE);
        eprintln!("plus petit paiement depuis une pièce de 3 KAS : {petit} sompi ; plancher d'une pièce à lignée : {plancher} sompi (v0.7 : {})", crate::coeur_plancher());

        // Rechargement sans clé.
        let tx = build_recharger(&c, &sas, (op(1), V), (op(2), D), FRAIS_RECHARGE).unwrap();
        let entries = vec![piece.clone(), UtxoEntry::new(D, vault_spk(&art_s), 2_000, false, None)];
        let (u0, u1) = (script_entree(&tx, &entries, 0).expect("absorb accepté"), script_entree(&tx, &entries, 1).expect("recharger accepté"));
        assert!(u0 <= CB_ABSORB as u64 && u1 <= CB_RECHARGER as u64, "budgets de calcul : absorb {u0}, recharger {u1}");
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!((tx.outputs[0].value, &tx.outputs[0].script_public_key), (V + D - FRAIS_RECHARGE, &m));
        assert_eq!(tx.outputs[0].covenant.map(|b| (b.covenant_id, b.authorizing_input)), Some((lignee, 0)));
        assert!(tx.inputs.iter().all(|i| i.sequence == 0 && i.signature_script.len() < 600), "aucune attente, aucune signature");
        let mr = crate::masse::masses(&tx, &entries).unwrap();
        assert!(mr.standard() && mr.compute * 100 <= FRAIS_RECHARGE, "masse {} / {} / {}", mr.compute, mr.transient, mr.storage);
        assert!(crate::garde_diffusion(&tx).is_ok());
        // L'outil refuse ce que le réseau refuserait.
        assert!(build_recharger(&c, &sas, (op(1), V), (op(2), Sas::depot_minimal(&c, FRAIS_RECHARGE) - 1), FRAIS_RECHARGE).is_err(), "dépôt trop petit");
        assert!(build_recharger(&c, &sas, (op(1), V), (op(2), D), F + 1).is_err(), "frais au-delà du plafond");
        assert!(build_recharger(&c, &sas, (op(1), V), (op(2), Sas::depot_minimal(&c, FRAIS_RECHARGE)), FRAIS_RECHARGE).is_ok());
        // Le même versement présenté à une pièce hors lignée (poussière) : refusé par les deux scripts.
        let poussiere = vec![UtxoEntry::new(V, m.clone(), 1_000, false, None), entries[1].clone()];
        assert!(script_entree(&tx, &poussiere, 0).is_none() && script_entree(&tx, &poussiere, 1).is_none(), "versement dans une pièce hors lignée");

        // Gel : une pièce de la lignée et une poussière d'un tiers, chacune vers sa sortie, hors lignée.
        let gel = build_gel(&c, &[(op(1), V, Some(lignee)), (op(3), P, None)], &rt, FEE, &k(1)).unwrap();
        let eg = vec![piece.clone(), UtxoEntry::new(P, m.clone(), 3_000, false, None)];
        for i in 0..2 {
            let u = script_entree(&gel, &eg, i).expect("gel accepté");
            assert!(u <= CB_OWNER as u64, "budget du gel : {u}");
        }
        assert!(gel.outputs.iter().all(|o| o.covenant.is_none() && o.script_public_key == rt));
        assert!(crate::masse::masses(&gel, &eg).unwrap().standard());
        assert!(build_gel(&c, &[(op(1), V, Some(lignee))], &p2pk(10), FEE, &k(1)).is_err(), "l'outil refuse une autre adresse");
        let vole = build_gel(&c, &[(op(1), V, Some(lignee))], &rt, FEE, &k(2)).unwrap();
        assert!(script_entree(&vole, std::slice::from_ref(&piece), 0).is_none(), "gel signé par l'agent refusé");

        // Retour d'un dépôt par le propriétaire.
        let tx = build_retour(&sas, &[(op(2), D), (op(4), 2 * D)], &rt, FRAIS_RECHARGE, &k(1)).unwrap();
        let er = vec![UtxoEntry::new(D, vault_spk(&art_s), 0, false, None), UtxoEntry::new(2 * D, vault_spk(&art_s), 0, false, None)];
        for i in 0..2 {
            let u = script_entree(&tx, &er, i).expect("retour accepté");
            assert!(u <= CB_RETOUR as u64, "budget du retour : {u}");
        }
        assert!(crate::masse::masses(&tx, &er).unwrap().standard());
        assert!(build_retour(&sas, &[(op(2), D)], &p2pk(10), FRAIS_RECHARGE, &k(1)).is_err(), "l'outil refuse une autre adresse");

        eprintln!(
            "cœur v0.9 : {} octets (v0.8 : {}, v0.7 : {}) ; sas v0.2 : {} octets ; pay = {u_pay} unité(s), absorb = {u0}, recharger = {u1}",
            crate::bytecode(&art_c).len(),
            crate::bytecode(&c.artifact_v08().unwrap()).len(),
            crate::bytecode(&c.artifact().unwrap()).len(),
            crate::bytecode(&art_s).len(),
        );
        eprintln!(
            "masses (calcul / stockage) : genèse {} / {} g ; paiement {} / {} g ; rechargement {} / {} g",
            mg.compute, mg.storage, mp.compute, mp.storage, mr.compute, mr.storage
        );
    }

    /// Les versions précédentes ne changent pas : sources archivés à l'identique, bytecodes de
    /// référence inchangés, coffres v0.7 toujours gelables. Le cœur v0.9 a une autre adresse.
    #[test]
    fn versions_precedentes_archivees_a_l_identique() {
        let b2 = |d: &[u8]| hex::encode(blake2b_simd::Params::new().hash_length(32).hash(d).as_bytes());
        assert_eq!(b2(crate::coeur::SOURCE_V08.as_bytes()), "02c204bd016063b73da9d3b720cd168b35a95c9486913151422c7afa0e7434c5", "source v0.8 archivé à l'identique");
        assert_eq!(b2(crate::sas::SOURCE.as_bytes()), "0ce27f68a43a5c1928f204dadf8c6fc93aa7ff225ce0f2fd0ab20ff4e8c83520", "source du sas v0.1 archivé à l'identique");
        assert_eq!(b2(crate::coeur::SOURCE.as_bytes()), "817f910f77087108678e9541892bc208c5790927356a733a028ee94e50b7f894", "source v0.7 archivé à l'identique");
        let r = Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: crate::CAPACITY, periode: crate::JOUR_DAA, retour: Some(empreinte(&p2pk(1))) };
        assert_eq!(b2(&crate::bytecode(&r.artifact_v08().unwrap())), "849d197be4edcd6843463214fa900e15b2649637af33aca32439b95bbb4f3181", "bytecode v0.8 inchangé");
        assert_eq!(b2(&crate::bytecode(&r.artifact().unwrap())), "b85e0c9df3a116287344ce7f0a11bc275758f14de64b62642fda39238b8122be", "bytecode v0.7 inchangé");
        let b = vrai();
        assert_ne!(vault_spk(&b.coffre), vault_spk(&b.v08));
        assert_ne!(vault_spk(&b.coffre), vault_spk(&b.v07));
        assert!(acceptee(&monter(&[sg(&b.v07, V, "ownerControl", 1)], &[o(V - FR, &p2pk(11))], 0)), "gel d'un coffre v0.7");
    }

    /// Réglages aberrants : une capacité nulle ou négative ne doit pas ouvrir `absorb`, lignée ou non.
    #[test]
    fn absorb_refuse_avec_une_capacite_aberrante() {
        for cap in [0i64, -1, -(C as i64)] {
            let art = compiler_coeur(crate::coeur::SOURCE_V09, &coeur_avec(2, cap));
            let m = vault_spk(&art);
            for sortie in [V, V + 1, (V as i64 + cap) as u64, V + C] {
                let essai = monter(&[sc(&art, V, "absorb").dans(x_id()), tiers(10, 2 * C)], &[l(sortie, &m)], 0);
                assert!(!acceptee(&essai), "capacité {cap} : regonflement à {sortie} accepté");
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Fuzzing au niveau du COFFRE ENTIER : un petit registre de pièces tenu comme le réseau le tient.

    /// Une pièce du registre.
    #[derive(Clone)]
    struct Piece {
        op: TransactionOutpoint,
        e: UtxoEntry,
        /// Emplacement d'origine (0..k) pour une pièce de la lignée du coffre.
        emplacement: Option<usize>,
    }

    /// Le registre : toutes les pièces non dépensées, et l'heure. Une transaction n'y entre que si
    /// `acceptee_a` l'accepte (lignées KIP-20, scripts de toutes les entrées, verrous, montants) ;
    /// les pièces créées héritent de la lignée déclarée par leur sortie et du score courant, comme
    /// dans rusty-kaspa (utxo_diff.rs : `output.covenant.map(|x| x.covenant_id)`).
    struct Monde {
        pieces: Vec<Piece>,
        now: u64,
        n: u8,
        /// Lignée du coffre (née de la genèse) : sert à suivre les emplacements.
        lx: Option<Hash>,
    }
    impl Monde {
        /// Une pièce apparaît (dépôt d'un payeur, fonds d'un tiers) : hors de toute lignée.
        fn frapper(&mut self, valeur: u64, spk: ScriptPublicKey) -> TransactionOutpoint {
            self.n += 1;
            let op = TransactionOutpoint::new(TransactionId::from_bytes([self.n; 32]), 0xFFFF);
            self.pieces.push(Piece { op, e: UtxoEntry::new(valeur, spk, self.now, false, None), emplacement: None });
            op
        }
        fn piece(&self, op: &TransactionOutpoint) -> &Piece {
            self.pieces.iter().find(|p| p.op == *op).expect("pièce du registre")
        }
        /// Présente au réseau une transaction dépensant ces pièces. Acceptée : le registre est mis à jour.
        fn diffuser(&mut self, entrees: &[(In, TransactionOutpoint)], sorties: &[Out], seq: u64) -> bool {
            let sur: Vec<(In, TransactionOutpoint, u64)> = entrees.iter().map(|(e, op)| (e.clone(), *op, self.piece(op).e.block_daa_score)).collect();
            let (tx, entries) = monter_sur(&sur, sorties, seq);
            for ((_, op), e) in entrees.iter().zip(&entries) {
                let p = self.piece(op);
                assert!(p.e.amount == e.amount && p.e.script_public_key == e.script_public_key && p.e.covenant_id == e.covenant_id, "essai incohérent avec le registre");
            }
            if !acceptee_a(&tx, &entries, self.now) {
                return false;
            }
            // L'emplacement suit l'héritière (même lignée, autorisée par l'entrée qui la portait).
            let emplacements: Vec<Option<usize>> = entrees.iter().map(|(_, op)| self.piece(op).emplacement).collect();
            self.pieces.retain(|p| !entrees.iter().any(|(_, op)| *op == p.op));
            let id = tx.id();
            for (i, out) in tx.outputs.iter().enumerate() {
                let lignee = out.covenant.map(|b| b.covenant_id);
                let emplacement = out.covenant.filter(|b| self.lx == Some(b.covenant_id)).and_then(|b| emplacements[b.authorizing_input as usize]);
                self.pieces.push(Piece {
                    op: TransactionOutpoint::new(id, i as u32),
                    e: UtxoEntry::new(out.value, out.script_public_key.clone(), self.now, false, lignee),
                    emplacement,
                });
            }
            true
        }
        /// Pièces de la lignée du coffre, par emplacement croissant.
        fn lignee(&self) -> Vec<Piece> {
            let mut v: Vec<Piece> = self.pieces.iter().filter(|p| p.e.covenant_id.is_some() && p.e.covenant_id == self.lx).cloned().collect();
            v.sort_by_key(|p| p.emplacement);
            v
        }
        fn a(&self, spk: &ScriptPublicKey) -> Vec<Piece> {
            self.pieces.iter().filter(|p| p.e.script_public_key == *spk).cloned().collect()
        }
    }

    #[derive(Clone, Debug)]
    enum Geste {
        /// L'agent dépense ce pourcentage du maximum permis sur la pièce choisie de la lignée.
        Payer(usize, u64),
        /// L'agent tente un sompi de plus que le maximum permis.
        Tricher(usize),
        /// Un payeur dépose ce montant au sas.
        Deposer(u64),
        /// N'importe qui verse le plus ancien dépôt dans la pièce choisie de la lignée (sans clé).
        Verser(usize, bool),
        /// Un tiers regonfle la pièce de sa poche pour gêner l'agent.
        Gener(usize),
        /// L'attaquant crée une pièce de poussière à l'adresse du coffre : sans lignée (false) ou
        /// avec sa propre lignée (true, genèse valide).
        Poussiere(bool),
        /// L'attaquant tente de faire verser le plus ancien dépôt dans une pièce hors lignée (S3).
        DetournerDepot,
        /// L'agent tente de payer avec une pièce sans lignée de l'adresse du coffre.
        PayerPoussiere,
        /// L'agent (ou n'importe qui, ou une clé de propriétaire volée) tente d'ajouter une pièce à la lignée.
        Scinder(usize, u8),
        /// L'agent dépense l'argent du tiers dans la lignée du tiers (permis : ce n'est pas le coffre).
        PayerAutreLignee,
        /// Le propriétaire retire une pièce de la lignée vers l'adresse de retour.
        Retirer(usize),
    }
    fn geste() -> impl Strategy<Value = (u64, Geste)> {
        let g = prop_oneof![
            8 => (0usize..4, 1u64..=100).prop_map(|(i, p)| Geste::Payer(i, p)),
            2 => (0usize..4).prop_map(Geste::Tricher),
            3 => (C / 2..=20 * C).prop_map(Geste::Deposer),
            3 => (0usize..4, any::<bool>()).prop_map(|(i, f)| Geste::Verser(i, f)),
            1 => (0usize..4).prop_map(Geste::Gener),
            2 => any::<bool>().prop_map(Geste::Poussiere),
            2 => Just(Geste::DetournerDepot),
            1 => Just(Geste::PayerPoussiere),
            2 => (0usize..4, 0u8..5).prop_map(|(i, v)| Geste::Scinder(i, v)),
            1 => Just(Geste::PayerAutreLignee),
            1 => (0usize..4).prop_map(Geste::Retirer),
        ];
        (prop_oneof![0u64..50, 0u64..R / 4, 0u64..3 * R], g)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(cases(200)))]
        /// LE COFFRE ENTIER sous attaque. Un coffre de k pièces (1 à 4) créé par une vraie genèse,
        /// son sas, un agent avide ou tricheur, des payeurs, et un attaquant actif qui crée des
        /// pièces de poussière (avec ou sans fausse lignée), tente de détourner les dépôts, de
        /// scinder la lignée, de payer avec la poussière ; le propriétaire retire parfois une pièce.
        /// Chaque transaction passe par le vrai moteur, les règles de lignée du réseau et le verrou
        /// relatif. Vérifié à chaque pas :
        ///  - la lignée du coffre n'a jamais plus de pièces qu'à la création, toutes à son adresse,
        ///    une par emplacement ;
        ///  - sur TOUTE fenêtre (entre deux paiements quelconques), ce que l'agent a sorti du coffre
        ///    entier reste sous k × (C + C·D/R), et sous C + C·D/R par emplacement ;
        ///  - depuis la création : sous Σ min(C, C·âge/R) + k·C·t/R ;
        ///  - aucun dépôt n'entre dans une pièce hors lignée ; l'agent ne dépense jamais une pièce
        ///    sans lignée ; l'argent du propriétaire et des payeurs est expliqué au sompi.
        #[test]
        fn coffre_entier_sous_la_borne(pieces in 1usize..=4, age0 in prop_oneof![Just(0u64), 0u64..2 * R], gestes in proptest::collection::vec(geste(), 1..60)) {
            let c = coeur_avec(2, C as i64);
            let coffre = c.artifact_v09().unwrap();
            let (m, x, rt) = (vault_spk(&coffre), p2pk(10), p2pk(11));
            let debut = 10 * R;
            // Création : la genèse construite par l'outil, validée par le réseau, à `debut − age0`.
            let mut w = Monde { pieces: vec![], now: debut - age0, n: 0, lx: None };
            let fonds = w.frapper(pieces as u64 * V + FEE, p2pk(1));
            let (genese_tx, lx) = build_genese(&c, &[(fonds, w.piece(&fonds).e.clone())], &vec![V; pieces], None, &k(1)).unwrap();
            prop_assert!(acceptee_a(&genese_tx, &[w.piece(&fonds).e.clone()], w.now), "genèse refusée");
            w.pieces.clear();
            for (i, out) in genese_tx.outputs.iter().enumerate() {
                prop_assert_eq!(out.covenant.map(|b| b.covenant_id), Some(lx));
                w.pieces.push(Piece {
                    op: TransactionOutpoint::new(genese_tx.id(), i as u32),
                    e: UtxoEntry::new(out.value, out.script_public_key.clone(), w.now, false, Some(lx)),
                    emplacement: Some(i),
                });
            }
            w.lx = Some(lx);
            w.now = debut;
            let k0 = pieces;
            // Le sas de CE coffre : lié à la lignée née de la genèse.
            let sas_art = Sas::pour(&c, lx, FRAIS_MAX_DEFAUT).unwrap().artifact().unwrap();
            let s = vault_spk(&sas_art);
            let l = |valeur: u64, spk: &ScriptPublicKey| la(valeur, spk, lx, 0);
            // Comptes : argent du propriétaire et des payeurs d'un côté, argent de l'attaquant de l'autre.
            let (mut sorti, mut verse, mut dons, mut frais_sas, mut retire, mut frais_gel) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
            let mut paiements: Vec<(u64, usize, u64)> = vec![]; // (score, emplacement, dépense)
            let mut faits = [0u32; 6]; // paiements, versements, poussières, détournements tentés, scissions tentées, autre lignée
            for (dt, g) in gestes {
                w.now += dt;
                let lignee = w.lignee();
                let depots = w.a(&s);
                let hors: Vec<Piece> = w.a(&m).into_iter().filter(|p| p.e.covenant_id != Some(lx)).collect();
                match g {
                    Geste::Payer(i, pct) => {
                        let Some(p) = lignee.get(i % lignee.len().max(1)) else { continue };
                        let (valeur, age) = (p.e.amount, w.now - p.e.block_daa_score);
                        let spent = c.immediate(valeur, age) * pct / 100;
                        if spent <= FR {
                            continue;
                        }
                        let e = sg(&coffre, valeur, "pay", 2).dans(lx);
                        prop_assert!(w.diffuser(&[(e, p.op)], &[o(spent - FR, &x), l(valeur - spent, &m)], c.attente(spent as i64)), "paiement permis refusé : {spent} à l'âge {age}");
                        sorti += spent;
                        paiements.push((w.now, p.emplacement.unwrap(), spent));
                        faits[0] += 1;
                    }
                    Geste::Tricher(i) => {
                        let Some(p) = lignee.get(i % lignee.len().max(1)) else { continue };
                        let (valeur, age) = (p.e.amount, w.now - p.e.block_daa_score);
                        let spent = c.immediate(u64::MAX, age) + 1;
                        if spent > valeur || spent <= FR {
                            continue;
                        }
                        for seq in [c.attente(spent.min(C) as i64), age, 0] {
                            let e = sg(&coffre, valeur, "pay", 2).dans(lx);
                            prop_assert!(!w.diffuser(&[(e, p.op)], &[o(spent - FR, &x), l(valeur - spent, &m)], seq), "dépense {spent} au-delà du rythme acceptée à l'âge {age}");
                        }
                    }
                    Geste::Deposer(d) => {
                        w.frapper(d, s.clone());
                    }
                    Geste::Verser(i, cher) => {
                        let (Some(p), Some(d)) = (lignee.get(i % lignee.len().max(1)), depots.first()) else { continue };
                        let frais = if cher { F } else { FR };
                        let (valeur, depot) = (p.e.amount, d.e.amount);
                        let ok = w.diffuser(&[(sc(&coffre, valeur, "absorb").dans(lx), p.op), (sc(&sas_art, depot, "recharger"), d.op)], &[l(valeur + depot - frais, &m)], 0);
                        prop_assert_eq!(ok, depot >= C + frais, "versement sans clé : dépôt {}, frais {}", depot, frais);
                        if ok {
                            verse += depot;
                            frais_sas += frais;
                            faits[1] += 1;
                        }
                    }
                    Geste::Gener(i) => {
                        let Some(p) = lignee.get(i % lignee.len().max(1)) else { continue };
                        let valeur = p.e.amount;
                        let don = w.frapper(2 * C, x.clone());
                        prop_assert!(w.diffuser(&[(sc(&coffre, valeur, "absorb").dans(lx), p.op), (tiers(10, 2 * C), don)], &[l(valeur + C, &m), o(C - FR, &x)], 0));
                        dons += C;
                    }
                    Geste::Poussiere(fausse) => {
                        if fausse {
                            // Une vraie genèse de l'attaquant, à l'adresse du coffre, avec son argent.
                            let op = w.frapper(P + FR, x.clone());
                            let out = TransactionOutput::new(P, m.clone());
                            let y = covenant_id(op, std::iter::once((0u32, &out)));
                            prop_assert!(w.diffuser(&[(tiers(10, P + FR), op)], &[la(P, &m, y, 0)], 0), "genèse de l'attaquant refusée");
                            prop_assert!(y != lx);
                        } else {
                            w.frapper(P, m.clone());
                        }
                        faits[2] += 1;
                    }
                    Geste::DetournerDepot => {
                        let (Some(p), Some(d)) = (hors.first(), depots.first()) else { continue };
                        let (valeur, depot, id) = (p.e.amount, d.e.amount, p.e.covenant_id);
                        let piece = In { lignee: id, ..sc(&coffre, valeur, "absorb") };
                        let total = valeur + depot - FR;
                        let mut formes = vec![vec![o(total, &m)], vec![l(total, &m)], vec![la(total, &m, lx, 1)]];
                        if let Some(y) = id {
                            formes.push(vec![la(total, &m, y, 0)]);
                        }
                        for forme in formes {
                            prop_assert!(!w.diffuser(&[(piece.clone(), p.op), (sc(&sas_art, depot, "recharger"), d.op)], &forme, 0), "S3 : dépôt versé dans une pièce hors lignée");
                        }
                        // Même cosigné par une clé de propriétaire volée.
                        let vole = In { lignee: id, ..sg(&coffre, valeur, "ownerControl", 1) };
                        let mut formes = vec![o(total, &m), l(total, &m)];
                        if let Some(y) = id {
                            formes.push(la(total, &m, y, 0));
                        }
                        for forme in formes {
                            prop_assert!(!w.diffuser(&[(vole.clone(), p.op), (sc(&sas_art, depot, "recharger"), d.op)], &[forme], 0), "S3 avec la clé du propriétaire");
                        }
                        faits[3] += 1;
                    }
                    Geste::PayerPoussiere => {
                        let Some(p) = hors.iter().find(|p| p.e.covenant_id.is_none()) else { continue };
                        let valeur = p.e.amount;
                        let depense = (valeur / 2).min(C);
                        for reste in [o(valeur - depense, &m), l(valeur - depense, &m)] {
                            prop_assert!(!w.diffuser(&[(sg(&coffre, valeur, "pay", 2), p.op)], &[o(depense - FR, &x), reste], R), "poussière sans lignée dépensée par l'agent");
                        }
                    }
                    Geste::Scinder(i, variante) => {
                        let Some(p) = lignee.get(i % lignee.len().max(1)) else { continue };
                        let valeur = p.e.amount;
                        let don = w.frapper(3 * C, x.clone());
                        let (entree, sorties): (In, Vec<Out>) = match variante {
                            0 => (sc(&coffre, valeur, "absorb").dans(lx), vec![l(valeur + C, &m), l(C, &m), o(C - FR, &x)]),
                            1 => (sc(&coffre, valeur, "absorb").dans(lx), vec![l(valeur + C, &m), l(C, &x), o(C - FR, &x)]),
                            2 => (sg(&coffre, valeur, "ownerControl", 1).dans(lx), vec![l(valeur, &m), l(C, &m), o(2 * C - FR, &x)]),
                            3 => (sg(&coffre, valeur, "ownerControl", 1).dans(lx), vec![o(valeur - FR, &rt), l(C, &m), o(2 * C, &x)]),
                            _ => (sg(&coffre, valeur, "ownerControl", 1).dans(lx), vec![l(valeur - FR, &rt), o(3 * C, &x)]),
                        };
                        prop_assert!(!w.diffuser(&[(entree, p.op), (tiers(10, 3 * C), don)], &sorties, 0), "pièce ajoutée à la lignée (variante {variante})");
                        // L'agent, seul : le bénéficiaire rattaché à la lignée.
                        let age = w.now - p.e.block_daa_score;
                        let spent = c.immediate(valeur, age);
                        if spent > FR {
                            let e = sg(&coffre, valeur, "pay", 2).dans(lx);
                            prop_assert!(!w.diffuser(&[(e, p.op)], &[l(spent - FR, &x), l(valeur - spent, &m)], c.attente(spent as i64)), "scission par l'agent");
                        }
                        faits[4] += 1;
                    }
                    Geste::PayerAutreLignee => {
                        let Some(p) = hors.iter().find(|p| p.e.covenant_id.is_some()) else { continue };
                        let (valeur, age, y) = (p.e.amount, w.now - p.e.block_daa_score, p.e.covenant_id.unwrap());
                        let spent = c.immediate(valeur, age).min(valeur / 2);
                        if spent <= FR {
                            continue;
                        }
                        let e = sg(&coffre, valeur, "pay", 2).dans(y);
                        // Permis : c'est l'argent du tiers, dans SA lignée ; il n'entre pas dans les comptes du coffre.
                        prop_assert!(w.diffuser(&[(e, p.op)], &[o(spent - FR, &x), la(valeur - spent, &m, y, 0)], c.attente(spent as i64)));
                        faits[5] += 1;
                    }
                    Geste::Retirer(i) => {
                        if lignee.len() < 2 {
                            continue;
                        }
                        let p = &lignee[i % lignee.len()];
                        let valeur = p.e.amount;
                        prop_assert!(w.diffuser(&[(sg(&coffre, valeur, "ownerControl", 1).dans(lx), p.op)], &[o(valeur - FR, &rt)], 0));
                        retire += valeur - FR;
                        frais_gel += FR;
                    }
                }
                // ---- invariants du coffre entier
                let lignee = w.lignee();
                prop_assert!(lignee.len() <= k0, "la lignée a gagné une pièce : {} > {}", lignee.len(), k0);
                prop_assert!(lignee.iter().all(|p| p.e.script_public_key == m), "pièce de la lignée hors de l'adresse du coffre");
                let mut vus = std::collections::HashSet::new();
                prop_assert!(lignee.iter().all(|p| p.emplacement.is_some_and(|e| e < k0 && vus.insert(e))), "deux pièces pour un emplacement");
                prop_assert!(w.pieces.iter().all(|p| p.e.covenant_id != Some(lx) || p.e.script_public_key == m));
                // Argent du propriétaire et des payeurs : expliqué au sompi.
                let au_coffre: u64 = lignee.iter().map(|p| p.e.amount).sum();
                prop_assert_eq!(au_coffre + sorti + frais_sas + retire + frais_gel, k0 as u64 * V + verse + dons, "valeur inexpliquée");
                // Une pièce sans lignée à l'adresse du coffre ne bouge jamais sans le propriétaire.
                prop_assert!(w.a(&m).iter().filter(|p| p.e.covenant_id.is_none()).all(|p| p.e.amount == P), "une pièce sans lignée a bougé");
                // Borne depuis la création.
                let t = w.now - debut;
                prop_assert!(sorti <= k0 as u64 * c.fenetre(u64::MAX, age0, t), "borne depuis la création dépassée : {sorti}");
                // Toute fenêtre glissante [tᵢ, tⱼ], coffre entier et par emplacement.
                for i in 0..paiements.len() {
                    let mut par_emplacement = vec![0u64; k0];
                    let mut total = 0u64;
                    for j in i..paiements.len() {
                        let d = paiements[j].0 - paiements[i].0;
                        total += paiements[j].2;
                        par_emplacement[paiements[j].1] += paiements[j].2;
                        let borne = C + (C as u128 * d as u128 / R as u128) as u64;
                        prop_assert!(total <= k0 as u64 * borne, "fenêtre glissante dépassée (coffre entier) : {total} en {d}");
                        prop_assert!(par_emplacement.iter().all(|s| *s <= borne), "fenêtre glissante dépassée (un emplacement) en {d}");
                    }
                }
            }
            if std::env::var("PLAFOND_FUZZ_BILAN").is_ok() {
                eprintln!("bilan : {} paiements, {} versements, {} poussières, {} détournements tentés, {} scissions tentées, {} paiements dans une autre lignée", faits[0], faits[1], faits[2], faits[3], faits[4], faits[5]);
            }
        }
    }
}

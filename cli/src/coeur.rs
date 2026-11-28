//! Cœur v0.7 : budget d'agent sans mémoire (contracts/archive/coeur-v0.7.sil), avec adresse de retour.
//! Le cœur v0.9.2 (contracts/coeur.sil : rechargement sans clé, lignée KIP-20, retrait partiel,
//! sorties de retour sans lignée) est compilé par `Coeur::artifact_v092` et utilisé par src/lignee.rs.
//! Le cœur v0.9.1 (contracts/archive/coeur-v0.9.1.sil, retrait partiel en entrée séparée) reste
//! compilé par `Coeur::artifact_v091` pour la comparaison ; il n'a jamais été déployé.
//! Le cœur v0.9 (contracts/archive/coeur-v0.9.sil, sans retrait partiel) reste compilé par
//! `Coeur::artifact_v09` pour la comparaison « avant, après » ; il n'a jamais été déployé.
//! Le cœur v0.8 (contracts/archive/coeur-v0.8.sil, rechargement sans clé, sans lignée) reste
//! compilé par `Coeur::artifact_v08` pour son banc d'essai (src/sas.rs) ; il n'a jamais été déployé.
//! Les coffres v0.6 (contracts/archive/coeur-v0.6.sil, sans adresse de retour) restent gérés :
//! `Coeur::retour == None` compile l'ancien script, pour les retrouver et les geler.
//!
//! Règle unique : dépenser `spent` (paiement + frais) exige que la pièce ait au moins
//! ceil(spent × période / capacité) unités DAA d'âge, ce que le réseau vérifie lui-même
//! (verrou relatif). Pas d'état, pas d'horodatage fourni par l'agent, pas de lignée.
//! Preuve de la borne : spec/borne-de-perte-v0.6.md ; tests de comportement : tests/coeur_tests.rs.
#![allow(dead_code)] // à côté de la v0.5.1 tant que la comparaison n'est pas tranchée

use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use secp256k1::Keypair;
use silverscript_abi::{ArtifactValue, SilAbiArtifact};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

use crate::{Res, bytecode, sign, vault_sigscript, vault_spk};

/// Cœur v0.7 : celui que l'outil déploie aujourd'hui (coffres existants et nouveaux).
pub const SOURCE: &str = include_str!("../../contracts/archive/coeur-v0.7.sil");
/// Cœur v0.9.1 (contracts/coeur.sil) : v0.9 plus l'entrée `ownerWithdraw` (retrait partiel par le
/// propriétaire, frais au rythme du contrat). Utilisé par src/lignee.rs.
pub const SOURCE_V091: &str = include_str!("../../contracts/archive/coeur-v0.9.1.sil");
/// Cœur v0.9.2 (contracts/coeur.sil) : le retrait partiel est une branche de `ownerControl`, et
/// toute sortie vers l'adresse de retour est une pièce ordinaire, sans aucune lignée (W10 fermé).
pub const SOURCE_V092: &str = include_str!("../../contracts/coeur.sil");
/// Cœur v0.9, archivé à l'identique : v0.8 plus la lignée KIP-20 (le nombre de pièces du coffre ne
/// peut plus augmenter), sans retrait partiel. Jamais déployé.
pub const SOURCE_V09: &str = include_str!("../../contracts/archive/coeur-v0.9.sil");
/// Cœur v0.8, archivé à l'identique : v0.7 plus l'entrée `absorb`, sans lignée (limite S3). Jamais
/// déployé ; gardé avec son banc d'essai (src/sas.rs).
pub const SOURCE_V08: &str = include_str!("../../contracts/archive/coeur-v0.8.sil");
/// Cœur v0.6, sans adresse de retour : seulement pour les coffres déjà créés.
pub const SOURCE_V06: &str = include_str!("../../contracts/archive/coeur-v0.6.sil");
/// Le verrou relatif de Kaspa ne compte que 32 bits (SEQUENCE_LOCK_TIME_MASK).
pub const PERIODE_MAX: i64 = (1i64 << 32) - 1;
/// Budgets de calcul déclarés (marge incluse), mesurés par `budget_de_calcul_suffisant`.
pub const CB_PAY: u16 = 12;
/// `ownerControl` : une vérification de signature (≈ 10 unités) ; 5 était trop peu (essai testnet du
/// 24 nov. 2026 : « script units exceeded … used=100589, limit=59999 »).
pub const CB_OWNER: u16 = 12;

/// Paramètres d'un coffre. Le script refuse lui-même les valeurs dangereuses ; l'outil refuse en
/// plus les valeurs absurdes (capacité ou période nulles : coffre inutilisable).
#[derive(Clone, Debug)]
pub struct Coeur {
    pub owner: Vec<u8>,
    pub agent: Vec<u8>,
    pub capacite: i64,
    pub periode: i64,
    /// Empreinte blake2b (32 octets) du script de l'adresse de retour ; `None` : coffre v0.6.
    pub retour: Option<Vec<u8>>,
}

/// Paramètres publics d'un coffre, tels qu'un vendeur les reçoit (clés en hexadécimal) : tout ce
/// qu'il faut pour recompiler le script et retrouver son adresse.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Publics {
    pub owner: String,
    pub agent: String,
    pub capacite: i64,
    pub periode: i64,
    /// Empreinte de l'adresse de retour (hexadécimal) ; absente pour un coffre v0.6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retour: Option<String>,
}

impl Publics {
    pub fn coeur(&self) -> Res<Coeur> {
        let retour = self.retour.as_deref().map(hex::decode).transpose()?;
        let c = Coeur { owner: hex::decode(&self.owner)?, agent: hex::decode(&self.agent)?, capacite: self.capacite, periode: self.periode, retour };
        if c.owner.len() != 32 || c.agent.len() != 32 || c.retour.as_ref().is_some_and(|r| r.len() != 32) {
            return Err("clés ou adresse de retour du coffre invalides (32 octets attendus)".into());
        }
        c.verifier()?;
        Ok(c)
    }
}

impl Coeur {
    pub fn verifier(&self) -> Res<()> {
        if self.capacite <= 0 {
            return Err("capacité nulle ou négative : l'agent ne pourrait rien payer".into());
        }
        if self.periode <= 0 || self.periode > PERIODE_MAX {
            return Err(format!("période hors de 1..={PERIODE_MAX} (verrou relatif 32 bits)").into());
        }
        // Le script calcule (spent × period + capacity) − 1 en 64 bits signés, dans cet ordre, et le
        // moteur refuse tout dépassement intermédiaire : il faut C × R + C ≤ 2^63 − 1 pour qu'un
        // paiement à pleine capacité reste possible (R59). Plus strict que la garde du script
        // (C × R ≤ 2^63 − 1), donc sans danger.
        if self.capacite as i128 * (self.periode as i128 + 1) > i64::MAX as i128 {
            return Err("capacité × période déborde".into());
        }
        Ok(())
    }

    pub fn publics(&self) -> Publics {
        Publics {
            owner: hex::encode(&self.owner),
            agent: hex::encode(&self.agent),
            capacite: self.capacite,
            periode: self.periode,
            retour: self.retour.as_ref().map(hex::encode),
        }
    }

    pub fn artifact(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        self.artifact_sans_verification()
    }

    /// Pour les tests de paramètres aberrants : le script doit les refuser seul.
    pub fn artifact_sans_verification(&self) -> Res<SilAbiArtifact> {
        let mut args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into()];
        let source = match &self.retour {
            Some(r) => {
                args.push(r.clone().into());
                SOURCE
            }
            None => SOURCE_V06,
        };
        Ok(compile_to_sil_abi_artifact_with_options(source, &args, CompileOptions::default())?)
    }

    /// Le même coffre en cœur v0.8 (entrée `absorb` en plus) : autre script, donc autre adresse.
    /// Exige une adresse de retour (les mêmes cinq paramètres que la v0.7).
    pub fn artifact_v08(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        let retour = self.retour.clone().ok_or("le cœur v0.8 exige une adresse de retour")?;
        let args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into(), retour.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE_V08, &args, CompileOptions::default())?)
    }

    /// Le même coffre en cœur v0.9 (lignée KIP-20) : autre script, donc autre adresse. Mêmes cinq
    /// paramètres ; l'identifiant de la lignée n'est pas dans le script, il naît avec la genèse.
    pub fn artifact_v09(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        let retour = self.retour.clone().ok_or("le cœur v0.9 exige une adresse de retour")?;
        let args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into(), retour.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE_V09, &args, CompileOptions::default())?)
    }

    /// Le même coffre en cœur v0.9.1 (v0.9 plus le retrait partiel) : autre script, donc autre
    /// adresse. Mêmes cinq paramètres.
    pub fn artifact_v091(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        let retour = self.retour.clone().ok_or("le cœur v0.9.1 exige une adresse de retour")?;
        let args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into(), retour.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE_V091, &args, CompileOptions::default())?)
    }

    /// Le même coffre en cœur v0.9.2 : autre script, donc autre adresse. Mêmes cinq paramètres.
    pub fn artifact_v092(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        let retour = self.retour.clone().ok_or("le cœur v0.9.2 exige une adresse de retour")?;
        let args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into(), retour.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE_V092, &args, CompileOptions::default())?)
    }

    /// Âge exigé (unités DAA) pour dépenser `spent`, paiement et frais compris.
    pub fn attente(&self, spent: i64) -> u64 {
        ((spent as i128 * self.periode as i128 + self.capacite as i128 - 1) / self.capacite as i128) as u64
    }

    /// Dépense maximale possible maintenant pour une pièce de cet âge : min(valeur, capacité, C × âge / R).
    pub fn immediate(&self, valeur: u64, age: u64) -> u64 {
        let rythme = (self.capacite as i128 * age as i128 / self.periode as i128).min(self.capacite as i128);
        (rythme as u64).min(valeur)
    }

    /// Perte maximale sur les D prochaines unités pour une pièce de cet âge et toutes ses
    /// descendantes : min(valeur, min(C, C × âge / R) + C × D / R) (spec/borne-de-perte-v0.6.md).
    pub fn fenetre(&self, valeur: u64, age: u64, d: u64) -> u64 {
        let (c, r) = (self.capacite as i128, self.periode as i128);
        let depart = (c * r).min(c * age as i128);
        // Borner par la valeur AVANT de revenir à 64 bits : le quotient peut dépasser 2^64 (R59).
        ((depart + c * d as i128) / r).min(valeur as i128) as u64
    }
}

/// Paiement de l'agent : `montant` au bénéficiaire, le reste moins les frais revient au coffre.
/// La `sequence` vaut exactement le délai exigé : le réseau refuse tant que la pièce est trop jeune.
pub fn build_pay(
    c: &Coeur,
    art: &SilAbiArtifact,
    piece: TransactionOutpoint,
    valeur: u64,
    beneficiaire: ScriptPublicKey,
    montant: u64,
    frais: u64,
    agent: &Keypair,
    sequence: Option<u64>,
) -> Res<Transaction> {
    let spent = montant.checked_add(frais).filter(|s| *s <= valeur).ok_or("montant + frais au-delà de la pièce")?;
    if spent as i64 > c.capacite {
        return Err(format!("dépense {spent} au-delà de la capacité {}", c.capacite).into());
    }
    // `sequence` forcée : seulement pour démontrer le refus du réseau (paiement trop tôt).
    let input = TransactionInput::new_with_compute_budget(piece, vec![], sequence.unwrap_or_else(|| c.attente(spent as i64)), CB_PAY);
    let outputs = vec![
        TransactionOutput { value: montant, script_public_key: beneficiaire, covenant: None },
        TransactionOutput { value: valeur - spent, script_public_key: vault_spk(art), covenant: None },
    ];
    let mut tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
    let entree = UtxoEntry::new(valeur, vault_spk(art), 0, false, None);
    let s = sign(&tx, std::slice::from_ref(&entree), 0, agent);
    tx.inputs[0].signature_script = vault_sigscript(art, "pay", &[s.into()])?;
    Ok(tx)
}

pub fn octets(art: &SilAbiArtifact) -> usize {
    bytecode(art).len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::constants::{SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK};
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::{PopulatedTransaction, TransactionId, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_address_script};
    use proptest::prelude::*;

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }
    fn cases(n: u32) -> u32 {
        std::env::var("FUZZ_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(n)
    }
    fn coeur(c: i64, r: i64) -> Coeur {
        Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: c, periode: r, retour: Some(retour_hash()) }
    }
    /// Adresse de retour des tests : la clé 11 (distincte du propriétaire, de l'agent et du vendeur).
    fn retour_spk() -> ScriptPublicKey {
        pay_to_address_script(&crate::address(&k(11)))
    }
    fn retour_hash() -> Vec<u8> {
        crate::sequestre::spk_hash(&retour_spk()).to_vec()
    }
    fn externe() -> ScriptPublicKey {
        pay_to_address_script(&crate::address(&k(10)))
    }

    /// Script : le vrai moteur de Kaspa. Renvoie les unités de calcul consommées si accepté.
    fn script(tx: &Transaction, entree: &UtxoEntry) -> Option<u64> {
        let populated = PopulatedTransaction::new(tx, vec![entree.clone()]);
        let cov = CovenantsContext::from_tx(&populated).ok()?;
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
        if let Err(e) = vm.execute() {
            if std::env::var("PLAFOND_DEBUG_SCRIPT").is_ok() {
                eprintln!("script refusé : {e}");
            }
            return None;
        }
        Some(vm.used_script_units().0.div_ceil(kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT))
    }

    /// Consensus, copié de rusty-kaspa 2.1.0
    /// (consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs) :
    /// verrou relatif `block_daa_score + (sequence & MASK) − 1 < pov`, et sorties ≤ entrées.
    /// Le score inscrit sur une pièce créée est celui du bloc qui l'accepte (= son pov),
    /// vérifié dans pipeline/virtual_processor/utxo_validation.rs (add_transaction(tx, pov_daa_score)).
    fn consensus(tx: &Transaction, entree: &UtxoEntry, pov: u64) -> bool {
        let sorties: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
        let verrou_ok = tx.inputs.iter().all(|i| {
            i.sequence & SEQUENCE_LOCK_TIME_DISABLED == SEQUENCE_LOCK_TIME_DISABLED
                || (entree.block_daa_score as i64 + (i.sequence & SEQUENCE_LOCK_TIME_MASK) as i64 - 1) < pov as i64
        });
        verrou_ok && sorties <= entree.amount as u128
    }

    fn accepte(tx: &Transaction, entree: &UtxoEntry, pov: u64) -> bool {
        consensus(tx, entree, pov) && script(tx, entree).is_some()
    }

    /// Transaction de paiement avec une `sequence` choisie (éventuellement tricheuse) et une
    /// destination quelconque ; `dest_coffre` : la sortie 0 va vers ce script (coffre frère).
    fn tx_pay(art: &SilAbiArtifact, valeur: u64, dest: ScriptPublicKey, montant: u64, frais: u64, seq: u64) -> Transaction {
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], seq, CB_PAY);
        let reste = valeur.saturating_sub(montant + frais);
        let outputs = vec![
            TransactionOutput { value: montant, script_public_key: dest, covenant: None },
            TransactionOutput { value: reste, script_public_key: vault_spk(art), covenant: None },
        ];
        let mut tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
        let entree = UtxoEntry::new(valeur, vault_spk(art), 0, false, None);
        let s = sign(&tx, std::slice::from_ref(&entree), 0, &k(2));
        tx.inputs[0].signature_script = vault_sigscript(art, "pay", &[s.into()]).unwrap();
        tx
    }

    #[test]
    fn budget_de_calcul_suffisant_et_outil_conforme() {
        let c = coeur(200_000_000, 864_000);
        let art = c.artifact().unwrap();
        let valeur = 1_000_000_000;
        let tx = build_pay(&c, &art, TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), valeur, externe(), 50_000_000, 20_000, &k(2), None).unwrap();
        let entree = UtxoEntry::new(valeur, vault_spk(&art), 1_000, false, None);
        let unites = script(&tx, &entree).expect("paiement construit par l'outil accepté par le script");
        eprintln!("cœur v0.7 : {} octets, paiement = {unites} unités de calcul", octets(&art));
        assert!(unites <= CB_PAY as u64, "budget insuffisant : {unites} > {CB_PAY}");
        let attente = tx.inputs[0].sequence;
        assert!(!consensus(&tx, &entree, 1_000 + attente - 1), "trop tôt d'une unité : refusé par le réseau");
        assert!(consensus(&tx, &entree, 1_000 + attente), "âge exactement égal au délai : accepté");
        // L'outil refuse ce qui dépasse la capacité ou la pièce.
        let op = TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0);
        assert!(build_pay(&c, &art, op, valeur, externe(), 200_000_000, 1, &k(2), None).is_err());
        assert!(build_pay(&c, &art, op, 1_000, externe(), 999, 2, &k(2), None).is_err());
        // Paramètres absurdes refusés par l'outil.
        assert!(coeur(0, 864_000).artifact().is_err());
        assert!(coeur(1, 0).artifact().is_err());
        assert!(coeur(1, PERIODE_MAX + 1).artifact().is_err());
        assert!(coeur(i64::MAX, 2).artifact().is_err());
        assert!(coeur(1, PERIODE_MAX).artifact().is_ok());
    }

    /// Masse KIP-9 : sans identifiant de covenant, la continuation n'occupe plus qu'une unité de
    /// stockage (pluralité 1 au lieu de 2), soit 4 fois moins de poids dans C · p² / montant.
    fn stockage_v06(v: u64, a: u64, reste: u64) -> Option<u64> {
        use kaspa_consensus_core::mass::{UtxoCell, calc_storage_mass, utxo_plurality};
        let p = utxo_plurality(&vault_spk(&coeur(1, 1).artifact().unwrap()), false);
        assert_eq!(p, 1);
        calc_storage_mass(false, [UtxoCell::new(p, v)].into_iter(), [UtxoCell::new(1, a), UtxoCell::new(p, reste)].into_iter(), crate::masse::STORM)
    }
    fn plancher_v06(frais: u64) -> u64 {
        let ok = |v: u64| (1..=40).any(|i| {
            let a = v / 41 * i;
            a > 0 && a + frais < v && stockage_v06(v, a, v - a - frais).is_some_and(|m| m <= crate::masse::MAX_STANDARD_MASS)
        });
        let (mut lo, mut hi) = (frais + 2, 100 * 100_000_000u64);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if ok(mid) { hi = mid } else { lo = mid + 1 }
        }
        lo
    }

    #[test]
    fn masse_d_un_paiement_v06() {
        let c = coeur(200_000_000, 864_000);
        let art = c.artifact().unwrap();
        let v = 1_000_000_000u64;
        let frais = crate::FEE; // frais par défaut de l'outil
        let op = TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0);
        let tx = build_pay(&c, &art, op, v, externe(), 20_000_000, frais, &k(2), None).unwrap();
        let m = crate::masse::masses(&tx, &[UtxoEntry::new(v, vault_spk(&art), 0, false, None)]).unwrap();
        let (p06, p051) = (plancher_v06(crate::FEE), crate::masse::survival_floor(crate::FEE));
        eprintln!("v0.6 : calcul {} g, transitoire {} g, stockage {} g ; plancher d'un couloir {:.4} KAS (v0.5.1 : {:.4} KAS)",
            m.compute, m.transient, m.storage, p06 as f64 / 1e8, p051 as f64 / 1e8);
        assert!(m.standard());
        assert!(m.compute * 100 <= frais, "les frais couvrent la masse de calcul");
        assert!(p06 < p051, "le plancher baisse sans identifiant de covenant");
    }

    /// Le budget de calcul déclaré pour le gel couvre ce que coûte vraiment `ownerControl`.
    #[test]
    fn budget_de_calcul_du_gel_suffisant() {
        let c = coeur(200_000_000, 864_000);
        let art = c.artifact().unwrap();
        let v = 1_000_000_000u64;
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], 0, CB_OWNER);
        let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(v - 3_000_000, retour_spk())], 0, Default::default(), 0, vec![]);
        let entree = UtxoEntry::new(v, vault_spk(&art), 1_000, false, None);
        let s = sign(&tx, std::slice::from_ref(&entree), 0, &k(1));
        tx.inputs[0].signature_script = vault_sigscript(&art, "ownerControl", &[s.into()]).unwrap();
        let unites = script(&tx, &entree).expect("gel accepté par le script");
        eprintln!("gel (ownerControl) = {unites} unités de calcul");
        assert!(unites <= CB_OWNER as u64, "budget du gel insuffisant : {unites} > {CB_OWNER}");
    }

    /// Script de l'entrée `idx` d'une transaction à plusieurs entrées (vrai moteur de Kaspa).
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
        vm.execute().ok()?;
        Some(vm.used_script_units().0.div_ceil(kaspa_consensus_core::mass::units::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT))
    }

    /// Transaction `ownerControl` : `valeurs` = pièces du coffre (entrées 0..n), `sorties` libres,
    /// signée par `signataire` pour chaque entrée du coffre.
    fn tx_proprio(art: &SilAbiArtifact, valeurs: &[u64], sorties: Vec<TransactionOutput>, signataire: &Keypair) -> (Transaction, Vec<UtxoEntry>) {
        let inputs = (0..valeurs.len())
            .map(|i| TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([5; 32]), i as u32), vec![], 0, CB_OWNER))
            .collect();
        let entries: Vec<UtxoEntry> = valeurs.iter().map(|v| UtxoEntry::new(*v, vault_spk(art), 1_000, false, None)).collect();
        let mut tx = Transaction::new(1, inputs, sorties, 0, Default::default(), 0, vec![]);
        for i in 0..valeurs.len() {
            let s = sign(&tx, &entries, i, signataire);
            tx.inputs[i].signature_script = vault_sigscript(art, "ownerControl", &[s.into()]).unwrap();
        }
        (tx, entries)
    }

    fn toutes_acceptees(tx: &Transaction, entries: &[UtxoEntry]) -> bool {
        (0..entries.len()).all(|i| script_entree(tx, entries, i).is_some())
    }

    /// v0.7 : la clé du propriétaire est volée. Le voleur ne peut envoyer la pièce que vers le coffre
    /// ou vers l'adresse de retour, jamais chez lui ; ses frais sont bornés par la capacité.
    #[test]
    fn retour_cle_proprietaire_volee_ne_peut_rien_detourner() {
        let cap = 50_000_000u64;
        let c = coeur(cap as i64, 288_000);
        let art = c.artifact().unwrap();
        let v = 1_000_000_000u64;
        let out = |val: u64, spk: ScriptPublicKey| TransactionOutput::new(val, spk);
        // Vers l'adresse du voleur : refusé, quel que soit le montant.
        for val in [v - 1_000_000, v, 1] {
            let (tx, e) = tx_proprio(&art, &[v], vec![out(val, externe())], &k(1));
            assert!(!toutes_acceptees(&tx, &e), "détournement vers une adresse étrangère accepté ({val})");
        }
        // Vers l'adresse de retour : accepté, frais jusqu'à la capacité incluse.
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v - cap, retour_spk())], &k(1));
        let unites = script_entree(&tx, &e, 0).expect("gel vers l'adresse de retour accepté");
        assert!(unites <= CB_OWNER as u64, "budget du gel : {unites} > {CB_OWNER}");
        // Frais au-delà de la capacité : refusé (le voleur ne peut pas brûler la pièce en frais).
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v - cap - 1, retour_spk())], &k(1));
        assert!(!toutes_acceptees(&tx, &e), "frais au-delà de la capacité acceptés");
        // Rechargement : la pièce revient au coffre, au moins entière ; pas moins.
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v + 7, vault_spk(&art))], &k(1));
        assert!(toutes_acceptees(&tx, &e), "rechargement refusé");
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v - 1, vault_spk(&art))], &k(1));
        assert!(!toutes_acceptees(&tx, &e), "rechargement qui fait fondre la pièce accepté");
        // Sans sortie correspondante : refusé.
        let (tx, e) = tx_proprio(&art, &[v, v], vec![out(2 * v - 1_000, retour_spk())], &k(1));
        assert!(!toutes_acceptees(&tx, &e), "deux pièces sur une seule sortie acceptées");
        // Gel par lot : entrée i -> sortie i, toutes vers l'adresse de retour.
        let (tx, e) = tx_proprio(&art, &[v, 2 * v], vec![out(v - 1_000, retour_spk()), out(2 * v - 1_000, retour_spk())], &k(1));
        assert!(toutes_acceptees(&tx, &e), "gel par lot refusé");
        // Lot où la seconde pièce part ailleurs : refusé.
        let (tx, e) = tx_proprio(&art, &[v, v], vec![out(v - 1_000, retour_spk()), out(v - 1_000, externe())], &k(1));
        assert!(!toutes_acceptees(&tx, &e), "seconde pièce détournée acceptée");
        // Sorties supplémentaires libres (rendu du propriétaire lors d'un rechargement) : acceptées.
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v + 5, vault_spk(&art)), out(123_456, externe())], &k(1));
        assert!(toutes_acceptees(&tx, &e), "rendu du propriétaire refusé");
        // Signé par l'agent : refusé.
        let (tx, e) = tx_proprio(&art, &[v], vec![out(v - 1_000, retour_spk())], &k(2));
        assert!(!toutes_acceptees(&tx, &e), "ownerControl signé par l'agent accepté");
    }

    /// Les coffres v0.6 restent reconnus : sans adresse de retour, l'outil recompile EXACTEMENT
    /// l'ancien script (mêmes octets, donc même adresse) pour les retrouver et les geler.
    #[test]
    fn retour_coffres_v06_toujours_reconnus() {
        let c = Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: crate::CAPACITY, periode: crate::JOUR_DAA, retour: None };
        let code = crate::bytecode(&c.artifact().unwrap());
        let empreinte = hex::encode(blake2b_simd::Params::new().hash_length(32).hash(&code).as_bytes());
        assert_eq!(empreinte, "6057a023b315e2a2d609829d336b7ba76147af1115443adff4f377fde6c948f2", "bytecode v0.6 inchangé");
        // Et un coffre v0.6 se gèle toujours vers n'importe quelle adresse du propriétaire.
        let art = c.artifact().unwrap();
        let (tx, e) = tx_proprio(&art, &[1_000_000_000], vec![TransactionOutput::new(999_000_000, externe())], &k(1));
        assert!(toutes_acceptees(&tx, &e));
    }

    #[test]
    fn enchainement_dans_un_meme_bloc_impossible() {
        // Une pièce créée au score t ne se dépense pas au même score : il faut sequence ≥ 1,
        // donc t + 1 − 1 < pov, donc pov > t.
        let c = coeur(200_000_000, 864_000);
        let art = c.artifact().unwrap();
        let tx = tx_pay(&art, 1_000_000_000, externe(), 1, 0, 1);
        let entree = UtxoEntry::new(1_000_000_000, vault_spk(&art), 5_000, false, None);
        assert!(!accepte(&tx, &entree, 5_000));
        assert!(accepte(&tx, &entree, 5_001));
        let tx0 = tx_pay(&art, 1_000_000_000, externe(), 1, 0, 0);
        assert!(script(&tx0, &entree).is_none(), "sequence 0 refusée par le script");
    }

    /// Pré-positionnement entre coffres frères (R52) : un agent qui a deux coffres du même
    /// propriétaire peut transférer de l'un vers l'autre et multiplier les pièces. La borne reste
    /// vraie pour les pièces présentes au début de la fenêtre (c'est ce que compte le moteur de
    /// risque), mais le chiffre annoncé À LA CRÉATION d'un seul coffre ne vaut plus.
    #[test]
    fn coffres_freres_pre_positionnement() {
        let (cap, r) = (200_000_000i64, 864_000i64);
        let a = coeur(cap, r);
        let b = coeur(cap, r + 1); // autre coffre, même agent
        let (art_a, art_b) = (a.artifact().unwrap(), b.artifact().unwrap());
        // Dix jours : chaque jour, A transfère une capacité entière vers B.
        let mut pieces_b = 0;
        let mut t = 0u64;
        let mut valeur_a = 100 * cap as u64;
        for _ in 0..10 {
            t += r as u64;
            let tx = tx_pay(&art_a, valeur_a, vault_spk(&art_b), cap as u64 - 1_000, 1_000, a.attente(cap));
            let entree = UtxoEntry::new(valeur_a, vault_spk(&art_a), t - r as u64, false, None);
            assert!(accepte(&tx, &entree, t));
            valeur_a -= cap as u64;
            pieces_b += 1;
        }
        // Au jour 11, chacune des dix pièces de B peut dépenser une capacité immédiatement.
        t += r as u64;
        let immediate_b: u64 = (0..pieces_b).map(|i| b.immediate(cap as u64 - 1_000, t - (i + 1) * r as u64)).sum();
        assert!(immediate_b > 9 * cap as u64, "dix pièces prêtes : {immediate_b}");
        // Ce que le moteur de risque voit au jour 11 (pièces présentes) couvre bien cette rafale ;
        // ce qu'aurait annoncé la création de B seul (une capacité) ne la couvre pas.
        assert!(immediate_b > b.immediate(u64::MAX, u64::MAX));
    }

    /// R52 par blanchiment : l'agent du coffre A prend une capacité par jour vers sa propre adresse,
    /// puis la redépose en dix pièces dans le coffre frère B, attend, et vide B d'un coup.
    /// La rafale dépasse une fenêtre glissante de 24 h, mais la perte NETTE depuis la création
    /// reste sous la courbe annoncée à la création de A et de B.
    #[test]
    fn blanchiment_entre_freres_sous_la_courbe() {
        let (cap, r) = (200_000_000i64, 864_000u64);
        let (a, b) = (coeur(cap, r as i64), coeur(cap, r as i64 + 1));
        let (art_a, art_b) = (a.artifact().unwrap(), b.artifact().unwrap());
        let poche = pay_to_address_script(&crate::address(&k(66))); // adresse de l'agent
        let (va0, vb0) = (100 * cap as u64, 10 * cap as u64);
        let mut va = va0;
        let mut cree_a = 0u64;
        let (mut sorti, mut revenu) = (0u64, 0u64);
        let mut t = 0u64;
        for _ in 0..10 {
            t += r;
            let tx = tx_pay(&art_a, va, poche.clone(), cap as u64, 0, a.attente(cap));
            assert!(accepte(&tx, &UtxoEntry::new(va, vault_spk(&art_a), cree_a, false, None), t));
            va -= cap as u64;
            cree_a = t;
            sorti += cap as u64;
        }
        // L'agent rend tout dans B, en dix pièces.
        revenu += 10 * cap as u64;
        let depot = t;
        t += r + 1;
        for _ in 0..10 {
            let tx = tx_pay(&art_b, cap as u64, poche.clone(), cap as u64 - 1, 1, b.attente(cap - 1));
            assert!(accepte(&tx, &UtxoEntry::new(cap as u64, vault_spk(&art_b), depot, false, None), t), "rafale depuis B");
            sorti += cap as u64 - 1;
        }
        // Et la pièce d'origine de B, ancienne, donne aussi sa capacité.
        sorti += b.immediate(vb0, t) as u64;
        let net = sorti - revenu;
        let courbe = a.fenetre(va0, 0, t) + b.fenetre(vb0, t, t);
        let fenetre_24h = a.fenetre(va, t - cree_a, r) + b.fenetre(vb0, t, r);
        eprintln!("rafale en un instant {} ; perte nette {net} ≤ courbe {courbe} ; fenêtre glissante annoncée {fenetre_24h}", sorti - 10 * cap as u64);
        assert!(net <= courbe, "la courbe annoncée à la création tient");
        assert!(sorti - 10 * cap as u64 > fenetre_24h, "la fenêtre glissante, elle, est dépassée");
    }

    // ------------------------------------------------ fuzzing : moteur + consensus = modèle

    #[derive(Clone, Debug)]
    enum Seq {
        Honnete,
        MoinsUn,
        Zero,
        Desactivee,
        BitHautEtDelai,
        DeuxPuissance32,
        /// La plus forte : tout l'âge réel de la pièce, le maximum que le réseau accepte.
        ToutLAge,
        Hasard(u64),
    }

    fn seq() -> impl Strategy<Value = Seq> {
        prop_oneof![
            4 => Just(Seq::Honnete),
            1 => Just(Seq::MoinsUn),
            1 => Just(Seq::Zero),
            1 => Just(Seq::Desactivee),
            1 => Just(Seq::BitHautEtDelai),
            1 => Just(Seq::DeuxPuissance32),
            4 => Just(Seq::ToutLAge),
            1 => any::<u64>().prop_map(Seq::Hasard),
        ]
    }

    fn valeur_seq(s: &Seq, attente: u64, age: u64) -> u64 {
        match s {
            Seq::Honnete => attente,
            Seq::MoinsUn => attente.saturating_sub(1),
            Seq::Zero => 0,
            Seq::Desactivee => SEQUENCE_LOCK_TIME_DISABLED | attente,
            Seq::BitHautEtDelai => (1u64 << 40) | attente,
            Seq::DeuxPuissance32 => 1u64 << 32,
            Seq::ToutLAge => age.min(u32::MAX as u64),
            Seq::Hasard(v) => *v,
        }
    }

    /// Modèle de référence, en une ligne lisible : ce que la règle promet.
    /// La dépense réelle est ce qui quitte la pièce : valeur − continuation (tx_pay borne la
    /// continuation à 0 quand montant + frais dépasse la pièce).
    fn modele(c: &Coeur, valeur: u64, montant: u64, frais: u64, seq: u64, age: u64) -> bool {
        let reste = valeur.saturating_sub(montant + frais);
        let spent = (valeur - reste) as u128;
        let delai = seq & SEQUENCE_LOCK_TIME_MASK;
        montant <= valeur - reste
            && spent <= c.capacite as u128
            && seq & SEQUENCE_LOCK_TIME_DISABLED == 0
            && delai >= c.attente(spent as i64)
            && delai <= age
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(256), ..ProptestConfig::default() })]

        #[test]
        fn coeur_moteur_et_consensus_egal_modele(
            cap in 1i64..=2_000_000_000,
            r in prop_oneof![3 => 1i64..2_000_000, 1 => 1i64..=PERIODE_MAX],
            valeur in 1u64..10_000_000_000,
            part in 0.0f64..1.3,
            frais in 0u64..2_000_000,
            age_hasard in 0u64..20_000_000,
            pres_de_la_frontiere in prop::bool::weighted(0.7),
            ecart in -3i64..=3,
            s in seq(),
        ) {
            let c = coeur(cap, r);
            prop_assume!(c.verifier().is_ok());
            let art = c.artifact().unwrap();
            let montant = ((cap as f64 * part) as u64).max(1);
            let attente = c.attente((montant + frais) as i64);
            // Les erreurs se cachent à la frontière : l'âge est souvent pris à ±3 du délai exigé.
            let age = if pres_de_la_frontiere { (attente as i64 + ecart).max(0) as u64 } else { age_hasard };
            let sq = valeur_seq(&s, attente, age);
            let tx = tx_pay(&art, valeur, externe(), montant, frais, sq);
            let cree = 1_000u64;
            let entree = UtxoEntry::new(valeur, vault_spk(&art), cree, false, None);
            let attendu = modele(&c, valeur, montant, frais, sq, age);
            prop_assert_eq!(accepte(&tx, &entree, cree + age), attendu, "seq={:#x} attente={} age={}", sq, attente, age);
        }
    }

    // ------------------------------------------------ fuzzing : la borne de perte

    #[derive(Clone, Debug)]
    struct Piece {
        coffre: usize,
        valeur: u64,
        cree: u64,
    }

    #[derive(Clone, Debug)]
    enum Pas {
        /// L'agent dépense depuis la pièce n° i (modulo) ; `avidite` ∈ [0, 1.2] de ce qui est permis.
        Payer { i: usize, avidite: f64, frais: u64, vers_frere: bool, s: Seq },
        /// Dépôt d'une nouvelle pièce : par le propriétaire (`tiers` faux), ou par quelqu'un
        /// d'autre (`tiers` vrai), y compris l'agent qui « rend » de l'argent pris plus tôt pour
        /// le pré-positionner dans un coffre frère (blanchiment, R52).
        Deposer { coffre: usize, valeur: u64, tiers: bool },
        /// Le propriétaire gèle un coffre au milieu des attaques : toutes ses pièces reviennent
        /// (`ownerControl`, vérifié par le vrai moteur). Ce n'est pas une perte.
        Geler { coffre: usize },
    }

    /// Transaction de gel d'une pièce par le propriétaire (clé 1) ; le vrai moteur doit l'accepter.
    fn gel_accepte(art: &SilAbiArtifact, valeur: u64, cree: u64) -> bool {
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([4; 32]), 0), vec![], 0, CB_OWNER);
        // Gel v0.7 : la pièce part vers l'adresse de retour, 1 sompi de frais (≤ capacité).
        let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(valeur.saturating_sub(1).max(1), retour_spk())], 0, Default::default(), 0, vec![]);
        let entree = UtxoEntry::new(valeur, vault_spk(art), cree, false, None);
        let s = sign(&tx, std::slice::from_ref(&entree), 0, &k(1));
        tx.inputs[0].signature_script = vault_sigscript(art, "ownerControl", &[s.into()]).unwrap();
        script(&tx, &entree).is_some()
    }

    fn pas() -> impl Strategy<Value = (u64, Pas)> {
        let payer = (any::<usize>(), prop_oneof![3 => 0.0f64..1.2, 1 => 1.0f64..3.0], 0u64..500_000, any::<bool>(), seq())
            .prop_map(|(i, avidite, frais, vers_frere, s)| Pas::Payer { i, avidite, frais, vers_frere, s });
        let deposer = (0usize..2, 1u64..3_000_000_000, any::<bool>()).prop_map(|(coffre, valeur, tiers)| Pas::Deposer { coffre, valeur, tiers });
        // Écart de temps : 0 (même bloc), petit, ou grand.
        let dt = prop_oneof![1 => Just(0u64), 3 => 1u64..2_000, 3 => 1u64..2_000_000];
        let geler = (0usize..2).prop_map(|coffre| Pas::Geler { coffre });
        (dt, prop_oneof![12 => payer, 2 => deposer, 1 => geler])
    }

    /// Simule le système et vérifie, pour chaque instant a et chaque durée D, que la perte réelle
    /// (sorties vers l'extérieur + frais) sur [a, a + D] ne dépasse jamais ce que le moteur de
    /// risque annonce à l'instant a pour les pièces présentes, plus les dépôts faits pendant la fenêtre.
    fn simuler(coffres: &[Coeur], initial: &[(usize, u64, u64)], pas: &[(u64, Pas)]) -> Result<(), TestCaseError> {
        let arts: Vec<SilAbiArtifact> = coffres.iter().map(|c| c.artifact().unwrap()).collect();
        let mut pieces: Vec<Piece> = initial.iter().map(|&(coffre, valeur, cree)| Piece { coffre, valeur, cree }).collect();
        let mut t = initial.iter().map(|p| p.2).max().unwrap_or(0) + 1;
        let mut instantanes: Vec<(u64, Vec<Piece>)> = vec![];
        let mut pertes: Vec<(u64, u64)> = vec![];
        let mut depots: Vec<(u64, Piece)> = vec![];
        let mut apports: Vec<(u64, Piece)> = vec![]; // dépôts du propriétaire
        let mut retours: Vec<(u64, u64)> = vec![]; // dépôts de tiers (argent qui revient)
        let initiales = pieces.clone();
        let debut = t;
        let mut acceptes = 0;
        for (dt, p) in pas {
            t += dt;
            if instantanes.last().map(|x| x.0) != Some(t) {
                instantanes.push((t, pieces.clone()));
            }
            match p {
                Pas::Deposer { coffre, valeur, tiers } => {
                    let pc = Piece { coffre: *coffre % coffres.len(), valeur: *valeur, cree: t };
                    if *tiers {
                        retours.push((t, *valeur));
                    } else {
                        apports.push((t, pc.clone()));
                    }
                    depots.push((t, pc.clone()));
                    pieces.push(pc);
                }
                Pas::Geler { coffre } => {
                    let c = *coffre % coffres.len();
                    for p in pieces.iter().filter(|p| p.coffre == c) {
                        prop_assert!(gel_accepte(&arts[c], p.valeur, p.cree), "le gel du propriétaire doit toujours passer");
                    }
                    pieces.retain(|p| p.coffre != c);
                }
                Pas::Payer { i, avidite, frais, vers_frere, s } => {
                    if pieces.is_empty() {
                        continue;
                    }
                    let idx = i % pieces.len();
                    let pc = pieces[idx].clone();
                    let c = &coffres[pc.coffre];
                    if pc.cree > t {
                        continue;
                    }
                    let permis = c.immediate(pc.valeur, t - pc.cree);
                    let spent = ((permis as f64 * avidite) as u64).max(1).min(pc.valeur);
                    let frais = (*frais).min(spent - 1);
                    let montant = spent - frais;
                    let frere = (pc.coffre + 1) % coffres.len();
                    let dest = if *vers_frere && frere != pc.coffre { vault_spk(&arts[frere]) } else { externe() };
                    let sq = valeur_seq(s, c.attente(spent as i64), t - pc.cree);
                    let tx = tx_pay(&arts[pc.coffre], pc.valeur, dest.clone(), montant, frais, sq);
                    let entree = UtxoEntry::new(pc.valeur, vault_spk(&arts[pc.coffre]), pc.cree, false, None);
                    let ok = accepte(&tx, &entree, t);
                    prop_assert_eq!(ok, modele(c, pc.valeur, montant, frais, sq, t - pc.cree), "moteur ≠ modèle");
                    if ok {
                        acceptes += 1;
                        pieces.remove(idx);
                        pieces.push(Piece { coffre: pc.coffre, valeur: pc.valeur - spent, cree: t });
                        if dest == externe() {
                            pertes.push((t, spent));
                        } else {
                            pertes.push((t, frais));
                            pieces.push(Piece { coffre: frere, valeur: montant, cree: t });
                        }
                    }
                }
            }
        }
        let fin = t;
        let _ = acceptes;
        // La courbe annoncée à la création : à tout instant x, la perte NETTE du propriétaire
        // depuis la création (sorties moins argent revenu) reste sous
        //   Σ pièces initiales  min(V, min(C, C·âge/R) + C·(x − début)/R)
        // + Σ apports du propriétaire  min(V, C·(x − apport)/R).
        // Aucune hypothèse sur les coffres frères ni sur les dépôts de tiers.
        let mut moments: Vec<u64> = pertes.iter().map(|p| p.0).chain(retours.iter().map(|r| r.0)).chain([fin]).collect();
        moments.sort();
        for x in moments {
            let sorti: u64 = pertes.iter().filter(|(y, _)| *y <= x).map(|(_, v)| v).sum();
            let revenu: u64 = retours.iter().filter(|(y, _)| *y <= x).map(|(_, v)| v).sum();
            let courbe: u64 = initiales.iter().map(|p| coffres[p.coffre].fenetre(p.valeur, debut - p.cree, x - debut)).sum::<u64>()
                + apports.iter().filter(|(y, _)| *y <= x).map(|(y, p)| coffres[p.coffre].fenetre(p.valeur, 0, x - y)).sum::<u64>();
            prop_assert!(sorti as i128 - revenu as i128 <= courbe as i128,
                "courbe dépassée à {} : sorti {} − revenu {} > {}", x, sorti, revenu, courbe);
        }
        // Vérification de la borne sur toutes les fenêtres [a, a + D].
        for (a, presentes) in &instantanes {
            for d in [0u64, 1, 1_000, 86_400, 864_000, 3 * 864_000, fin - a] {
                let perte: u64 = pertes.iter().filter(|(x, _)| *x >= *a && *x <= a + d).map(|(_, v)| v).sum();
                let annonce: u64 = presentes.iter().map(|p| coffres[p.coffre].fenetre(p.valeur, a - p.cree, d)).sum::<u64>()
                    + depots.iter().filter(|(x, _)| *x >= *a && *x <= a + d)
                        .map(|(x, p)| coffres[p.coffre].fenetre(p.valeur, 0, a + d - x)).sum::<u64>();
                prop_assert!(perte <= annonce, "fenêtre [{}, +{}] : perte {} > annonce {}", a, d, perte, annonce);
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(128), ..ProptestConfig::default() })]

        /// Un seul coffre : la borne simple C + C × D / R pour la pièce déposée tient sur toute fenêtre.
        #[test]
        fn agent_avide_un_coffre_sous_la_borne(
            cap in 1_000i64..2_000_000_000,
            r in 1i64..3_000_000,
            valeur in 1u64..20_000_000_000,
            age0 in 0u64..5_000_000,
            pas in prop::collection::vec(pas(), 1..40),
        ) {
            let c = coeur(cap, r);
            prop_assume!(c.verifier().is_ok());
            let pas: Vec<_> = pas.into_iter().filter(|(_, p)| matches!(p, Pas::Payer { .. })).collect();
            simuler(std::slice::from_ref(&c), &[(0, valeur, 10_000_000 - age0.min(10_000_000))], &pas)?;
        }

        /// Deux coffres frères, transferts entre eux et dépôts : la borne du moteur de risque tient.
        #[test]
        fn agent_avide_coffres_freres_sous_l_annonce_du_moteur(
            cap in 1_000i64..2_000_000_000,
            r in 1i64..3_000_000,
            cap2 in 1_000i64..2_000_000_000,
            r2 in 1i64..3_000_000,
            v1 in 1u64..20_000_000_000,
            v2 in 1u64..20_000_000_000,
            pas in prop::collection::vec(pas(), 1..40),
        ) {
            let (c1, c2) = (coeur(cap, r), coeur(cap2, r2));
            prop_assume!(c1.verifier().is_ok() && c2.verifier().is_ok());
            simuler(&[c1, c2], &[(0, v1, 0), (1, v2, 500)], &pas)?;
        }
    }

    // ------------------------------------------------ Red Team 26 nov. 2026 : code = spécification
    // Preuves écrites : spec/red-team/rapport-2026-11-26.md, §3.

    /// Référence en grands entiers, écrite sans reprendre le code de l'outil.
    fn ref_immediate(c: i128, r: i128, v: i128, age: i128) -> i128 {
        v.min(c).min(c * age / r)
    }
    fn ref_fenetre(c: i128, r: i128, v: i128, age: i128, d: i128) -> i128 {
        // min(V, floor((min(C·R, C·âge) + C·D) / R)) : UNE seule division, voir le rapport §3.3.
        v.min(((c * r).min(c * age) + c * d) / r)
    }

    /// Paramètres aux bornes : capacité et période petites, ordinaires, ou collées aux limites
    /// (période = 2^32 − 1, C × R au ras de 2^63).
    fn params_aux_bornes() -> impl Strategy<Value = (i64, i64)> {
        prop_oneof![
            (1i64..=2_000_000_000, 1i64..2_000_000),
            (1i64..=1_000, 1i64..=1_000),
            (1i64..=2_000_000_000, PERIODE_MAX - 3..=PERIODE_MAX),
            // C × R tout près de la limite : C = (2^63 − 1) / R − écart.
            (1i64..=PERIODE_MAX, 0i64..3).prop_map(|(r, e)| ((i64::MAX / r - e).max(1), r)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(4_000), ..ProptestConfig::default() })]

        /// Équivalence (rapport §3.1) : pour tout coffre accepté par l'outil et toute dépense
        /// 0 ≤ s ≤ C, « ceil(s·R/C) ≤ âge » (ce que le script exige) ⇔ « s ≤ floor(C·âge/R) »
        /// (ce que l'outil et le moteur de risque annoncent). Aux bornes : s = 0, s = C, âge à ±2
        /// de la frontière, âge au-delà de 2^32.
        #[test]
        fn script_et_outil_disent_la_meme_chose(
            (cap, r) in params_aux_bornes(),
            part in 0.0f64..=1.0,
            coin in 0u8..6,
            ecart in -2i64..=2,
            age_hasard in prop_oneof![0u64..10_000_000, (1u64 << 32) - 2..(1u64 << 32) + 2, any::<u64>()],
        ) {
            let c = coeur(cap, r);
            prop_assume!(c.verifier().is_ok());
            let s = match coin { 0 => 0, 1 => cap, 2 => 1, 3 => cap - 1, _ => (cap as f64 * part) as i64 }.clamp(0, cap);
            let attente = c.attente(s);
            // Le délai calculé est exact (plafond de la division), et il tient dans le verrou 32 bits.
            let (ci, ri, si) = (cap as i128, r as i128, s as i128);
            prop_assert_eq!(attente as i128, (si * ri + ci - 1) / ci);
            prop_assert!((attente as i128) * ci >= si * ri && (attente as i128 - 1) * ci < si * ri || s == 0 && attente == 0);
            prop_assert!(attente <= r as u64 && attente <= SEQUENCE_LOCK_TIME_MASK);
            // Ce que le script calcule ne déborde jamais des 64 bits signés (R59).
            prop_assert!(si * ri + ci <= i64::MAX as i128, "le calcul du script déborderait");
            for age in [(attente as i64 + ecart).max(0) as u64, age_hasard] {
                let permis = c.immediate(u64::MAX, age);
                prop_assert_eq!(permis as i128, ref_immediate(ci, ri, u64::MAX as i128, age as i128));
                prop_assert_eq!(attente <= age, s as u64 <= permis, "s={} attente={} age={} permis={}", s, attente, age, permis);
            }
        }

        /// M1, M2 et la courbe (spec/moteur-de-risque.md §4.2) : l'outil (`Coeur`), le moteur de
        /// risque (`risque::Couloir`) et la vue du coffre (`coffre::Vue`) rendent exactement les
        /// formules, sans dépassement, pour toutes les valeurs que le type permet.
        #[test]
        fn m1_m2_et_courbe_sans_arrondi_ni_depassement(
            (cap, r) in params_aux_bornes(),
            v in prop_oneof![1u64..20_000_000_000, any::<u64>()],
            age in prop_oneof![0u64..10_000_000, any::<u64>()],
            d in prop_oneof![0u64..10_000_000, any::<u64>()],
        ) {
            let c = coeur(cap, r);
            prop_assume!(c.verifier().is_ok());
            let (ci, ri) = (cap as i128, r as i128);
            let m1 = c.immediate(v, age);
            let m2 = c.fenetre(v, age, d);
            prop_assert_eq!(m1 as i128, ref_immediate(ci, ri, v as i128, age as i128));
            prop_assert_eq!(m2 as i128, ref_fenetre(ci, ri, v as i128, age as i128, d as i128), "M2 (R59 : dépassement)");
            prop_assert!(m1 <= m2 && m2 <= v);
            prop_assert_eq!(c.fenetre(v, age, 0), m1, "M2 sur une fenêtre nulle = M1");
            if let Some(d2) = d.checked_add(1) {
                prop_assert!(c.fenetre(v, age, d2) >= m2, "M2 croît avec D");
            }
            // Le moteur de risque et la vue appellent bien les mêmes formules.
            if v <= i64::MAX as u64 && age <= 1 << 62 && d <= i64::MAX as u64 {
                let now = 1i64 << 62;
                let couloir = crate::risque::Couloir {
                    agent: String::new(), params: crate::risque::Rythme { capacite: cap, periode: r }, creation: now - age as i64, valeur: v,
                };
                prop_assert_eq!(couloir.immediate(now) as u64, m1);
                prop_assert_eq!(couloir.fenetre(now, d as i64) as u64, m2);
            }
            let op = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
            let x = 1u64 << 40;
            let etat = crate::coffre::EtatCoeur { version: crate::coffre::VERSION.into(), retour: None, capacite: cap, periode: r, agent: String::new(), cree_daa: x,
                apports: vec![crate::coffre::Apport { txid: String::new(), sompi: v, daa: x }], vues: vec![], achats: vec![] };
            let vue = crate::coffre::Vue { coeur: c.clone(), adresse: String::new(),
                pieces: vec![crate::coffre::Piece { outpoint: op, valeur: v, creation: Some(x) }], now: x.saturating_add(age), etat: Some(etat) };
            prop_assert_eq!(vue.immediate(), c.immediate(v, x.saturating_add(age) - x));
            prop_assert_eq!(vue.courbe(x.saturating_add(d)) as i128, ref_fenetre(ci, ri, v as i128, 0, (x.saturating_add(d) - x) as i128));
            prop_assert_eq!(vue.courbe(x - 1), 0, "avant l'apport : rien");
        }
    }

    /// R59 (a) : la perte annoncée sur une fenêtre ne doit jamais « reboucler » vers une petite
    /// valeur. Avant correctif, le résultat était tronqué à 64 bits AVANT d'être borné par la
    /// valeur de la pièce : une fenêtre assez longue annonçait 0.
    #[test]
    fn r59_fenetre_ne_reboucle_pas() {
        let c = coeur(1 << 40, 1);
        assert!(c.verifier().is_ok());
        assert_eq!(c.fenetre(5_000_000_000, 0, 1 << 24), 5_000_000_000, "C·D/R = 2^64 : toute la pièce est exposée");
        // Coffre de référence, fenêtre démesurée (affichage de la courbe très loin dans le temps).
        let c = coeur(50_000_000, 288_000);
        for d in [u64::MAX, u64::MAX / 2, 106_250_000_000_000_000] {
            assert_eq!(c.fenetre(2_000_000_000, 0, d), 2_000_000_000, "D = {d}");
        }
    }

    /// R59 (b) : le script calcule (spent × period + capacity) − 1 en 64 bits signés ; le moteur
    /// refuse tout dépassement, même intermédiaire. Si C × R + C dépasse 2^63 − 1, un paiement proche de la
    /// capacité serait refusé par le réseau alors que l'outil l'annonce possible. Sans danger
    /// pour les fonds (le propriétaire garde la main), mais l'outil doit refuser ces réglages.
    #[test]
    fn r59_reglages_au_ras_du_debordement() {
        let r = PERIODE_MAX;
        let cap = i64::MAX / r; // C × R ≤ 2^63 − 1 mais la somme intermédiaire C × R + C déborde
        let c = coeur(cap, r);
        let art = c.artifact_sans_verification().unwrap();
        let valeur = 10 * cap as u64;
        // Le script, lui, refuse bien le paiement à pleine capacité (débordement détecté par le moteur)…
        let tx = tx_pay(&art, valeur, externe(), cap as u64, 0, r as u64);
        let entree = UtxoEntry::new(valeur, vault_spk(&art), 0, false, None);
        assert!(script(&tx, &entree).is_none(), "débordement : le moteur refuse");
        // …donc l'outil ne doit pas laisser créer un tel coffre.
        assert!(c.verifier().is_err(), "réglages au ras du débordement refusés par l'outil");
        // Juste en dessous de la limite : accepté par l'outil, et le paiement à pleine capacité passe.
        let cap_ok = i64::MAX / (r + 1);
        let c = coeur(cap_ok, r);
        assert!(c.verifier().is_ok());
        let art = c.artifact().unwrap();
        let tx = tx_pay(&art, 10 * cap_ok as u64, externe(), cap_ok as u64, 0, c.attente(cap_ok));
        let entree = UtxoEntry::new(10 * cap_ok as u64, vault_spk(&art), 0, false, None);
        assert!(accepte(&tx, &entree, r as u64), "pleine capacité au bout d'une période");
        assert!(!accepte(&tx, &entree, r as u64 - 1));
    }

    /// R63 (durcissement, prochaine version du contrat) : selon UNDEFINED-BEHAVIOUR.md du
    /// compilateur, une division par zéro ou un dépassement arithmétique est un « comportement
    /// indéfini » sur lequel un contrat ne doit pas compter pour refuser. Or coeur.sil compte
    /// dessus dans trois cas de réglages aberrants : période nulle (division de la garde), capacité
    /// nulle (division du délai) et C × R + C au-delà de 2^63 − 1 (somme du délai). Avec le
    /// compilateur épinglé (443d519e) et le bytecode figé par son empreinte, le moteur refuse bien
    /// dans les trois cas : ce test le fige. L'outil et le vendeur refusent ces réglages en amont.
    #[test]
    fn r63_reglages_aberrants_refuses_par_le_bytecode_fige() {
        let essais = |c: &Coeur, valeur: u64| -> bool {
            let Ok(art) = c.artifact_sans_verification() else { return false }; // refus dès la compilation : sûr aussi
            let entree = UtxoEntry::new(valeur, vault_spk(&art), 0, false, None);
            let mut passe = false;
            for montant in [0u64, 1, 1_000, valeur / 2, valeur] {
                for seq in [0u64, 1, 1_000, u32::MAX as u64] {
                    passe |= script(&tx_pay(&art, valeur, externe(), montant, 0, seq), &entree).is_some();
                }
            }
            passe
        };
        assert!(coeur(200_000_000, 0).verifier().is_err() && coeur(0, 864_000).verifier().is_err());
        assert!(!essais(&coeur(200_000_000, 0), 1_000_000_000), "période nulle : aucun paiement ne doit passer");
        assert!(!essais(&coeur(200_000_000, -5), 1_000_000_000), "période négative");
        assert!(!essais(&coeur(-5, -5), 1_000_000_000), "capacité et période négatives");
        assert!(!essais(&coeur(-5, 864_000), 1_000_000_000), "capacité négative");
        // Capacité nulle : seule la dépense nulle resterait concevable (rien ne sort) ; le bytecode
        // figé la refuse aussi (division par zéro dans le calcul du délai).
        assert!(!essais(&coeur(0, 864_000), 1_000_000_000), "capacité nulle");
    }

    /// Dépense nulle (ni paiement ni frais) : le délai exigé est 0, le script accepte. L'agent ne
    /// gagne rien (rien ne sort, et la pièce recréée repart de l'âge 0) ; noté pour mémoire.
    #[test]
    fn depense_nulle_sans_effet() {
        let c = coeur(200_000_000, 864_000);
        let art = c.artifact().unwrap();
        let tx = tx_pay(&art, 1_000_000_000, externe(), 0, 0, 0);
        let entree = UtxoEntry::new(1_000_000_000, vault_spk(&art), 5_000, false, None);
        assert!(accepte(&tx, &entree, 5_000));
        assert_eq!(tx.outputs[1].value, 1_000_000_000, "tout reste dans le coffre");
    }

    // ------------------------------------------------ Red Team : le compilateur et `this.ageDaa`
    // Lecture des sources du compilateur (révision 443d519e) : rapport §2.

    /// Garde émise par le compilateur juste avant OpCheckSequenceVerify :
    /// OpDup 0 <2^32> OpWithin OpVerify (10 octets), puis 0xb1.
    const GARDE_CSV: [u8; 11] = [0x76, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa5, 0x69, 0xb1];

    /// Positions des opcodes OpCheckSequenceVerify (0xb1) d'un script, en sautant les données
    /// poussées (une clé peut contenir l'octet 0xb1).
    fn positions_csv(b: &[u8]) -> Vec<usize> {
        let (mut i, mut out) = (0, vec![]);
        while i < b.len() {
            let op = b[i];
            let saut = match op {
                0x01..=0x4b => op as usize,
                0x4c => 1 + b[i + 1] as usize,
                0x4d => 2 + u16::from_le_bytes([b[i + 1], b[i + 2]]) as usize,
                0x4e => 4 + u32::from_le_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4]]) as usize,
                _ => 0,
            };
            if op == 0xb1 {
                out.push(i);
            }
            i += 1 + saut;
        }
        out
    }
    fn tous_les_csv_gardes(b: &[u8]) -> usize {
        let pos = positions_csv(b);
        for p in &pos {
            assert!(*p >= 10 && b[p - 10..=*p] == GARDE_CSV, "OpCheckSequenceVerify sans garde à l'octet {p}");
        }
        pos.len()
    }
    fn mini(corps: &str, args: &[ArtifactValue]) -> Result<SilAbiArtifact, String> {
        let src = format!("pragma silverscript ^0.1.0;\ncontract Mini(int d) {{\n{corps}\n}}\n");
        compile_to_sil_abi_artifact_with_options(&src, args, CompileOptions::default()).map_err(|e| e.to_string())
    }
    /// Exécute l'entrée `go(x)` du mini-contrat avec la `sequence` donnée, par le vrai moteur.
    fn mini_accepte(art: &SilAbiArtifact, x: i64, seq: u64) -> bool {
        let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), vec![], seq, CB_PAY);
        let mut tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(1, externe())], 0, Default::default(), 0, vec![]);
        tx.inputs[0].signature_script = vault_sigscript(art, "go", &[x.into()]).unwrap();
        script(&tx, &UtxoEntry::new(10, vault_spk(art), 0, false, None)).is_some()
    }

    /// Cible 3 : le contrôle « délai ∈ [0, 2^32) » accompagne-t-il TOUTE utilisation de
    /// `this.ageDaa` ? Oui : la grammaire n'admet `this.ageDaa` que sous la forme
    /// `require(this.ageDaa >= expression)`, et le compilateur n'émet OpCheckSequenceVerify qu'à un
    /// seul endroit, toujours précédé de la garde. Ce test le vérifie sur le bytecode produit, pour
    /// le cœur et pour des contrats écrits exprès (constante, argument, calcul, branche, boucle
    /// d'appels), puis par l'exécution : aucun délai hors bornes n'est tronqué.
    #[test]
    fn compilateur_garde_toujours_le_verrou_relatif() {
        // Le cœur : un seul verrou, gardé.
        assert_eq!(tous_les_csv_gardes(&crate::bytecode(&coeur(200_000_000, 864_000).artifact().unwrap())), 1);
        for (c, r) in [(1, 1), (1, PERIODE_MAX), (i64::MAX / 2, 1), (177, 0xb1b1b1)] {
            assert_eq!(tous_les_csv_gardes(&crate::bytecode(&coeur(c, r).artifact_sans_verification().unwrap())), 1);
        }
        // Formes variées : chacune compile, et chaque verrou émis est gardé.
        let formes = [
            ("entry go(int x) { require(this.ageDaa >= d); require(x == x); }", 1),
            ("entry go(int x) { require(this.ageDaa >= x); }", 1),
            ("entry go(int x) { require(this.ageDaa >= x * 2 + d); }", 1),
            ("entry go(int x) { if (x > 3) { require(this.ageDaa >= x); } else { require(this.ageDaa >= d); } }", 2),
            ("entry go(int x) { int y = x - 1; require(this.ageDaa >= y); require(this.ageDaa >= x, \"encore\"); }", 2),
        ];
        for (corps, n) in formes {
            let art = mini(corps, &[5i64.into()]).unwrap_or_else(|e| panic!("{corps} : {e}"));
            assert_eq!(tous_les_csv_gardes(&crate::bytecode(&art)), n, "{corps}");
        }
        // Toute autre utilisation de `this.ageDaa` est refusée à la compilation.
        for corps in [
            "entry go(int x) { int a = this.ageDaa; require(a >= x); }",
            "entry go(int x) { require(this.ageDaa > x); }",
            "entry go(int x) { require(x <= this.ageDaa); }",
            "entry go(int x) { require(this.ageDaa >= x || x == 0); }",
            "entry go(int x) { require(this.ageDaa + 1 >= x); }",
            "entry go(int x) { require(!(this.ageDaa >= x)); }",
        ] {
            assert!(mini(corps, &[5i64.into()]).is_err(), "devrait être refusé : {corps}");
        }
        // Constante hors bornes : refusée dès la compilation.
        let constante = "entry go(int x) { require(this.ageDaa >= d); require(x == x); }";
        assert!(mini(constante, &[(1i64 << 32).into()]).is_err());
        assert!(mini(constante, &[(-1i64).into()]).is_err());
        assert!(mini(constante, &[((1i64 << 32) - 1).into()]).is_ok());
        // Valeur connue seulement à l'exécution : la garde refuse, rien n'est tronqué à 32 bits.
        let art = mini("entry go(int x) { require(this.ageDaa >= x); }", &[5i64.into()]).unwrap();
        assert!(mini_accepte(&art, 5, 5) && mini_accepte(&art, 5, 6) && !mini_accepte(&art, 5, 4));
        assert!(mini_accepte(&art, 0, 0));
        let max = (1i64 << 32) - 1;
        assert!(mini_accepte(&art, max, max as u64) && !mini_accepte(&art, max, max as u64 - 1));
        for (x, seq) in [
            (1i64 << 32, 0u64),              // 2^32 tronqué vaudrait 0
            (1 << 32, 1 << 32),
            ((1 << 32) + 5, 5),              // 2^32 + 5 tronqué vaudrait 5
            ((1 << 32) + 5, (1 << 32) + 5),
            (-1, 0),
            (-1, u32::MAX as u64),
            (i64::MIN + 1, 0),               // bit de poids fort
            (i64::MAX, u64::MAX >> 1),
            (1 << 40, 1 << 40),
        ] {
            assert!(!mini_accepte(&art, x, seq), "délai {x} avec sequence {seq:#x} : devrait être refusé");
        }
        // `sequence` avec le bit « verrou désactivé » : refusée par OpCheckSequenceVerify.
        assert!(!mini_accepte(&art, 5, SEQUENCE_LOCK_TIME_DISABLED | 5));
    }

    // ------------------------------------------------ Red Team : réorganisations de chaîne
    //
    // Modèle (rapport §1). Une réorganisation abandonne une branche de blocs et en adopte une autre
    // à partir d'un point de fourche. Vu du coffre :
    //  - l'état revient à celui de la fourche (les pièces dépensées sur la branche abandonnée
    //    réapparaissent, celles qu'elle avait créées disparaissent) ;
    //  - l'horloge (score DAA) repart de la fourche : elle n'est PAS monotone pour un observateur ;
    //  - les transactions de la branche abandonnée retournent au mempool. Chacune peut être
    //    ré-inscrite telle quelle (mêmes octets, même signature, même `sequence`) à un autre score,
    //    dans le même ordre de dépendance, ou ne jamais l'être ; le réseau la revalide alors
    //    entièrement : sa pièce d'entrée doit exister sur la nouvelle branche, et son verrou
    //    relatif est recompté depuis la NOUVELLE date d'inscription de cette pièce ;
    //  - l'adversaire (l'agent) choisit lesquelles rejouer, quand, et peut glisser d'autres
    //    paiements à la place (double dépense de la même pièce) ; il peut aussi doubler un gel.
    // Invariant : sur l'historique FINAL, la perte nette reste sous la courbe, et la borne par
    // fenêtre tient pour les pièces de l'historique final.

    #[derive(Clone, Debug, PartialEq)]
    struct Pc {
        id: u32,
        valeur: u64,
        cree: u64,
    }

    /// Une transaction diffusée, telle qu'elle peut être rejouée sur une autre branche.
    #[derive(Clone, Debug)]
    enum Diffusee {
        /// Dépôt d'une pièce (propriétaire, ou tiers si `tiers`).
        Depot { id: u32, valeur: u64, tiers: bool },
        /// Paiement signé de l'agent : dépense la pièce `entree`, crée la continuation `sortie`.
        Pay { entree: u32, sortie: u32, valeur: u64, montant: u64, frais: u64, seq: u64 },
        /// Gel d'une pièce par le propriétaire.
        Gel { entree: u32 },
    }

    #[derive(Clone, Debug, Default)]
    struct Branche {
        t: u64,
        pieces: Vec<Pc>,
        pertes: Vec<(u64, u64)>,
        retours: Vec<(u64, u64)>,
        /// Dépôts (instant d'inscription, valeur, du propriétaire ?).
        depots: Vec<(u64, u64, bool)>,
        instantanes: Vec<(u64, Vec<Pc>)>,
        geles: Vec<u32>,
        inscrites: usize,
    }

    impl Branche {
        fn avancer(&mut self, dt: u64) {
            self.t += dt;
            if self.instantanes.last().map(|x| x.0) != Some(self.t) {
                self.instantanes.push((self.t, self.pieces.clone()));
            }
        }

        /// Le réseau valide `tx` dans le contexte de CETTE branche, à l'instant courant, avec le vrai
        /// moteur de script et la règle de consensus du verrou relatif. Vrai si elle est inscrite.
        fn inscrire(&mut self, c: &Coeur, art: &SilAbiArtifact, tx: &Diffusee) -> bool {
            let ok = match tx {
                Diffusee::Depot { id, valeur, tiers } => {
                    if self.pieces.iter().any(|p| p.id == *id) {
                        return false;
                    }
                    self.pieces.push(Pc { id: *id, valeur: *valeur, cree: self.t });
                    self.depots.push((self.t, *valeur, !*tiers));
                    if *tiers {
                        self.retours.push((self.t, *valeur));
                    }
                    true
                }
                Diffusee::Gel { entree } => {
                    let Some(i) = self.pieces.iter().position(|p| p.id == *entree) else { return false };
                    assert!(gel_accepte(art, self.pieces[i].valeur, self.pieces[i].cree), "le gel passe toujours si la pièce existe");
                    self.pieces.remove(i);
                    self.geles.push(*entree);
                    true
                }
                Diffusee::Pay { entree, sortie, valeur, montant, frais, seq } => {
                    // La pièce d'entrée doit exister ici (sinon : entrée manquante ou déjà dépensée).
                    let Some(i) = self.pieces.iter().position(|p| p.id == *entree) else { return false };
                    let pc = self.pieces[i].clone();
                    assert_eq!(pc.valeur, *valeur, "même identifiant, même pièce");
                    let signee = tx_pay(art, *valeur, externe(), *montant, *frais, *seq);
                    let utxo = UtxoEntry::new(*valeur, vault_spk(art), pc.cree, false, None);
                    let ok = accepte(&signee, &utxo, self.t);
                    assert_eq!(ok, modele(c, *valeur, *montant, *frais, *seq, self.t - pc.cree), "moteur ≠ modèle");
                    if ok {
                        let spent = valeur - signee.outputs[1].value;
                        self.pieces.remove(i);
                        self.pieces.push(Pc { id: *sortie, valeur: valeur - spent, cree: self.t });
                        self.pertes.push((self.t, spent));
                    }
                    ok
                }
            };
            self.inscrites += ok as usize;
            ok
        }

        /// Les deux invariants de la preuve, sur l'historique de cette branche.
        fn verifier(&self, c: &Coeur, initiales: &[Pc], debut: u64) -> Result<(), TestCaseError> {
            let mut moments: Vec<u64> = self.pertes.iter().map(|p| p.0).chain(self.retours.iter().map(|r| r.0)).chain([self.t]).collect();
            moments.sort();
            for x in moments {
                let sorti: u64 = self.pertes.iter().filter(|(y, _)| *y <= x).map(|(_, v)| v).sum();
                let revenu: u64 = self.retours.iter().filter(|(y, _)| *y <= x).map(|(_, v)| v).sum();
                let courbe: u64 = initiales.iter().map(|p| c.fenetre(p.valeur, debut - p.cree, x - debut)).sum::<u64>()
                    + self.depots.iter().filter(|(y, _, proprio)| *proprio && *y <= x).map(|(y, v, _)| c.fenetre(*v, 0, x - y)).sum::<u64>();
                prop_assert!(sorti as i128 - revenu as i128 <= courbe as i128, "courbe dépassée à {} : sorti {} − revenu {} > {}", x, sorti, revenu, courbe);
            }
            for (a, presentes) in &self.instantanes {
                for d in [0u64, 1, 1_000, 86_400, 864_000, self.t - a] {
                    let perte: u64 = self.pertes.iter().filter(|(x, _)| *x >= *a && *x <= a + d).map(|(_, v)| v).sum();
                    let annonce: u64 = presentes.iter().map(|p| c.fenetre(p.valeur, a - p.cree, d)).sum::<u64>()
                        + self.depots.iter().filter(|(x, _, _)| *x >= *a && *x <= a + d).map(|(x, v, _)| c.fenetre(*v, 0, a + d - x)).sum::<u64>();
                    prop_assert!(perte <= annonce, "fenêtre [{}, +{}] : perte {} > annonce {}", a, d, perte, annonce);
                }
            }
            Ok(())
        }
    }

    /// Ce que fait un acteur sur une branche : produit une transaction (identifiants neufs).
    #[derive(Clone, Debug)]
    enum Geste {
        Payer { i: usize, avidite: f64, frais: u64, s: Seq },
        Deposer { valeur: u64, tiers: bool },
        Geler { i: usize },
    }

    fn geste() -> impl Strategy<Value = (u64, Geste)> {
        let payer = (any::<usize>(), prop_oneof![3 => 0.0f64..1.2, 1 => 1.0f64..3.0], 0u64..500_000, seq())
            .prop_map(|(i, avidite, frais, s)| Geste::Payer { i, avidite, frais, s });
        let deposer = (1u64..3_000_000_000, any::<bool>()).prop_map(|(valeur, tiers)| Geste::Deposer { valeur, tiers });
        let geler = any::<usize>().prop_map(|i| Geste::Geler { i });
        let dt = prop_oneof![1 => Just(0u64), 3 => 1u64..2_000, 3 => 1u64..2_000_000];
        (dt, prop_oneof![12 => payer, 3 => deposer, 1 => geler])
    }

    /// Fabrique la transaction du geste dans l'état de la branche (sans l'inscrire).
    fn fabriquer(c: &Coeur, b: &Branche, g: &Geste, prochain: &mut u32) -> Option<Diffusee> {
        let mut neuf = || {
            *prochain += 1;
            *prochain
        };
        match g {
            Geste::Deposer { valeur, tiers } => Some(Diffusee::Depot { id: neuf(), valeur: *valeur, tiers: *tiers }),
            Geste::Geler { i } => (!b.pieces.is_empty()).then(|| Diffusee::Gel { entree: b.pieces[i % b.pieces.len()].id }),
            Geste::Payer { i, avidite, frais, s } => {
                if b.pieces.is_empty() {
                    return None;
                }
                let pc = &b.pieces[i % b.pieces.len()];
                let age = b.t - pc.cree;
                let permis = c.immediate(pc.valeur, age);
                let spent = ((permis as f64 * avidite) as u64).max(1).min(pc.valeur);
                let frais = (*frais).min(spent - 1);
                let sq = valeur_seq(s, c.attente(spent as i64), age);
                Some(Diffusee::Pay { entree: pc.id, sortie: neuf(), valeur: pc.valeur, montant: spent - frais, frais, seq: sq })
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: cases(192), ..ProptestConfig::default() })]

        /// Réorganisation : une histoire commune, puis une branche A (abandonnée) et une branche B
        /// (finale) qui repart de la fourche. Sur B, l'adversaire rejoue tout ou partie des
        /// transactions de A à d'autres scores, y intercale des doubles dépenses, puis continue.
        /// La courbe et la borne par fenêtre tiennent sur l'historique final, et aussi sur A tant
        /// qu'elle était la chaîne. Les pièces gelées sur B ne reparaissent jamais.
        #[test]
        fn reorganisation_sous_la_courbe(
            cap in 1_000i64..2_000_000_000,
            r in 1i64..3_000_000,
            valeur in 1u64..20_000_000_000,
            age0 in 0u64..5_000_000,
            commun in prop::collection::vec(geste(), 0..12),
            suite_a in prop::collection::vec(geste(), 1..16),
            // Pour chaque transaction de A : écart de temps sur B, rejouée ou non, intrus éventuel.
            rejeu in prop::collection::vec((prop_oneof![2 => Just(0u64), 3 => 1u64..2_000, 2 => 1u64..2_000_000], prop::bool::weighted(0.8), prop::option::weighted(0.3, geste())), 16),
            suite_b in prop::collection::vec(geste(), 0..10),
        ) {
            let c = coeur(cap, r);
            prop_assume!(c.verifier().is_ok());
            let art = c.artifact().unwrap();
            let debut = 10_000_000u64;
            let initiales = vec![Pc { id: 0, valeur, cree: debut - age0 }];
            let mut prochain = 0u32;
            let mut tronc = Branche { t: debut, pieces: initiales.clone(), ..Default::default() };
            for (dt, g) in &commun {
                tronc.avancer(*dt);
                if let Some(tx) = fabriquer(&c, &tronc, g, &mut prochain) {
                    tronc.inscrire(&c, &art, &tx);
                }
            }
            // Branche A : ce que le réseau a d'abord inscrit.
            let mut a = tronc.clone();
            let mut diffusees = vec![];
            for (dt, g) in &suite_a {
                a.avancer(*dt);
                if let Some(tx) = fabriquer(&c, &a, g, &mut prochain) {
                    if a.inscrire(&c, &art, &tx) {
                        diffusees.push(tx);
                    }
                }
            }
            a.verifier(&c, &initiales, debut)?;
            // Branche B : l'horloge et l'état repartent de la fourche.
            let mut b = tronc.clone();
            for (tx, (dt, rejouer, intrus)) in diffusees.iter().zip(&rejeu) {
                b.avancer(*dt);
                if let Some((dt2, g)) = intrus {
                    if let Some(autre) = fabriquer(&c, &b, g, &mut prochain) {
                        b.inscrire(&c, &art, &autre);
                    }
                    b.avancer(*dt2 % 1_000);
                }
                if *rejouer {
                    b.inscrire(&c, &art, tx);
                }
            }
            for (dt, g) in &suite_b {
                b.avancer(*dt);
                if let Some(tx) = fabriquer(&c, &b, g, &mut prochain) {
                    b.inscrire(&c, &art, &tx);
                }
            }
            b.verifier(&c, &initiales, debut)?;
            prop_assert!(b.geles.iter().all(|g| b.pieces.iter().all(|p| p.id != *g)), "une pièce gelée sur la chaîne finale ne reparaît pas");
        }
    }

    /// Réorganisation, cas choisis à la main : ce que le modèle doit montrer (et montre).
    #[test]
    fn reorganisation_cas_choisis() {
        let (cap, r) = (200_000_000i64, 864_000i64);
        let c = coeur(cap, r);
        let art = c.artifact().unwrap();
        let depot = Diffusee::Depot { id: 1, valeur: 1_000_000_000, tiers: false };
        let spent = 50_000_000u64;
        let att = c.attente(spent as i64);
        let pay = Diffusee::Pay { entree: 1, sortie: 2, valeur: 1_000_000_000, montant: spent - 20_000, frais: 20_000, seq: att };
        let suite = Diffusee::Pay { entree: 2, sortie: 3, valeur: 1_000_000_000 - spent, montant: spent - 20_000, frais: 20_000, seq: att };

        // Branche A : dépôt à 1 000, deux paiements enchaînés, chacun au plus tôt.
        let mut a = Branche { t: 1_000, ..Default::default() };
        assert!(a.inscrire(&c, &art, &depot));
        a.avancer(att);
        assert!(a.inscrire(&c, &art, &pay));
        a.avancer(att);
        assert!(a.inscrire(&c, &art, &suite));

        // (1) Branche B : le dépôt est ré-inscrit 500 unités PLUS TARD. Le même paiement signé,
        // présenté au même score que sur A, est refusé : le verrou est recompté depuis la nouvelle
        // inscription. Il ne passe qu'une fois le délai entier écoulé de nouveau, et la suite aussi.
        let mut b = Branche { t: 1_500, ..Default::default() };
        assert!(b.inscrire(&c, &art, &depot));
        b.avancer(att - 500);
        assert!(!b.inscrire(&c, &art, &pay), "rejoué trop tôt pour la nouvelle inscription : refusé");
        assert!(!b.inscrire(&c, &art, &suite), "la suite dépend d'une pièce qui n'existe pas encore");
        b.avancer(500);
        assert!(b.inscrire(&c, &art, &pay));
        assert!(!b.inscrire(&c, &art, &suite), "continuation trop jeune sur la nouvelle branche");
        b.avancer(att);
        assert!(b.inscrire(&c, &art, &suite));
        b.verifier(&c, &[], 1_500).unwrap();

        // (2) Branche B' : le dépôt n'est pas ré-inscrit. Aucun paiement de A ne survit.
        let mut b2 = Branche { t: 1_000, ..Default::default() };
        b2.avancer(10 * att);
        assert!(!b2.inscrire(&c, &art, &pay) && !b2.inscrire(&c, &art, &suite));

        // (3) Double dépense : sur B'', l'agent remplace son premier paiement par un plus gros.
        // Le paiement de A et sa suite ne peuvent plus être inscrits ; la perte reste sous la courbe.
        let mut b3 = Branche { t: 1_000, ..Default::default() };
        assert!(b3.inscrire(&c, &art, &depot));
        b3.avancer(r as u64);
        let gros = Diffusee::Pay { entree: 1, sortie: 9, valeur: 1_000_000_000, montant: cap as u64, frais: 0, seq: r as u64 };
        assert!(b3.inscrire(&c, &art, &gros));
        assert!(!b3.inscrire(&c, &art, &pay) && !b3.inscrire(&c, &art, &suite));
        b3.verifier(&c, &[], 1_000).unwrap();

        // (4) Limite documentée (spec/moteur-de-risque.md §6) : un chiffre annoncé sur une branche
        // ensuite abandonnée ne vaut pas pour la branche finale. Sur A, juste après le deuxième
        // paiement, le moteur annonce 0 d'exposition immédiate (la continuation est neuve). Si A
        // est abandonnée et que B inscrit les mêmes paiements plus tard, ils tombent APRÈS
        // l'instant de l'annonce : la perte sur [annonce, annonce + 0] n'est plus nulle. L'écart ne
        // dépasse jamais ce que la branche abandonnée avait déjà compté comme perdu.
        let instant = a.t;
        let annonce_a: u64 = a.pieces.iter().map(|p| c.fenetre(p.valeur, instant - p.cree, 0)).sum();
        assert_eq!(annonce_a, 0);
        let mut b4 = Branche { t: 1_000, ..Default::default() };
        assert!(b4.inscrire(&c, &art, &depot));
        b4.avancer(att);
        assert!(b4.inscrire(&c, &art, &pay));
        b4.avancer(instant - b4.t); // la suite est inscrite pile à l'instant de l'annonce faite sur A
        assert!(b4.inscrire(&c, &art, &suite));
        let perte_b: u64 = b4.pertes.iter().filter(|(x, _)| *x >= instant).map(|(_, v)| v).sum();
        let annulees: u64 = a.pertes.iter().map(|(_, v)| v).sum();
        assert!(perte_b > annonce_a && perte_b <= annonce_a + annulees);
        b4.verifier(&c, &[], 1_000).unwrap(); // sur l'historique final, tout tient
    }

    /// La borne simple, vérifiée directement : la pièce déposée de longue date, attaquée par un
    /// agent qui dépense à chaque instant tout ce qui est permis, ne perd jamais plus que
    /// C + C × D / R sur une fenêtre de D, et atteint presque cette valeur (la borne est serrée).
    #[test]
    fn borne_simple_atteinte_et_jamais_depassee() {
        let (cap, r) = (200_000_000i64, 864_000i64);
        let c = coeur(cap, r);
        let art = c.artifact().unwrap();
        let mut piece = Piece { coffre: 0, valeur: 100 * cap as u64, cree: 0 };
        let debut = 10 * r as u64; // pièce vieille de dix périodes
        let mut t = debut;
        let mut perte = 0u64;
        let d = 3 * r as u64;
        while t <= debut + d {
            let spent = c.immediate(piece.valeur, t - piece.cree);
            if spent > 0 {
                let tx = tx_pay(&art, piece.valeur, externe(), spent, 0, c.attente(spent as i64));
                let entree = UtxoEntry::new(piece.valeur, vault_spk(&art), piece.cree, false, None);
                assert!(accepte(&tx, &entree, t));
                perte += spent;
                piece = Piece { coffre: 0, valeur: piece.valeur - spent, cree: t };
            }
            t += 7_919; // l'agent se réveille souvent
        }
        let borne = (cap as u64) + (cap as u64) * d / r as u64;
        eprintln!("perte réelle {perte} / borne {borne}");
        assert!(perte <= borne);
        assert!(perte >= borne - borne / 100, "la borne est atteinte à 1 % près : elle est serrée");
    }
}

#[cfg(test)]
mod bytecode {
    /// Écrit le bytecode du cœur (paramètres de référence) pour `tools/desassembler.py`.
    #[test]
    fn exporter_bytecode_de_reference() {
        let k = |b: u8| secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let c = super::Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: crate::CAPACITY, periode: crate::JOUR_DAA, retour: None };
        let b = crate::bytecode(&c.artifact().unwrap());
        assert_eq!(b.len(), 211);
        if let Ok(f) = std::env::var("PLAFOND_EXPORT_BYTECODE") {
            std::fs::write(f, hex::encode(&b)).unwrap();
        }
    }
}

//! Cœur v0.6 : budget d'agent sans mémoire (contracts/coeur.sil), branche coeur-v0.6.
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

pub const SOURCE: &str = include_str!("../../contracts/coeur.sil");
/// Le verrou relatif de Kaspa ne compte que 32 bits (SEQUENCE_LOCK_TIME_MASK).
pub const PERIODE_MAX: i64 = (1i64 << 32) - 1;
/// Budgets de calcul déclarés (marge incluse), mesurés par `budget_de_calcul_suffisant`.
pub const CB_PAY: u16 = 12;
pub const CB_OWNER: u16 = 5;

/// Paramètres d'un coffre. Le script refuse lui-même les valeurs dangereuses ; l'outil refuse en
/// plus les valeurs absurdes (capacité ou période nulles : coffre inutilisable).
#[derive(Clone, Debug)]
pub struct Coeur {
    pub owner: Vec<u8>,
    pub agent: Vec<u8>,
    pub capacite: i64,
    pub periode: i64,
}

impl Coeur {
    pub fn verifier(&self) -> Res<()> {
        if self.capacite <= 0 {
            return Err("capacité nulle ou négative : l'agent ne pourrait rien payer".into());
        }
        if self.periode <= 0 || self.periode > PERIODE_MAX {
            return Err(format!("période hors de 1..={PERIODE_MAX} (verrou relatif 32 bits)").into());
        }
        if self.capacite > i64::MAX / self.periode {
            return Err("capacité × période déborde".into());
        }
        Ok(())
    }

    pub fn artifact(&self) -> Res<SilAbiArtifact> {
        self.verifier()?;
        self.artifact_sans_verification()
    }

    /// Pour les tests de paramètres aberrants : le script doit les refuser seul.
    pub fn artifact_sans_verification(&self) -> Res<SilAbiArtifact> {
        let args: Vec<ArtifactValue> =
            vec![self.owner.clone().into(), self.agent.clone().into(), self.capacite.into(), self.periode.into()];
        Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
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
        (((depart + c * d as i128) / r) as u64).min(valeur)
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
) -> Res<Transaction> {
    let spent = montant.checked_add(frais).filter(|s| *s <= valeur).ok_or("montant + frais au-delà de la pièce")?;
    if spent as i64 > c.capacite {
        return Err(format!("dépense {spent} au-delà de la capacité {}", c.capacite).into());
    }
    let input = TransactionInput::new_with_compute_budget(piece, vec![], c.attente(spent as i64), CB_PAY);
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
        Coeur { owner: crate::xonly(&k(1)), agent: crate::xonly(&k(2)), capacite: c, periode: r }
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
        vm.execute().ok()?;
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
        let tx = build_pay(&c, &art, TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0), valeur, externe(), 50_000_000, 20_000, &k(2)).unwrap();
        let entree = UtxoEntry::new(valeur, vault_spk(&art), 1_000, false, None);
        let unites = script(&tx, &entree).expect("paiement construit par l'outil accepté par le script");
        eprintln!("cœur v0.6 : {} octets, paiement = {unites} unités de calcul", octets(&art));
        assert!(unites <= CB_PAY as u64, "budget insuffisant : {unites} > {CB_PAY}");
        let attente = tx.inputs[0].sequence;
        assert!(!consensus(&tx, &entree, 1_000 + attente - 1), "trop tôt d'une unité : refusé par le réseau");
        assert!(consensus(&tx, &entree, 1_000 + attente), "âge exactement égal au délai : accepté");
        // L'outil refuse ce qui dépasse la capacité ou la pièce.
        let op = TransactionOutpoint::new(TransactionId::from_bytes([3; 32]), 0);
        assert!(build_pay(&c, &art, op, valeur, externe(), 200_000_000, 1, &k(2)).is_err());
        assert!(build_pay(&c, &art, op, 1_000, externe(), 999, 2, &k(2)).is_err());
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
        let tx = build_pay(&c, &art, op, v, externe(), 20_000_000, frais, &k(2)).unwrap();
        let m = crate::masse::masses(&tx, &[UtxoEntry::new(v, vault_spk(&art), 0, false, None)]).unwrap();
        let (p06, p051) = (plancher_v06(crate::FEE), crate::masse::survival_floor(crate::FEE));
        eprintln!("v0.6 : calcul {} g, transitoire {} g, stockage {} g ; plancher d'un couloir {:.4} KAS (v0.5.1 : {:.4} KAS)",
            m.compute, m.transient, m.storage, p06 as f64 / 1e8, p051 as f64 / 1e8);
        assert!(m.standard());
        assert!(m.compute * 100 <= frais, "les frais couvrent la masse de calcul");
        assert!(p06 < p051, "le plancher baisse sans identifiant de covenant");
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

    // ------------------------------------------------ fuzzing : moteur + consensus = modèle

    #[derive(Clone, Debug)]
    enum Seq {
        Honnete,
        MoinsUn,
        Zero,
        Desactivee,
        BitHautEtDelai,
        DeuxPuissance32,
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
            1 => any::<u64>().prop_map(Seq::Hasard),
        ]
    }

    fn valeur_seq(s: &Seq, attente: u64) -> u64 {
        match s {
            Seq::Honnete => attente,
            Seq::MoinsUn => attente.saturating_sub(1),
            Seq::Zero => 0,
            Seq::Desactivee => SEQUENCE_LOCK_TIME_DISABLED | attente,
            Seq::BitHautEtDelai => (1u64 << 40) | attente,
            Seq::DeuxPuissance32 => 1u64 << 32,
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
            let sq = valeur_seq(&s, attente);
            // Les erreurs se cachent à la frontière : l'âge est souvent pris à ±3 du délai exigé.
            let age = if pres_de_la_frontiere { (attente as i64 + ecart).max(0) as u64 } else { age_hasard };
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
        /// Le propriétaire (ou un tiers) dépose une nouvelle pièce.
        Deposer { coffre: usize, valeur: u64 },
    }

    fn pas() -> impl Strategy<Value = (u64, Pas)> {
        let payer = (any::<usize>(), 0.0f64..1.2, 0u64..500_000, any::<bool>(), seq())
            .prop_map(|(i, avidite, frais, vers_frere, s)| Pas::Payer { i, avidite, frais, vers_frere, s });
        let deposer = (0usize..2, 1u64..3_000_000_000).prop_map(|(coffre, valeur)| Pas::Deposer { coffre, valeur });
        // Écart de temps : 0 (même bloc), petit, ou grand.
        let dt = prop_oneof![1 => Just(0u64), 3 => 1u64..2_000, 3 => 1u64..2_000_000];
        (dt, prop_oneof![6 => payer, 1 => deposer])
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
        let mut acceptes = 0;
        for (dt, p) in pas {
            t += dt;
            if instantanes.last().map(|x| x.0) != Some(t) {
                instantanes.push((t, pieces.clone()));
            }
            match p {
                Pas::Deposer { coffre, valeur } => {
                    let pc = Piece { coffre: *coffre % coffres.len(), valeur: *valeur, cree: t };
                    depots.push((t, pc.clone()));
                    pieces.push(pc);
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
                    let sq = valeur_seq(s, c.attente(spent as i64));
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

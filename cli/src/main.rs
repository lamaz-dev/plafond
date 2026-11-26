//! vault-cli — déploie et utilise le coffre AgentBudget sur le testnet-10 de Kaspa.
//!
//! Clés (testnet uniquement) lues dans les variables d'environnement :
//!   OWNER_SK, AGENT_SK : clés privées hexadécimales (32 octets). Jamais dans le dépôt.
//! État du coffre (public, sans secret) : fichier JSON, par défaut `testnet/etat-coffre.json`.
//!
//! Commandes :
//!   cles                  génère deux nouvelles clés de test (à ranger dans les secrets GitHub)
//!   adresses              affiche les adresses du propriétaire, de l'agent et du service payé
//!   etat                  état du réseau, solde du propriétaire, état du coffre
//!   deployer [retour]     crée le coffre avec les fonds du propriétaire ; [retour] : adresse de retour
//!   payer <sompi> [--sans-verif]   l'agent paie le service depuis le coffre
//!   recuperer             le propriétaire récupère tout le coffre
//!   sequestre-ouvrir <sompi> <requete> [delai]   l'agent paie un séquestre de livraison (DeliveryEscrow)
//!   sequestre-reclamer <resultat> [--fausse-preuve]   le vendeur encaisse contre la preuve du vérificateur
//!   sequestre-rembourser  le propriétaire récupère le séquestre après le délai
//!   payer ... --forcer-masse   désactive le refus local KIP-9 (pour observer le refus du réseau)

use std::{env, fs, time::Duration};

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineFlags, extract_script_pub_key_address, pay_to_address_script, pay_to_script_hash_script};
use kaspa_wrpc_client::prelude::*;
use secp256k1::{Keypair, Message};
use serde::{Deserialize, Serialize};
use silverscript_abi::{ArtifactValue, SilAbiArtifact, encode_contract_entry_sig_script};
use silverscript_lang::compiler::{CompileOptions, compile_to_sil_abi_artifact_with_options};

#[cfg(test)]
mod fuzz;
mod masse;
mod noeud;
#[cfg_attr(not(test), allow(dead_code))]
mod agents;
mod attaques;
mod cle;
mod connexion;
mod demo;
mod double_auth;
mod secrets;
mod console;
mod prive;
mod retrouver;
mod ardoise;
mod coeur;
mod coffre;
mod course;
mod risque;
mod sobriete;

/// Mémoire plafonnée (voir sobriete.rs) ; les tests n'y sont pas soumis.
#[cfg(not(test))]
#[global_allocator]
static MEMOIRE: sobriete::Plafonne = sobriete::Plafonne;
mod relais;
mod routeur;
mod sequestre;
mod x402;

const SOURCE: &str = include_str!("../../contracts/agent_budget.sil");
/// v0.4, conservée uniquement pour rapatrier les coffres créés avant la v0.5 (R34).
const SOURCE_V04: &str = include_str!("../../contracts/archive/agent_budget_v0.4.sil");
/// v0.5, conservée pour rapatrier les coffres créés avant la v0.5.1 (seconde relecture, constat n° 5).
const SOURCE_V05: &str = include_str!("../../contracts/archive/agent_budget_v0.5.sil");
/// Version de contrat à compiler : 0 = courante, 4 = v0.4 archivée, 5 = v0.5 archivée.
pub static SOURCE_ANCIENNE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
fn source_choisie() -> &'static str {
    match SOURCE_ANCIENNE.load(std::sync::atomic::Ordering::Relaxed) {
        4 => SOURCE_V04,
        5 => SOURCE_V05,
        _ => SOURCE,
    }
}
/// Révision exacte du compilateur SilverScript (doit correspondre à Cargo.toml).
const SILVERSCRIPT_REV: &str = "7eb04634bfbae5350c1808efc7e34c4efa7f93af";

// Réglages du coffre de test (en sompi : 1 KAS = 100 000 000 sompi).
const CAPACITY: i64 = 200_000_000; // 2 TKAS de budget
const REFILL: i64 = 36_000; // recharge complète en ~1 h (10 DAA/s)
const MAX_PER_PAYMENT: i64 = 50_000_000; // 0,5 TKAS max par paiement
const MAX_FEE: i64 = 3_000_000; // frais max autorisés par paiement (0,03 TKAS)
const FEE: u64 = 1_500_000; // frais par entrée (le testnet exige 100 sompi par unité de masse)
const FUND: u64 = 500_000_000; // 5 TKAS déposés dans le coffre
const LANE: i64 = 0;
/// 24 h en score DAA (10 DAA/s sur le testnet-10).
pub const JOUR_DAA: i64 = 864_000;

/// Règles d'un coffre, calculées à partir des trois réglages de l'utilisateur : combien l'agent peut
/// dépenser, sur quelle période, et combien au plus par achat. Cœur v0.6 : la capacité C est le
/// plafond par achat, et la période de recharge R est choisie pour que C + C·P/R = budget sur la
/// période P (borne prouvée, spec/borne-de-perte-v0.6.md). Un mandat neuf démarre à zéro : sa
/// courbe de perte est C·t/R, plafonnée au capital.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Regles {
    pub capacite: i64,
    pub recharge_daa: i64,
    pub plafond: i64,
    pub depot: u64,
    #[serde(default)]
    pub budget: i64,
    #[serde(default)]
    pub periode_daa: i64,
    /// Nombre de pièces du coffre (1 à 4) : autant d'achats possibles d'affilée. Chaque pièce a la
    /// capacité C ; la période R est calculée pour que k·(C + C·P/R) = budget.
    #[serde(default = "une_piece")]
    pub pieces: i64,
}

fn une_piece() -> i64 {
    1
}

/// Pièces au plus par mandat : assez pour une petite rafale, peu pour garder le gel léger.
pub const PIECES_MAX: i64 = 4;

impl Regles {
    pub fn standard() -> Self {
        // Coffre de test : 4 TKAS par heure, 0,5 au plus par achat, 5 TKAS déposés.
        Regles { depot: FUND, ..Regles::calculer(2 * CAPACITY, 36_000, MAX_PER_PAYMENT).expect("réglages de test valides") }
    }

    pub fn calculer(budget: i64, periode_daa: i64, plafond: i64) -> Res<Self> {
        if ![36_000, JOUR_DAA, 7 * JOUR_DAA, 30 * JOUR_DAA].contains(&periode_daa) {
            return Err("période inconnue (heure, jour, semaine ou mois)".into());
        }
        if plafond < 1_000_000 {
            return Err("plafond par achat trop faible".into());
        }
        if budget > 100_000_000_000_000 {
            return Err("budget trop élevé".into());
        }
        if budget < 2 * plafond {
            return Err("le plafond par achat ne peut pas dépasser la moitié du budget de la période".into());
        }
        let capacite = plafond;
        // k pièces : k achats d'affilée possibles. Il faut budget > k·C (au moins la moitié du budget
        // reste pour la recharge) et des pièces au-dessus du plancher KIP-9.
        let depot_prevu = (budget as u64).max(100_000_000);
        let k = (budget / (2 * capacite)).clamp(1, PIECES_MAX).min((depot_prevu / (2 * coeur_plancher())).max(1) as i64);
        let kc = k * capacite;
        // R = ⌈k·C·P / (budget − k·C)⌉ : arrondi au-dessus, la dépense sur la période reste ≤ budget.
        let recharge = ((kc as i128 * periode_daa as i128 + (budget - kc) as i128 - 1) / (budget - kc) as i128) as i64;
        if recharge > coeur::PERIODE_MAX || capacite > i64::MAX / recharge {
            return Err("réglages hors des limites du contrat : choisissez un plafond plus faible ou une période plus courte".into());
        }
        // À l'ouverture, le coffre reçoit une période complète de budget (ajustable ensuite par « Ajouter des fonds »).
        let depot = (budget as u64).max(100_000_000);
        Ok(Regles { capacite, recharge_daa: recharge, plafond, depot, budget, periode_daa, pieces: k })
    }

    /// Dépense maximale possible sur une durée donnée à partir d'un coffre plein (borne prouvée).
    pub fn maximum_sur(&self, duree_daa: i64) -> i64 {
        let k = self.pieces.max(1);
        let une = self.capacite.saturating_add(((self.capacite as i128 * duree_daa as i128) / self.recharge_daa as i128).min(i64::MAX as i128) as i64);
        une.saturating_mul(k)
    }
}

static REGLES_COURANTES: std::sync::Mutex<Option<Regles>> = std::sync::Mutex::new(None);
/// Clé publique (x-only) de l'agent du coffre en cours : permet à la console de travailler sur un
/// coffre dont elle n'a plus la clé privée (agent connecté).
static AGENT_COURANT: std::sync::Mutex<Option<[u8; 32]>> = std::sync::Mutex::new(None);

/// Plus petit solde de pièce qui permet encore un paiement (masse KIP-9, cœur v0.6 : pluralité 1).
pub fn coeur_plancher() -> u64 {
    8_000_000 // ≈ 0,08 TKAS, mesuré par coeur::tests::masse_d_un_paiement_v06
}

/// Clé publique x-only de l'agent du coffre en cours (agent connecté : la console n'a plus sa clé privée).
pub fn agent_pk(agent: &Keypair) -> Vec<u8> {
    AGENT_COURANT.lock().unwrap_or_else(|e| e.into_inner()).map(|p| p.to_vec()).unwrap_or_else(|| xonly(agent))
}

/// Réglages d'un ancien coffre v0.5.1 : ceux du mandat en cours s'il y en a, sinon les réglages de
/// test de la v0.5.1 (capacité 2, recharge 1 h, 0,5 par achat).
fn regles_ancien() -> Regles {
    REGLES_COURANTES.lock().unwrap_or_else(|e| e.into_inner()).unwrap_or(Regles {
        capacite: CAPACITY,
        recharge_daa: REFILL,
        plafond: MAX_PER_PAYMENT,
        depot: FUND,
        budget: 2 * CAPACITY,
        periode_daa: REFILL,
        pieces: 1,
    })
}

/// Règles du coffre sur lequel porte l'opération en cours (standard par défaut).
pub fn regles() -> Regles {
    REGLES_COURANTES.lock().unwrap_or_else(|e| e.into_inner()).unwrap_or_else(Regles::standard)
}
const USE_ALLOWLIST: i64 = 0;
const DAA_MARGIN: u64 = 100; // marge sous le score DAA du réseau (~10 s)

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Etat {
    pub txid: String,
    pub index: u32,
    pub valeur: u64,
    pub tokens: i64,
    pub last_daa: i64,
    /// Identifiant de covenant (KIP-20) de la lignée du coffre, hex.
    #[serde(default)]
    pub cov_id: String,
}

impl Etat {
    pub fn covenant(&self) -> Res<Hash> {
        Ok(Hash::from_bytes(<[u8; 32]>::try_from(hex::decode(&self.cov_id)?.as_slice()).map_err(|_| "identifiant de covenant absent : redéployer le coffre (v0.3)")?))
    }
}

/// Budget de calcul (transactions v1) : un paiement mesuré coûte 11 unités, on prend une marge.
pub const CB_VAULT: u16 = 20;
pub const CB_P2PK: u16 = 15;

pub type Res<T> = Result<T, Box<dyn std::error::Error>>;

/// Clés de test : dérivées de la phrase secrète VAULT_PHRASE (secret GitHub choisi par le
/// propriétaire, jamais visible ailleurs), ou à défaut lues en hexadécimal dans OWNER_SK / AGENT_SK.
pub fn keypair_from_env(var: &str) -> Res<Keypair> {
    if let Ok(phrase) = env::var("VAULT_PHRASE") {
        let phrase = phrase.trim();
        if phrase.len() < 16 {
            return Err("VAULT_PHRASE trop courte (16 caractères minimum)".into());
        }
        let h = blake2b_simd::Params::new().hash_length(32).personal(b"vault-testnet10").key(var.as_bytes()).hash(phrase.as_bytes());
        return Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, h.as_bytes())?);
    }
    let hexkey = env::var(var).map_err(|_| format!("variable {var} absente (ou VAULT_PHRASE)"))?;
    let bytes = hex::decode(hexkey.trim())?;
    Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &bytes)?)
}

/// Clé du propriétaire : fichier chiffré (PROPRIETAIRE_CLE, mot de passe demandé), sinon clés de
/// test (VAULT_PHRASE ou OWNER_SK). Le fichier chiffré est le mode prévu pour un vrai propriétaire.
pub fn charger_proprietaire() -> Res<Keypair> {
    if let Ok(chemin) = env::var("PROPRIETAIRE_CLE") {
        return cle::ouvrir(&chemin);
    }
    keypair_from_env("OWNER_SK")
}

pub fn xonly(k: &Keypair) -> Vec<u8> {
    k.x_only_public_key().0.serialize().to_vec()
}

pub fn address(k: &Keypair) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &xonly(k))
}

/// Le « service » payé par l'agent : une adresse de test dérivée de la clé du propriétaire.
pub fn payee(owner: &Keypair) -> Keypair {
    let h = blake2b_simd::Params::new().hash_length(32).personal(b"vault-payee").hash(&owner.secret_bytes());
    Keypair::from_seckey_slice(secp256k1::SECP256K1, h.as_bytes()).unwrap()
}

/// Paramètres publics d'un coffre (tout ce qu'il faut pour recompiler son script).
/// Monnaie du budget. `KAS` aujourd'hui ; `KSD` (Kaspa Dollar) réservé, en attente de son standard.
pub const ASSET_KAS: &str = "KAS";
pub const ASSET_KSD: &str = "KSD";
fn default_asset() -> String {
    ASSET_KAS.into()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultParams {
    #[serde(default = "default_asset")]
    pub asset: String,
    pub owner: String, // clé publique x-only, hex
    pub agent: String,
    pub lane: i64,
    pub capacity: i64,
    pub refill_period: i64,
    pub max_per_payment: i64,
    pub max_fee: i64,
    pub use_allowlist: i64,
    pub payees: [String; 3],
    pub tokens: i64,
    pub last_daa: i64,
}

impl VaultParams {
    pub fn ours(owner: &Keypair, agent: &Keypair, tokens: i64, last_daa: i64) -> Self {
        Self::pour(&xonly(owner), agent, tokens, last_daa)
    }
    /// Comme `ours`, à partir de la seule clé publique x-only du propriétaire (le routeur n'a jamais sa clé secrète).
    pub fn pour(owner_pk: &[u8], agent: &Keypair, tokens: i64, last_daa: i64) -> Self {
        let zero = hex::encode([0u8; 32]);
        VaultParams {
            asset: ASSET_KAS.into(),
            owner: hex::encode(owner_pk),
            agent: hex::encode(AGENT_COURANT.lock().unwrap_or_else(|e| e.into_inner()).map(|p| p.to_vec()).unwrap_or_else(|| xonly(agent))),
            lane: LANE,
            capacity: regles_ancien().capacite,
            refill_period: regles_ancien().recharge_daa,
            max_per_payment: regles_ancien().plafond,
            max_fee: MAX_FEE,
            use_allowlist: USE_ALLOWLIST,
            payees: [zero.clone(), zero.clone(), zero],
            tokens,
            last_daa,
        }
    }
    /// Budget disponible à l'instant `now` (même calcul que le contrat v0.5) : la recharge court
    /// depuis `creation`, le score DAA du bloc qui a réellement inscrit ce coffre.
    pub fn available(&self, now: i64, creation: i64) -> i64 {
        if creation < self.last_daa {
            return 0; // le contrat refuse tout paiement (coffre non confirmé ou état incohérent)
        }
        let elapsed = (now - creation).clamp(0, self.refill_period);
        (self.tokens + elapsed * self.capacity / self.refill_period).min(self.capacity)
    }
}

/// Garde-fous sur les paramètres, appliqués à la création (outil) et à la vérification (vendeur).
/// Le script calcule `elapsed * capacity` avec `elapsed <= refillPeriod` : ce produit doit tenir sur 63 bits,
/// sinon chaque paiement échouerait (coffre bloqué, fonds récupérables seulement par le propriétaire).
pub fn check_params(p: &VaultParams) -> Res<()> {
    if p.capacity <= 0 || p.refill_period <= 0 || p.max_per_payment <= 0 || p.max_fee < 0 {
        return Err("paramètres invalides : capacité, période, plafond doivent être positifs".into());
    }
    if p.capacity.checked_mul(p.refill_period).is_none() {
        return Err("paramètres invalides : capacité × période de recharge dépasse 2^63".into());
    }
    if p.max_per_payment > p.capacity || p.max_fee > p.capacity || p.tokens < 0 || p.tokens > p.capacity {
        return Err("paramètres invalides : plafond, frais ou jetons supérieurs à la capacité".into());
    }
    if p.lane < 0 || p.last_daa < 0 {
        return Err("paramètres invalides : couloir ou DAA négatif".into());
    }
    Ok(())
}

pub fn compile_params(p: &VaultParams) -> Res<SilAbiArtifact> {
    check_params(p)?;
    compile_unchecked(p)
}

/// Compilation sans garde-fous : ce qu'un attaquant peut toujours faire de son côté.
/// Réservée aux tests antagonistes ; l'outil et le vendeur passent par `compile_params`.
pub fn compile_unchecked(p: &VaultParams) -> Res<SilAbiArtifact> {
    let source = source_choisie();
    compile_source(p, source)
}

/// Compile les paramètres avec une source donnée (v0.4 archivée pour la démonstration de R34).
pub fn compile_source(p: &VaultParams, source: &str) -> Res<SilAbiArtifact> {
    match p.asset.as_str() {
        ASSET_KAS => {}
        ASSET_KSD => return Err("monnaie KSD réservée : en attente du standard Kaspa Dollar".into()),
        other => return Err(format!("monnaie inconnue : {other}").into()),
    }
    let b = |h: &str| -> Res<ArtifactValue> { Ok(hex::decode(h)?.into()) };
    let args: Vec<ArtifactValue> = vec![
        b(&p.owner)?,
        b(&p.agent)?,
        p.lane.into(),
        p.capacity.into(),
        p.refill_period.into(),
        p.max_per_payment.into(),
        p.max_fee.into(),
        p.use_allowlist.into(),
        b(&p.payees[0])?,
        b(&p.payees[1])?,
        b(&p.payees[2])?,
        p.tokens.into(),
        p.last_daa.into(),
    ];
    Ok(compile_to_sil_abi_artifact_with_options(source, &args, CompileOptions::default())?)
}

fn compile(owner: &Keypair, agent: &Keypair, tokens: i64, last_daa: i64) -> Res<SilAbiArtifact> {
    compile_params(&VaultParams::ours(owner, agent, tokens, last_daa))
}

fn compile_pk(owner_pk: &[u8], agent: &Keypair, tokens: i64, last_daa: i64) -> Res<SilAbiArtifact> {
    compile_params(&VaultParams::pour(owner_pk, agent, tokens, last_daa))
}

/// Construit et signe un paiement de l'agent depuis le coffre.
/// Renvoie la transaction, l'état suivant et la valeur restante dans le coffre.
pub fn build_pay(
    owner: &Keypair,
    agent: &Keypair,
    e: &Etat,
    amount: i64,
    payee_spk: ScriptPublicKey,
    now: i64,
    creation: i64,
) -> Res<(Transaction, Etat)> {
    build_pay_pk(&xonly(owner), agent, e, amount, payee_spk, now, creation)
}

/// Paiement de l'agent depuis le coffre, avec la seule clé publique du propriétaire.
pub fn build_pay_pk(
    owner_pk: &[u8],
    agent: &Keypair,
    e: &Etat,
    amount: i64,
    payee_spk: ScriptPublicKey,
    now: i64,
    creation: i64,
) -> Res<(Transaction, Etat)> {
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let available = p.available(now, creation);
    let vault = compile_params(&p)?;
    let cov = e.covenant()?;
    let next_tokens = available - amount - FEE as i64; // les frais sont décomptés du budget
    let next = compile_pk(owner_pk, agent, next_tokens, now)?;
    let entry = UtxoEntry::new(e.valeur, vault_spk(&vault), creation as u64, false, Some(cov));
    let txid_in = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&e.txid)?.as_slice())?);
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid_in, e.index), vec![], 0, CB_VAULT);
    let rest = e.valeur - amount as u64 - FEE;
    let continuation = TransactionOutput {
        value: rest,
        script_public_key: vault_spk(&next),
        covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }),
    };
    let outputs = vec![TransactionOutput::new(amount as u64, payee_spk), continuation];
    let mut tx = Transaction::new(1, vec![input], outputs, now as u64, Default::default(), 0, vec![]);
    // Masse critique (KIP-9) : refuser localement ce que le mempool refuserait.
    if let Some(m) = masse::masses(&tx, std::slice::from_ref(&entry)) {
        if !m.standard() && !masse::FORCER.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(format!(
                "paiement non diffusable : masse de stockage {} g > {} g (KIP-9). Paiement minimal ≈ 0,02 KAS ; un couloir sous ≈ 0,13 KAS ne peut plus payer, le propriétaire doit le recharger ou le vider.",
                m.storage, masse::MAX_STANDARD_MASS
            ).into());
        }
    }
    let s = sign(&tx, &[entry], 0, agent);
    tx.inputs[0].signature_script = vault_sigscript(&vault, "pay", &[s.into(), amount.into(), now.into()])?;
    tx.finalize();
    let next_state = Etat { txid: tx.id().to_string(), index: 1, valeur: rest, tokens: next_tokens, last_daa: now, cov_id: e.cov_id.clone() };
    Ok((tx, next_state))
}

pub fn bytecode(a: &SilAbiArtifact) -> Vec<u8> {
    a.contracts.values().next().expect("un contrat").compiled.bytecode.clone()
}

pub fn vault_spk(a: &SilAbiArtifact) -> ScriptPublicKey {
    pay_to_script_hash_script(&bytecode(a))
}

pub fn sign(tx: &Transaction, entries: &[UtxoEntry], idx: usize, k: &Keypair) -> Vec<u8> {
    let reused = SigHashReusedValuesUnsync::new();
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let h = calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused);
    let sig = k.sign_schnorr(Message::from_digest_slice(h.as_bytes().as_slice()).unwrap());
    let mut s = sig.as_ref().to_vec();
    s.push(SIG_HASH_ALL.to_u8());
    s
}

pub fn vault_sigscript(a: &SilAbiArtifact, entry: &str, args: &[ArtifactValue]) -> Res<Vec<u8>> {
    let name = a.contracts.keys().next().expect("un contrat").clone();
    let mut ss = encode_contract_entry_sig_script(a, &name, entry, args)?;
    ss.extend(ScriptBuilder::with_flags(EngineFlags::default()).add_data(&bytecode(a))?.drain());
    Ok(ss)
}

const SEQUESTRE: &str = "testnet/sequestre.json";
const ARDOISE: &str = "testnet/ardoise.json";

/// Ardoise ouverte et dernier bon signé par l'agent (cumulé : seul le plus élevé compte).
#[derive(Serialize, Deserialize)]
struct ArdoiseOuverte {
    ardoise: ardoise::Ardoise,
    #[serde(default)]
    total: i64,
    #[serde(default)]
    bon: String,
}

/// Empreintes reproductibles : sources, version du compilateur et bytecode de référence.
/// Quiconque recompile le dépôt au même commit doit obtenir exactement ce texte (vérifié en CI).
pub fn empreintes() -> Res<String> {
    let b2 = |d: &[u8]| hex::encode(blake2b_simd::Params::new().hash_length(32).hash(d).as_bytes());
    // Paramètres de référence publics : clés de test dérivées des octets 1 (propriétaire), 2 (agent),
    // 3 (vendeur) et 7 (vérificateur), réglages du coffre de test.
    let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
    let vault = compile_params(&VaultParams::ours(&k(1), &k(2), CAPACITY, 1_000_000))?;
    let merchant = pay_to_address_script(&address(&k(3)));
    let refund = pay_to_address_script(&address(&k(1)));
    let escrow = sequestre::artifact(&merchant, &refund, &k(7), "GET:/meteo-kaspa/commande-1", sequestre::DEFAULT_TIMEOUT)?;
    let tab = ardoise::artifact(&merchant, &xonly(&k(3)), &refund, &xonly(&k(2)), ardoise::DEFAULT_TIMEOUT)?;
    // Cœur v0.7 : adresse de retour de référence = l'adresse du propriétaire de test (valeur par défaut).
    let coeur_ref = coeur::Coeur {
        owner: xonly(&k(1)),
        agent: xonly(&k(2)),
        capacite: CAPACITY,
        periode: JOUR_DAA,
        retour: Some(sequestre::spk_hash(&refund).to_vec()),
    };
    let coeur = coeur_ref.artifact()?;
    let coeur_v06 = coeur::Coeur { retour: None, ..coeur_ref }.artifact()?;
    let mut r = String::new();
    r.push_str("# Empreintes reproductibles (blake2b-256). Régénérer : vault-cli empreintes > contracts/EMPREINTES.txt\n");
    r.push_str(&format!("compilateur silverscript : {}\n", SILVERSCRIPT_REV));
    r.push_str(&format!("source agent_budget.sil : {}\n", b2(SOURCE.as_bytes())));
    r.push_str(&format!("source delivery_escrow.sil : {}\n", b2(sequestre::SOURCE.as_bytes())));
    r.push_str(&format!("source ardoise.sil : {}\n", b2(ardoise::SOURCE.as_bytes())));
    r.push_str(&format!("source coeur.sil (v0.7, adresse de retour) : {}\n", b2(coeur::SOURCE.as_bytes())));
    r.push_str(&format!("source archive/coeur-v0.6.sil (gel des anciens coffres) : {}\n", b2(coeur::SOURCE_V06.as_bytes())));
    for (name, a) in [
        ("AgentBudget (paramètres de référence)", &vault),
        ("DeliveryEscrow (paramètres de référence)", &escrow),
        ("Ardoise (paramètres de référence)", &tab),
        ("Coeur v0.7 (paramètres de référence)", &coeur),
        ("Coeur v0.6 (paramètres de référence)", &coeur_v06),
    ] {
        let code = bytecode(a);
        let addr = extract_script_pub_key_address(&pay_to_script_hash_script(&code), Prefix::Testnet)?;
        r.push_str(&format!("{name} : {} octets, bytecode {}\n  adresse P2SH testnet : {addr}\n", code.len(), b2(&code)));
    }
    Ok(r)
}

/// Garde-fou bloquant avant toute diffusion : convertit la transaction au format RPC (l'objet
/// réellement envoyé au nœud) et refuse si une entrée v1 y a perdu son budget de calcul.
/// Dans rusty-kaspa 2.1.0, `RpcTransactionInput.compute_budget` vaut 0 par défaut en JSON : un
/// aller-retour qui perd ce champ produirait une transaction rejetée (« script units exceeded »).
pub fn garde_diffusion(tx: &Transaction) -> Res<kaspa_rpc_core::RpcTransaction> {
    let rpc: kaspa_rpc_core::RpcTransaction = tx.into();
    if tx.version >= 1 {
        for (i, input) in rpc.inputs.iter().enumerate() {
            if input.compute_budget == 0 {
                return Err(format!("diffusion bloquée : budget de calcul nul sur l'entrée {i}").into());
            }
        }
    }
    Ok(rpc)
}

/// Coffre sur lequel porte l'opération en cours (console à plusieurs agents : un fichier d'état par
/// coffre). La console traite les requêtes une par une ; `avec_coffre` sérialise de toute façon.
static COFFRE_COURANT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static OPERATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Dossier de travail imposé (démo à clé jetable : tout reste dans `demo-jetable/`).
pub static ETAT_DEFAUT: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn etat_par_defaut() -> String {
    if let Some(e) = ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return e;
    }
    env::var("ETAT").unwrap_or_else(|_| "testnet/etat-coffre.json".into())
}

fn state_path() -> String {
    COFFRE_COURANT.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(etat_par_defaut)
}

/// Exécute `f` avec le fichier d'état d'un coffre donné, puis revient au coffre par défaut.
pub fn avec_coffre<T>(chemin_etat: &str, regles: Option<Regles>, agent_pub: Option<[u8; 32]>, f: impl FnOnce() -> T) -> T {
    let _seul = OPERATION.lock().unwrap_or_else(|e| e.into_inner());
    *COFFRE_COURANT.lock().unwrap_or_else(|e| e.into_inner()) = Some(chemin_etat.to_string());
    *REGLES_COURANTES.lock().unwrap_or_else(|e| e.into_inner()) = regles;
    *AGENT_COURANT.lock().unwrap_or_else(|e| e.into_inner()) = agent_pub;
    struct Retour;
    impl Drop for Retour {
        fn drop(&mut self) {
            *COFFRE_COURANT.lock().unwrap_or_else(|e| e.into_inner()) = None;
            *REGLES_COURANTES.lock().unwrap_or_else(|e| e.into_inner()) = None;
            *AGENT_COURANT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }
    let _r = Retour;
    f()
}

pub fn load_state() -> Res<Etat> {
    Ok(serde_json::from_str(&fs::read_to_string(state_path()).map_err(|_| "aucun coffre déployé (fichier d'état absent)")?)?)
}

/// Origine du coffre (état à sa création) : seule donnée que le propriétaire doit garder pour
/// retrouver le coffre courant sans fichier d'état ni routeur (`retrouver`).
fn origine_path() -> String {
    state_path().replace(".json", "-origine.json")
}

/// Mode survie : retrouve le coffre courant depuis son origine, via l'indexeur public, en
/// vérifiant chaque saut, puis confirme auprès du nœud que la sortie existe bien.
/// Lignée vérifiée depuis l'origine. Source principale : le nœud lui-même (parcours de sa chaîne depuis
/// le repère noté au déploiement) — aucune dépendance à un indexeur. Repli sur l'API REST publique
/// seulement sur demande explicite (AVEC_INDEXEUR=1), pour un coffre ancien sans repère.
pub async fn retrouver_lignee(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair, origine: &Etat) -> Res<(retrouver::Issue, usize, Vec<retrouver::Mouvement>)> {
    let raison = match noeud::lire_repere(&state_path()) {
        None => "aucun repère de survie (coffre créé avant cette version)".to_string(),
        Some(rep) => match noeud::lignee(c, &rep, &origine.txid).await {
            Ok(l) => match retrouver::retrouver_avec_historique(&l, owner_pk, agent, origine) {
                Ok(r) => return Ok(r),
                Err(e) => format!("lignée incomplète d'après le nœud : {e}"),
            },
            Err(e) => format!("parcours du nœud impossible : {e}"),
        },
    };
    if env::var("AVEC_INDEXEUR").is_err() {
        return Err(format!("{raison}. Pour un coffre ancien, autoriser le repli sur l'indexeur public : AVEC_INDEXEUR=1").into());
    }
    eprintln!("{raison} : repli sur l'indexeur public (AVEC_INDEXEUR)");
    let (pk, ag, o) = (owner_pk.to_vec(), agent.clone(), origine.clone());
    Ok(tokio::task::spawn_blocking(move || retrouver::retrouver_avec_historique(&retrouver::Rest::depuis_env(), &pk, &ag, &o).map_err(|e| e.to_string())).await??)
}

pub async fn retrouver_coffre(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair) -> Res<Etat> {
    let origine: Etat = serde_json::from_str(&fs::read_to_string(origine_path()).map_err(|_| "origine du coffre absente : impossible de le retrouver")?)?;
    let (issue, sauts, _) = retrouver_lignee(c, owner_pk, agent, &origine).await?;
    match issue {
        retrouver::Issue::Ferme { txid } => Err(format!("coffre déjà fermé par le propriétaire (transaction {txid})").into()),
        retrouver::Issue::Courant(mut e) => {
            e.valeur = montant_coffre(c, owner_pk, agent, &e).await?; // le nœud fait foi, pas l'indexeur
            creation_coffre(c, owner_pk, agent, &e).await.map_err(|_| "la lignée indique un coffre que le nœud ne connaît pas encore (non confirmé ou source en retard) : réessayer")?;
            println!("Coffre retrouvé après {sauts} paiement(s), chaque saut vérifié : sortie {}:{}, {} TKAS", e.txid, e.index, e.valeur as f64 / 1e8);
            save_state(&e)?;
            Ok(e)
        }
    }
}

pub fn save_state(e: &Etat) -> Res<()> {
    let p = state_path();
    if let Some(dir) = std::path::Path::new(&p).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, serde_json::to_string_pretty(e)?)?;
    Ok(())
}

/// Client du testnet-10 : nœud choisi par NOEUD_WRPC (ex. ws://127.0.0.1:17210), sinon découverte
/// automatique d'un nœud public. Connexion bornée dans le temps : un réseau injoignable renvoie une
/// erreur claire au lieu de bloquer la console.
async fn client_testnet() -> Res<KaspaRpcClient> {
    // Un nœud public peut ne pas répondre à un instant donné (premier passage réel du 22 nov. 2026,
    // étape 7) : trois essais, chacun avec un nouveau client (le découvreur choisit un autre nœud).
    for essai in 1..=3 {
        match client_testnet_essai().await {
            Ok(c) => return Ok(c),
            Err(e) if essai < 3 => eprintln!("(nœud injoignable, essai {essai}/3 : {e} ; nouvel essai)"),
            Err(e) => return Err(e),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    unreachable!()
}

async fn client_testnet_essai() -> Res<KaspaRpcClient> {
    let net = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let url = env::var("NOEUD_WRPC").ok().filter(|u| !u.trim().is_empty());
    let resolver = if url.is_some() { None } else { Some(Resolver::default()) };
    let client = KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, url.as_deref(), resolver, Some(net), None)?;
    let opts = ConnectOptions {
        block_async_connect: true,
        strategy: ConnectStrategy::Fallback,
        connect_timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    };
    match tokio::time::timeout(Duration::from_secs(20), client.connect(Some(opts))).await {
        Ok(r) => {
            r?;
        }
        Err(_) => {
            let _ = client.disconnect().await;
            return Err("réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC".into());
        }
    }
    Ok(client)
}

/// Connexion partagée : la console garde UNE connexion ouverte pour toute la session au lieu d'en
/// ouvrir une par action (chaque ouverture coûtait jusqu'à 20 s quand un nœud public tardait).
/// Désactivée par défaut : les commandes ponctuelles ouvrent et ferment leur propre connexion.
pub static CONNEXION_PARTAGEE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PARTAGE: tokio::sync::Mutex<Option<KaspaRpcClient>> = tokio::sync::Mutex::const_new(None);

fn partage_actif() -> bool {
    CONNEXION_PARTAGEE.load(std::sync::atomic::Ordering::Relaxed)
}

pub async fn connect() -> Res<KaspaRpcClient> {
    if !partage_actif() {
        let client = client_testnet().await?;
        annoncer_connexion(&client.url().unwrap_or_default(), false);
        return Ok(client);
    }
    let mut p = PARTAGE.lock().await;
    if let Some(c) = p.as_ref() {
        if c.is_connected() {
            return Ok(c.clone());
        }
        let _ = c.disconnect().await;
    }
    let client = client_testnet().await?;
    annoncer_connexion(&client.url().unwrap_or_default(), false);
    *p = Some(client.clone());
    Ok(client)
}

/// Fin d'usage d'une connexion : fermée, sauf si elle est partagée (elle reste ouverte pour la suite).
pub async fn liberer(c: &KaspaRpcClient) -> Res<()> {
    if partage_actif() {
        return Ok(());
    }
    c.disconnect().await?;
    Ok(())
}

/// Connexion sans message sur la sortie standard (les commandes du relais y écrivent du JSON).
pub async fn connect_silencieux() -> Res<KaspaRpcClient> {
    let client = client_testnet().await?;
    annoncer_connexion(&client.url().unwrap_or_default(), true);
    Ok(client)
}

/// v0.5 : score DAA du bloc qui a réellement inscrit le coffre courant (le contrat fait courir
/// la recharge depuis lui). Erreur si le coffre n'est pas encore confirmé : réessayer.
/// Erreur « sortie absente » : l'état local est périmé (le coffre a bougé) ; distincte de
/// « pas encore confirmé », qui est passagère.
pub const INTROUVABLE: &str = "sortie du coffre introuvable sur la chaîne (état local périmé ?)";

/// Montant de la sortie courante du coffre, lu sur le nœud (lignée vérifiée).
pub async fn montant_coffre(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair, e: &Etat) -> Res<u64> {
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let spk = vault_spk(&compile_params(&p)?);
    let addr = kaspa_txscript::extract_script_pub_key_address(&spk, Prefix::Testnet).map_err(|_| "adresse de coffre invalide")?;
    let utxos = c.get_utxos_by_addresses(vec![addr]).await?;
    let u = utxos.iter().find(|u| u.outpoint.transaction_id.to_string() == e.txid && u.outpoint.index == e.index).ok_or(INTROUVABLE)?;
    if u.utxo_entry.covenant_id != Some(e.covenant()?) {
        return Err("sortie sans la lignée du coffre (leurre ou indexeur menteur) : refusée".into());
    }
    Ok(u.utxo_entry.amount)
}

pub async fn creation_coffre(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair, e: &Etat) -> Res<i64> {
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let spk = vault_spk(&compile_params(&p)?);
    let addr = kaspa_txscript::extract_script_pub_key_address(&spk, Prefix::Testnet).map_err(|_| "adresse de coffre invalide")?;
    let utxos = c.get_utxos_by_addresses(vec![addr]).await?;
    let u = utxos
        .iter()
        .find(|u| u.outpoint.transaction_id.to_string() == e.txid && u.outpoint.index == e.index)
        .ok_or(INTROUVABLE)?;
    // Montant donné par le nœud : un état (ou un indexeur) qui ment sur la valeur est détecté.
    if u.utxo_entry.amount != e.valeur {
        return Err(format!("montant du coffre incohérent : {} sompi annoncés, {} sur la chaîne", e.valeur, u.utxo_entry.amount).into());
    }
    // La sortie doit porter la LIGNÉE du coffre (identifiant de covenant attribué par le réseau,
    // infalsifiable) : un leurre au même script, ou une sortie inventée par un indexeur, ne l'a pas.
    if u.utxo_entry.covenant_id != Some(e.covenant()?) {
        return Err("sortie sans la lignée du coffre (leurre ou indexeur menteur) : refusée".into());
    }
    if u.utxo_entry.block_daa_score == u64::MAX {
        return Err("coffre pas encore confirmé sur la chaîne : réessayer dans quelques secondes".into());
    }
    Ok(u.utxo_entry.block_daa_score as i64)
}

/// Instant et inscription pour un paiement : (now, creation).
/// Si l'état local est périmé (un vendeur a diffusé le paiement sans confirmer, ou l'a retenu), le
/// coffre courant est retrouvé depuis son origine avant d'abandonner (constat n° 5 du relecteur).
pub async fn instants(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair, e: &Etat) -> Res<(i64, i64)> {
    let creation = match creation_coffre(c, owner_pk, agent, e).await {
        Ok(cr) => cr,
        Err(err) if err.to_string() == INTROUVABLE && std::path::Path::new(&origine_path()).exists() => {
            let courant = retrouver_coffre(c, owner_pk, agent).await.map_err(|e2| format!("{err} ; mode survie : {e2}"))?;
            if courant != *e {
                return Err(format!("état local périmé : coffre courant retrouvé ({}:{}) et enregistré, relancer l'opération", courant.txid, courant.index).into());
            }
            return Err(err);
        }
        Err(err) => return Err(err),
    };
    let now = ((virtual_daa(c).await? - DAA_MARGIN) as i64).max(e.last_daa);
    Ok((now, creation))
}

pub async fn virtual_daa(c: &KaspaRpcClient) -> Res<u64> {
    Ok(c.get_block_dag_info().await?.virtual_daa_score)
}

pub fn explorer(txid: &str) -> String {
    format!("https://tn10.kaspa.stream/transactions/{txid}")
}

/// Crée un coffre (cœur v0.6) ; renvoie l'identifiant de transaction.
pub async fn deployer(owner: &Keypair, agent: &Keypair) -> Res<String> {
    coffre::deployer(owner, agent).await
}

/// Ancienne création v0.5.1 (lignée KIP-20), gardée pour les tests de compatibilité.
#[allow(dead_code)]
async fn deployer_ancien(owner: &Keypair, agent: &Keypair) -> Res<String> {
        let (fund, capacite) = (regles().depot, regles().capacite);
        if load_state().is_ok() {
            return Err("un coffre est déjà déployé".into());
        }
        let c = connect().await?;
        let now = (virtual_daa(&c).await? - DAA_MARGIN) as i64;
        let utxos = c.get_utxos_by_addresses(vec![address(&owner)]).await?;
        let mut picked = vec![];
        let mut total = 0u64;
        for u in utxos.into_iter().take(20) {
            total += u.utxo_entry.amount;
            picked.push(u);
            if total >= fund + 2 * FEE + 100_000_000 {
                break;
            }
        }
        if total < fund + FEE {
            return Err(format!("solde insuffisant : {} TKAS, il en faut {}", total as f64 / 1e8, (fund + FEE) as f64 / 1e8).into());
        }
        let vault = compile(&owner, &agent, capacite, now)?;
        let entries: Vec<UtxoEntry> = picked.iter().map(|u| u.utxo_entry.clone().into()).collect();
        let inputs: Vec<TransactionInput> =
            picked.iter().map(|u| TransactionInput::new_with_compute_budget(u.outpoint.clone().into(), vec![], 0, CB_P2PK)).collect();
        let fee = FEE * picked.len() as u64;
        // Genèse de la lignée (KIP-20) : identifiant calculé depuis la première entrée et la sortie du coffre.
        let mut vault_out = TransactionOutput::new(fund, vault_spk(&vault));
        let cov = covenant_id(inputs[0].previous_outpoint, std::iter::once((0u32, &vault_out)));
        vault_out.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: cov });
        let mut outputs = vec![vault_out];
        let change = total - fund - fee;
        if change > 0 {
            outputs.push(TransactionOutput::new(change, pay_to_address_script(&address(&owner))));
        }
        let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        for i in 0..tx.inputs.len() {
            let s = sign(&tx, &entries, i, &owner);
            tx.inputs[i].signature_script = ScriptBuilder::new().add_data(&s)?.drain();
        }
        tx.finalize();
        // Repère de survie : bloc de tête AVANT diffusion, pour retrouver le coffre avec le seul nœud.
        let repere = noeud::tete(&c).await?;
        let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?;
        noeud::ecrire_repere(&state_path(), &repere)?;
        println!("Coffre déployé : {} TKAS, budget {} TKAS, lignée {}", fund as f64 / 1e8, capacite as f64 / 1e8, cov);
        println!("Transaction : {}", explorer(&txid.to_string()));
        let e0 = Etat { txid: txid.to_string(), index: 0, valeur: fund, tokens: capacite, last_daa: now, cov_id: cov.to_string() };
        save_state(&e0)?;
        fs::write(origine_path(), serde_json::to_string_pretty(&e0)?)?; // à garder par le propriétaire
        liberer(&c).await?;
        Ok(txid.to_string())
}

/// Ajoute des fonds au coffre (même lignée, état inchangé).
/// Paiement de l'agent (côté agent) : seule la clé publique du propriétaire est connue. L'état local
/// périmé est rattrapé par le mode survie (`instants`, puis `retrouver_coffre`).
pub(crate) async fn payer_agent(owner_pk: &[u8], agent: &Keypair, montant: i64, destinataire: &Address, sans_verif: bool) -> Res<String> {
    if load_state().is_ok() {
        return payer_agent_ancien(owner_pk, agent, montant, destinataire, sans_verif).await;
    }
    coffre::payer(owner_pk, agent, montant.max(0) as u64, pay_to_address_script(destinataire), sans_verif, 0).await
}

/// Paiement depuis un ancien coffre v0.5.1.
async fn payer_agent_ancien(owner_pk: &[u8], agent: &Keypair, montant: i64, destinataire: &Address, sans_verif: bool) -> Res<String> {
    let c = connect_silencieux().await?;
    let e = match load_state() {
        Ok(e) if creation_coffre(&c, owner_pk, agent, &e).await.is_ok() => e,
        _ => retrouver_coffre(&c, owner_pk, agent).await?,
    };
    let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
    let disponible = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa).available(now, creation);
    println!("Budget disponible : {} unités, paiement demandé : {} unités", disponible, montant);
    if !sans_verif && (montant + FEE as i64 > disponible || montant > regles_ancien().plafond) {
        return Err("refusé localement : dépasse le budget disponible ou le plafond par achat (--sans-verif pour laisser le réseau trancher)".into());
    }
    // Sans vérification locale (démo du refus) : l'agent encode honnêtement l'état qui en résulterait,
    // même impossible (budget négatif) ; c'est le réseau, par le contrat, qui refuse.
    let (tx, suivant) = if sans_verif {
        attaques::tx_agent(owner_pk, agent, &pay_to_address_script(destinataire), &e, montant, pay_to_address_script(destinataire), now, creation, attaques::Triche::Aucune)?
    } else {
        build_pay_pk(owner_pk, agent, &e, montant, pay_to_address_script(destinataire), now, creation)?
    };
    let r = c.submit_transaction(garde_diffusion(&tx)?, false).await;
    liberer(&c).await?;
    match r {
        Ok(txid) => {
            save_state(&suivant)?;
            Ok(txid.to_string())
        }
        Err(err) => Err(format!("REFUSÉ par le réseau : {err}").into()),
    }
}

pub async fn recharger(owner: &Keypair, agent: &Keypair, add: u64) -> Res<String> {
    if load_state().is_ok() {
        return recharger_ancien(owner, agent, add).await;
    }
    coffre::recharger(owner, agent, add).await
}

async fn recharger_ancien(owner: &Keypair, agent: &Keypair, add: u64) -> Res<String> {
        // Le propriétaire ajoute des fonds au coffre en restant dans la même lignée (état inchangé).
        // Un agent connecté paie de son côté : l'état local peut être périmé ; on retrouve alors le
        // coffre courant sur le registre public (même mécanisme que le gel).
        let c = connect().await?;
        let e = match load_state() {
            Ok(e) if creation_coffre(&c, &xonly(owner), agent, &e).await.is_ok() => e,
            _ => retrouver_coffre(&c, &xonly(owner), agent).await?,
        };
        let cov = e.covenant()?;
        let vault = compile(&owner, &agent, e.tokens, e.last_daa)?;
        let utxos = c.get_utxos_by_addresses(vec![address(&owner)]).await?;
        let mut picked = vec![];
        let mut total = 0u64;
        for u in utxos.into_iter().take(20) {
            total += u.utxo_entry.amount;
            picked.push(u);
            if total >= add + 3 * FEE {
                break;
            }
        }
        let fee = FEE * (picked.len() as u64 + 1);
        if total < add + fee {
            return Err("solde du propriétaire insuffisant".into());
        }
        let txid_in = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&e.txid)?.as_slice())?);
        let mut entries = vec![UtxoEntry::new(e.valeur, vault_spk(&vault), 0, false, Some(cov))];
        let mut inputs = vec![TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid_in, e.index), vec![], 0, CB_VAULT)];
        for u in &picked {
            entries.push(u.utxo_entry.clone().into());
            inputs.push(TransactionInput::new_with_compute_budget(u.outpoint.clone().into(), vec![], 0, CB_P2PK));
        }
        let new_value = e.valeur + add;
        let mut outputs = vec![TransactionOutput {
            value: new_value,
            script_public_key: vault_spk(&vault),
            covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }),
        }];
        let change = total - add - fee;
        if change > 0 {
            outputs.push(TransactionOutput::new(change, pay_to_address_script(&address(&owner))));
        }
        let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        let s0 = sign(&tx, &entries, 0, &owner);
        let ss0 = vault_sigscript(&vault, "ownerControl", &[s0.into()])?;
        let mut sigs = vec![ss0];
        for i in 1..tx.inputs.len() {
            let s = sign(&tx, &entries, i, &owner);
            sigs.push(ScriptBuilder::new().add_data(&s)?.drain());
        }
        for (i, ss) in sigs.into_iter().enumerate() {
            tx.inputs[i].signature_script = ss;
        }
        tx.finalize();
        let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?;
        println!("Coffre rechargé de {} TKAS (même lignée) : {}", add as f64 / 1e8, explorer(&txid.to_string()));
        save_state(&Etat { txid: txid.to_string(), index: 0, valeur: new_value, ..e })?;
        liberer(&c).await?;
        Ok(txid.to_string())
}

/// Gel prioritaire du coffre par le propriétaire (voir la commande `recuperer`).
/// Gel : coffre v0.6 (toutes les pièces de l'adresse), ou ancien coffre v0.5.1 / v0.5 / v0.4.
pub async fn geler(owner: &Keypair, agent: &Keypair, sans_etat: bool, version: u8) -> Res<String> {
    if version == 0 && (coffre::charger().is_some() || (load_state().is_err() && !std::path::Path::new(&origine_path()).exists())) {
        return coffre::geler(owner, agent).await;
    }
    geler_ancien(owner, agent, sans_etat, version).await
}

async fn geler_ancien(owner: &Keypair, agent: &Keypair, sans_etat: bool, version: u8) -> Res<String> {
        if version == 4 || version == 5 {
            SOURCE_ANCIENNE.store(version, std::sync::atomic::Ordering::Relaxed);
        }
        let c = connect().await?;
        // Gel prioritaire : frais toujours au-dessus du plafond de frais de l'agent (maxFee), en
        // escalade ; si un paiement de l'agent occupe déjà la sortie dans la file d'attente, le gel
        // le REMPLACE ; si le paiement de l'agent passe quand même, le coffre a bougé : on le
        // retrouve et on recommence. Avant chaque tentative, le coffre courant est (re)localisé :
        // état local, sinon mode survie (--sans-etat pour forcer).
        let frais_gel = (2 * MAX_FEE as u64).max(FEE);
        let adresse_proprio = address(&owner);
        let mut gele = false;
        let mut id_gel = String::new();
        for tentative in 1..=6u64 {
            let local = if tentative == 1 && sans_etat { None } else { load_state().ok() };
            let e = match local {
                Some(e) if version == 4 || creation_coffre(&c, &xonly(&owner), &agent, &e).await.is_ok() => e,
                _ => {
                    println!("État local absent ou périmé : recherche du coffre courant (mode survie)…");
                    match retrouver_coffre(&c, &xonly(&owner), &agent).await {
                        Ok(e) => e,
                        Err(err) if tentative > 1 => {
                            println!("tentative {tentative} : {err} ; nouvel essai dans 3 s");
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            // escalade plafonnée : on garde au moins 0,05 TKAS de sortie (sinon trop lourde, KIP-9)
            let frais = (frais_gel * tentative).min(e.valeur.saturating_sub(5_000_000)).max(FEE);
            let vault = compile(&owner, &agent, e.tokens, e.last_daa)?;
            let entry = UtxoEntry::new(e.valeur, vault_spk(&vault), 0, false, e.covenant().ok());
            let txid_in = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&e.txid)?.as_slice())?);
            let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid_in, e.index), vec![], 0, CB_VAULT);
            let outputs = vec![TransactionOutput::new(e.valeur.checked_sub(frais).ok_or("coffre trop petit pour les frais du gel")?, pay_to_address_script(&adresse_proprio))];
            let mut tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
            let s = sign(&tx, &[entry], 0, &owner);
            tx.inputs[0].signature_script = vault_sigscript(&vault, "ownerControl", &[s.into()])?;
            tx.finalize();
            let id = tx.id();
            let envoi = match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    // sortie déjà prise par un paiement en attente : remplacement (frais plus élevés)
                    println!("tentative {tentative} : {err} ; remplacement du paiement en attente");
                    c.submit_transaction_replacement(garde_diffusion(&tx)?).await.map(|_| ()).map_err(|e| e.to_string())
                }
            };
            if let Err(err) = envoi {
                println!("tentative {tentative} refusée : {err}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
            // confirmation : la sortie du gel apparaît sur l'adresse du propriétaire
            for _ in 0..20 {
                let u = c.get_utxos_by_addresses(vec![adresse_proprio.clone()]).await?;
                if u.iter().any(|x| x.outpoint.transaction_id == id) {
                    gele = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            if gele {
                id_gel = id.to_string();
                println!("Coffre récupéré par le propriétaire : {} (frais {} TKAS, tentative {tentative})", explorer(&id.to_string()), frais as f64 / 1e8);
                break;
            }
            println!("tentative {tentative} : gel non confirmé (l'agent a peut-être payé avant) ; on relocalise le coffre");
        }
        if !gele {
            return Err("gel non confirmé après 6 tentatives : relancer recuperer".into());
        }
        let _ = fs::remove_file(state_path());
        liberer(&c).await?;
        Ok(id_gel)
}

// Deux fils d'exécution au plus : Plafond attend surtout le réseau, il n'a pas besoin de tous les cœurs.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Res<()> {
    sobriete::regler_memoire();
    let dossier_compte = env::var("PLAFOND_DOSSIER").unwrap_or_else(|_| "compte".into());
    sobriete::nettoyer(&[std::path::Path::new("."), std::path::Path::new(&dossier_compte)]);
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("aide");
    if matches!(cmd, "plafond" | "console" | "demo" | "routeur") {
        sobriete::priorite_basse();
    }

    if cmd == "empreintes" {
        print!("{}", empreintes()?);
        return Ok(());
    }

    if cmd == "masse" {
        print!("{}", masse::rapport(FEE));
        return Ok(());
    }

    if cmd == "relais-exemple" {
        // Hors ligne, clés de démonstration publiques : produit une réponse 402 et le paiement exact
        // correspondant, pour les faire vérifier par le code de kaspa-x402 (`tests/juge-kaspa-x402`).
        print!("{}", serde_json::to_string_pretty(&relais::exemple()?)?);
        return Ok(());
    }

    if cmd == "relais-payer" {
        // Fournisseur de fonds du client @kaspa-x402/client : lit {"request", "utxos"} sur l'entrée
        // standard, écrit un ExactTransactionPaymentResult. Clé : PORTE_MONNAIE_SK (testnet),
        // ou `--demo` pour la clé de démonstration publique [2;32]. Rien n'est diffusé.
        let porte_monnaie = if args.iter().any(|a| a == "--demo") {
            Keypair::from_seckey_slice(secp256k1::SECP256K1, &[2u8; 32])?
        } else {
            keypair_from_env("PORTE_MONNAIE_SK")?
        };
        let liste = |var: &str| -> Vec<String> {
            env::var(var).map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
        };
        let pol = relais::Politique {
            montant_max: env::var("RELAIS_MAX").ok().and_then(|v| v.parse().ok()).unwrap_or(MAX_PER_PAYMENT as u64),
            destinataires: liste("RELAIS_DESTINATAIRES"),
            origines: liste("RELAIS_ORIGINES"),
        };
        let entree: serde_json::Value = serde_json::from_reader(std::io::stdin())?;
        let pieces = relais::pieces_du_client(entree.get("utxos").ok_or("champ « utxos » absent")?)?;
        let req = entree.get("request").ok_or("champ « request » absent")?;
        print!("{}", relais::payer_pour_le_client(&porte_monnaie, &pieces, req, &pol)?);
        return Ok(());
    }

    if cmd == "pause" {
        let secs: u64 = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(5);
        tokio::time::sleep(Duration::from_secs(secs)).await;
        println!("(pause de {secs} s)");
        return Ok(());
    }
    if cmd == "cles" {
        if env::var("GITHUB_ACTIONS").is_ok() || env::var("CI").is_ok() {
            return Err("commande « cles » interdite en CI : elle afficherait des clés secrètes dans le journal public".into());
        }
        for name in ["OWNER_SK", "AGENT_SK"] {
            let k = Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
            println!("{name}={}", hex::encode(k.secret_bytes()));
        }
        return Ok(());
    }

    if args.iter().any(|a| a == "--forcer-masse") {
        masse::FORCER.store(true, std::sync::atomic::Ordering::Relaxed);
        println!("(refus local KIP-9 désactivé : le réseau tranchera)");
    }
    // Côté agent (sur son serveur) : installer le kit remis par la console, mettre à jour ses secrets,
    // vérifier que tout est lisible. Le code de connexion est saisi au clavier, jamais affiché.
    if cmd == "agent-installer" || cmd == "agent-secrets" || cmd == "agent-verifier" || cmd == "agent-payer" {
        let dossier = env::var("AGENT_DOSSIER").unwrap_or_else(|_| "agent".into());
        match cmd {
            "agent-installer" => {
                let fichier_kit = args.get(2).ok_or("fichier du kit de connexion manquant")?;
                // Saisi au clavier ; AGENT_CODE_CONNEXION seulement pour une démo automatisée (testnet).
                let code = zeroize::Zeroizing::new(match env::var("AGENT_CODE_CONNEXION") {
                    Ok(c) => c,
                    Err(_) => rpassword::prompt_password("Code de connexion : ")?,
                });
                // Installation, vérification (clé et secrets lisibles), puis effacement du fichier du kit ;
                // au moindre échec le kit reste en place pour réessayer.
                let r = connexion::installer_depuis_fichier(fichier_kit, &code, &dossier)?;
                println!("Agent « {} » installé dans {dossier}/ et vérifié (clé lisible par vous seul).", r.nom);
                match r.kit_efface {
                    Ok(()) => println!("Le fichier du kit ({fichier_kit}) a été effacé : il ne sert plus."),
                    Err(e) => println!("Le fichier du kit n'a pas pu être effacé ({e}) : supprimez-le vous-même ({fichier_kit})."),
                }
            }
            "agent-payer" => {
                // L'agent paie depuis son coffre avec sa propre clé (installée par le kit) ; la
                // console n'intervient pas. --sans-verif : laisser le réseau trancher (démo du refus).
                let dest = args.get(2).ok_or("adresse du destinataire manquante")?;
                let montant: i64 = args.get(3).ok_or("montant en sompi manquant")?.parse()?;
                let sans_verif = args.iter().any(|a| a == "--sans-verif");
                let d = std::path::Path::new(&dossier);
                let meta: serde_json::Value = serde_json::from_str(&fs::read_to_string(d.join("agent.json"))?)?;
                let owner_pk = hex::decode(meta["proprietaire"].as_str().ok_or("agent.json : propriétaire absent")?)?;
                let regles: Option<Regles> = serde_json::from_value(meta["regles"].clone()).unwrap_or(None);
                let hexa = zeroize::Zeroizing::new(fs::read_to_string(d.join("agent.key"))?);
                let k = Keypair::from_seckey_slice(secp256k1::SECP256K1, &zeroize::Zeroizing::new(hex::decode(hexa.trim())?))?;
                let destinataire = Address::try_from(dest.as_str()).map_err(|e| format!("adresse invalide : {e}"))?;
                if destinataire.prefix != Prefix::Testnet {
                    return Err("réseau de test uniquement : adresse kaspatest: attendue".into());
                }
                let etat = d.join("etat-coffre.json").to_string_lossy().into_owned();
                let r = avec_coffre(&etat, regles, None, || {
                    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(payer_agent(&owner_pk, &k, montant, &destinataire, sans_verif)))
                });
                match r {
                    Ok(txid) => println!("Paiement accepté par le réseau : {}", explorer(&txid)),
                    Err(e) if e.to_string().starts_with("REFUSÉ") => {
                        println!("Paiement {e}");
                        std::process::exit(2);
                    }
                    Err(e) => return Err(e),
                }
            }
            "agent-secrets" => {
                let n = connexion::maj_secrets(args.get(2).ok_or("fichier de secrets manquant")?, &dossier)?;
                println!("{n} secret(s) mis à jour dans {dossier}/.");
            }
            _ => {
                let l = connexion::verifier(&dossier)?;
                println!("Clé de l'agent : lisible.");
                for (nom, ok) in &l {
                    println!("  secret « {nom} » : {}", if *ok { "lisible" } else { "ILLISIBLE" });
                }
                if l.iter().any(|(_, ok)| !ok) {
                    return Err("au moins un secret est illisible pour cet agent".into());
                }
            }
        }
        return Ok(());
    }
    if cmd == "plafond" {
        // Usage normal : la console s'ouvre verrouillée ; le compte se crée ou s'ouvre dans la page.
        let dossier = env::var("PLAFOND_DOSSIER").unwrap_or_else(|_| "compte".into());
        CONNEXION_PARTAGEE.store(true, std::sync::atomic::Ordering::Relaxed);
        if env::var("PLAFOND_SANS_NAVIGATEUR").is_err() {
            console::OUVRIR_NAVIGATEUR.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let h = tokio::runtime::Handle::current();
        let essai = console::mode_essai(&dossier);
        tokio::task::spawn_blocking(move || if essai { console::lancer_essai(h, dossier) } else { console::lancer_compte(h, dossier) }.map_err(|e| e.to_string())).await??;
        return Ok(());
    }
    if cmd == "cle-creer" || cmd == "cle-info" {
        // Clé du propriétaire chiffrée sur son appareil (option A, non-custodial).
        let chemin = args.get(2).ok_or("chemin du fichier de clé manquant")?;
        let publique = if cmd == "cle-creer" {
            let k = cle::creer(chemin)?;
            println!("Fichier de clé créé : {chemin}");
            println!("Gardez-en une sauvegarde : sans ce fichier ET son mot de passe, le coffre ne peut plus être gelé.");
            xonly(&k)
        } else {
            hex::decode(cle::lire(chemin)?.publique)? // aucun mot de passe : la clé publique est en clair
        };
        println!("Clé publique x-only : {}", hex::encode(&publique));
        println!("Adresse du propriétaire (à alimenter depuis KasWare ou Kastle) : {}", Address::new(Prefix::Testnet, Version::PubKey, &publique));
        return Ok(());
    }
    if cmd == "routeur" {
        // API des agents (voir routeur.rs). Hors démo, le routeur ne charge JAMAIS la clé secrète du
        // propriétaire : seulement sa clé publique (PROPRIETAIRE_PUB) et la clé de l'agent.
        let agent = keypair_from_env("AGENT_SK")?;
        let demo = env::var("ROUTEUR_DEMO").map(|v| v == "1").unwrap_or(false);
        let (owner_pk, demo_cfg) = if demo {
            let owner = keypair_from_env("OWNER_SK")?;
            let vendeur = args.iter().any(|a| a == "--avec-vendeur").then(|| address(&payee(&owner)));
            (xonly(&owner), Some((address(&payee(&owner)), vendeur)))
        } else {
            if env::var("VAULT_PHRASE").is_ok() || env::var("OWNER_SK").is_ok() {
                return Err("routeur hors démo : ne fournir que AGENT_SK et PROPRIETAIRE_PUB, jamais la clé du propriétaire".into());
            }
            let pk = hex::decode(env::var("PROPRIETAIRE_PUB").map_err(|_| "PROPRIETAIRE_PUB manquante (clé publique x-only du propriétaire, hex)")?)?;
            if pk.len() != 32 || secp256k1::XOnlyPublicKey::from_slice(&pk).is_err() {
                return Err("PROPRIETAIRE_PUB invalide (32 octets x-only attendus)".into());
            }
            (pk, None)
        };
        let h = tokio::runtime::Handle::current();
        let cfg = routeur::Config { owner_pk, agent, demo: demo_cfg };
        tokio::task::spawn_blocking(move || routeur::lancer(h, cfg).map_err(|e| e.to_string())).await??;
        return Ok(());
    }

    // Démo sans aucune clé fournie : clés jetables du réseau de test, créées sur place.
    let jetable = cmd == "demo" && ["PROPRIETAIRE_CLE", "VAULT_PHRASE", "OWNER_SK"].iter().all(|v| env::var(v).is_err());
    let (owner, agent) = if jetable { demo::cles_jetables()? } else { (charger_proprietaire()?, keypair_from_env("AGENT_SK")?) };
    let service = payee(&owner);

    match cmd {
        "adresses" => {
            println!("Propriétaire (à alimenter au faucet) : {}", address(&owner));
            println!("Agent                                : {}", address(&agent));
            println!("Service payé par l'agent             : {}", address(&service));
            println!("Porte-monnaie du relais (Kaspa x402) : {}", address(&keypair_from_env("PORTE_MONNAIE_SK")?));
        }
        "pieces-porte-monnaie" => {
            // Pièces du porte-monnaie du relais, au format FundingProviderUtxo de @kaspa-x402/client.
            let pm = address(&keypair_from_env("PORTE_MONNAIE_SK")?);
            let c = connect_silencieux().await?;
            let utxos = c.get_utxos_by_addresses(vec![pm.clone()]).await?;
            let liste: Vec<serde_json::Value> = utxos
                .into_iter()
                .map(|u| {
                    let e: UtxoEntry = u.utxo_entry.into();
                    let mut v = serde_json::json!({
                        "outpoint": { "txid": u.outpoint.transaction_id.to_string(), "index": u.outpoint.index },
                        "amount": e.amount.to_string(),
                        "scriptPublicKey": relais::spk_hex(&e.script_public_key),
                        "address": pm.to_string(),
                    });
                    if let Some(cov) = e.covenant_id {
                        v["covenantId"] = serde_json::Value::String(cov.to_string());
                    }
                    v
                })
                .collect();
            print!("{}", serde_json::Value::Array(liste));
            liberer(&c).await?;
        }
        "relais-test-diffusion" => {
            // Diagnostic : même forme qu'un paiement exact (v0, P2PK), mais vers le propriétaire, diffusée
            // directement pour lire la réponse exacte du nœud.
            let pm = keypair_from_env("PORTE_MONNAIE_SK")?;
            let c = connect().await?;
            let utxos = c.get_utxos_by_addresses(vec![address(&pm)]).await?;
            let pieces: Vec<(TransactionOutpoint, UtxoEntry)> = utxos.into_iter().map(|u| (u.outpoint.into(), u.utxo_entry.into())).collect();
            let (tx, entries) = relais::construire_tx(&pm, &pieces, 20_000_000, pay_to_address_script(&address(&owner)))?;
            if let Some(m) = masse::masses(&tx, &entries) {
                println!("Masses : calcul {} g, transitoire {} g, stockage {} g (engagée {})", m.compute, m.transient, m.storage, tx.storage_mass());
            }
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => println!("Transaction v0 acceptée : {}", explorer(&txid.to_string())),
                Err(err) => println!("Transaction v0 REFUSÉE par le nœud : {err}"),
            }
            liberer(&c).await?;
        }
        "recharger-porte-monnaie" => {
            // Le coffre paie le porte-monnaie du relais, avec les règles du covenant (entrée `pay`).
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let pm = keypair_from_env("PORTE_MONNAIE_SK")?;
            if amount <= 0 {
                return Err("montant invalide".into());
            }
            // Le budget est fait respecter par le réseau : on attend au plus 10 min qu'il soit disponible.
            let txid_s = coffre::payer(&xonly(&owner), &agent, amount as u64, pay_to_address_script(&address(&pm)), false, 600).await?;
            let txid = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&txid_s)?.as_slice())?);
            eprintln!("Coffre → porte-monnaie : {} TKAS : {}", amount as f64 / 1e8, explorer(&txid_s));
            let c = connect_silencieux().await?;
            // Attendre que la pièce soit visible dans l'ensemble des UTXO du nœud.
            for _ in 0..40 {
                let u = c.get_utxos_by_addresses(vec![address(&pm)]).await?;
                if u.iter().any(|x| x.outpoint.transaction_id == txid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            print!("{}", serde_json::json!({ "transactionId": txid.to_string(), "amount": amount.to_string() }));
            liberer(&c).await?;
        }
        "etat" => {
            let c = connect().await?;
            let daa = virtual_daa(&c).await?;
            let utxos = c.get_utxos_by_addresses(vec![address(&owner)]).await?;
            let bal: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("Score DAA du réseau : {daa}");
            println!("Solde du propriétaire : {} TKAS ({} UTXO)", bal as f64 / 1e8, utxos.len());
            match coffre::charger() {
                Some(_) => {
                    let v = coffre::vue(&c, &xonly(&owner), &agent_pk(&agent)).await?;
                    println!("Coffre (cœur {}) {} : {} TKAS en {} pièce(s)", if v.coeur.retour.is_some() { "v0.7" } else { "v0.6" }, v.adresse, v.solde() as f64 / 1e8, v.pieces.len());
                    println!("  disponible maintenant : {} TKAS ; pire cas sur 24 h : {} TKAS", v.immediate() as f64 / 1e8, v.fenetre(JOUR_DAA as u64) as f64 / 1e8);
                    println!("  perte nette depuis la création : {} TKAS (courbe promise : {} TKAS)", v.apports().saturating_sub(v.solde()) as f64 / 1e8, v.courbe(v.now) as f64 / 1e8);
                }
                None if load_state().is_ok() => println!("Ancien coffre v0.5.1 présent : le geler (`recuperer`) puis en créer un nouveau"),
                None => println!("Coffre : pas encore déployé"),
            }
            liberer(&c).await?;
        }
        "deployer" => {
            // `deployer [adresse_de_retour]` : sans adresse, l'adresse du propriétaire (ou PLAFOND_RETOUR).
            match args.get(2) {
                Some(retour) => {
                    coffre::deployer_vers(&owner, &agent, Some(retour)).await?;
                }
                None => {
                    deployer(&owner, &agent).await?;
                }
            }
        }
        "payer" => {
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let no_check = args.iter().any(|a| a == "--sans-verif");
            match coffre::payer(&xonly(&owner), &agent, amount.max(0) as u64, pay_to_address_script(&address(&service)), no_check, 0).await {
                Ok(txid) => println!("Paiement accepté par le réseau : {}", explorer(&txid)),
                Err(err) => {
                    println!("Paiement {err}");
                    std::process::exit(2);
                }
            }
        }
        "sequestre-ouvrir" => {
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let requete = args.get(3).ok_or("requête manquante")?.clone();
            let timeout: i64 = args.get(4).and_then(|a| a.parse().ok()).unwrap_or(sequestre::DEFAULT_TIMEOUT);
            if fs::metadata(SEQUESTRE).is_ok() {
                return Err("un séquestre est déjà ouvert".into());
            }
            let verifier = keypair_from_env("VERIFIER_SK")?;
            let merchant = pay_to_address_script(&address(&service));
            let refund = pay_to_address_script(&address(&owner));
            let art = sequestre::artifact(&merchant, &refund, &verifier, &requete, timeout)?;
            let escrow_spk = pay_to_script_hash_script(&bytecode(&art));
            println!("Commande « {requete} » : {} TKAS mis en séquestre, délai {timeout} blocs (~{} s), contrat de {} octets",
                amount as f64 / 1e8, timeout / 10, sequestre::script_size(&art));
            match coffre::payer(&xonly(&owner), &agent, amount.max(0) as u64, escrow_spk, false, 0).await {
                Ok(txid) => {
                    println!("Séquestre ouvert depuis le coffre : {}", explorer(&txid));
                    let s = sequestre::Sequestre { txid, index: 0, valeur: amount as u64, requete, timeout };
                    fs::write(SEQUESTRE, serde_json::to_string_pretty(&s)?)?;
                }
                Err(err) => {
                    println!("Séquestre {err}");
                    std::process::exit(2);
                }
            }
        }
        "sequestre-reclamer" => {
            let resultat = args.get(2).ok_or("résultat livré manquant")?.clone();
            let fausse = args.iter().any(|a| a == "--fausse-preuve");
            let s: sequestre::Sequestre = serde_json::from_str(&fs::read_to_string(SEQUESTRE).map_err(|_| "aucun séquestre ouvert")?)?;
            let verifier = keypair_from_env("VERIFIER_SK")?;
            let merchant = pay_to_address_script(&address(&service));
            let refund = pay_to_address_script(&address(&owner));
            let art = sequestre::artifact(&merchant, &refund, &verifier, &s.requete, s.timeout)?;
            // Le vérificateur constate la livraison et signe ; en mode fraude, l'agent signe à sa place.
            let signer = if fausse { &agent } else { &verifier };
            let (proof, result_hash) = sequestre::proof(signer, &s, &resultat)?;
            println!("{} preuve de livraison pour « {} » : résultat {}",
                if fausse { "(fraude) FAUSSE" } else { "Vérificateur :" }, s.requete, hex::encode(&result_hash[..8]));
            let tx = sequestre::build_claim(&art, &s, merchant, FEE, proof, result_hash)?;
            let c = connect().await?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Vendeur payé contre preuve de livraison : {}", explorer(&txid.to_string()));
                    fs::remove_file(SEQUESTRE)?;
                }
                Err(err) => println!("Réclamation REFUSÉE par le réseau : {err}"),
            }
            liberer(&c).await?;
        }
        // Ardoise : micropaiements répétés chez UN vendeur, réglés en une seule transaction.
        "ardoise-ouvrir" => {
            let depot: u64 = args.get(2).ok_or("dépôt en sompi manquant")?.parse()?;
            let timeout: i64 = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(ardoise::DEFAULT_TIMEOUT);
            if fs::metadata(ARDOISE).is_ok() {
                return Err("une ardoise est déjà ouverte".into());
            }
            let art = ardoise::artifact(&pay_to_address_script(&address(&service)), &xonly(&service), &pay_to_address_script(&address(&owner)), &agent_pk(&agent), timeout)?;
            let spk = pay_to_script_hash_script(&bytecode(&art));
            println!("Ardoise chez le vendeur {} : dépôt {} TKAS, délai {timeout} blocs (~{} min)", address(&service), depot as f64 / 1e8, timeout / 600);
            match coffre::payer(&xonly(&owner), &agent, depot, spk, false, 2400).await {
                Ok(txid) => {
                    println!("Ardoise ouverte depuis le coffre : {}", explorer(&txid));
                    let o = ArdoiseOuverte { ardoise: ardoise::Ardoise { txid, index: 0, depot, timeout }, total: 0, bon: String::new() };
                    fs::write(ARDOISE, serde_json::to_string_pretty(&o)?)?;
                }
                Err(err) => {
                    println!("Ardoise {err}");
                    std::process::exit(2);
                }
            }
        }
        "ardoise-bon" => {
            // L'agent signe hors chaîne un bon CUMULÉ : rien ne passe sur la chaîne, aucun frais.
            let ajout: i64 = args.get(2).ok_or("montant de l'appel en sompi manquant")?.parse()?;
            let mut o: ArdoiseOuverte = serde_json::from_str(&fs::read_to_string(ARDOISE).map_err(|_| "aucune ardoise ouverte")?)?;
            let total = o.total.checked_add(ajout).filter(|t| ajout > 0 && *t as u64 <= o.ardoise.depot).ok_or("bon refusé : dépasserait le dépôt de l'ardoise")?;
            let sig = ardoise::bon(&agent, &o.ardoise, total)?;
            if !ardoise::bon_valable(&agent_pk(&agent), &o.ardoise, total, &sig) {
                return Err("bon invalide".into());
            }
            o.total = total;
            o.bon = hex::encode(&sig);
            fs::write(ARDOISE, serde_json::to_string_pretty(&o)?)?;
            println!("Bon signé hors chaîne : total dû {} TKAS sur {} (aucune transaction)", total as f64 / 1e8, o.ardoise.depot as f64 / 1e8);
        }
        "ardoise-clore" => {
            let o: ArdoiseOuverte = serde_json::from_str(&fs::read_to_string(ARDOISE).map_err(|_| "aucune ardoise ouverte")?)?;
            if o.total <= 0 {
                return Err("aucun bon à encaisser : laisser le délai passer puis rembourser".into());
            }
            if !ardoise::encaissable(&o.ardoise, o.total, FEE) {
                // R60 : sous le seuil, la part du vendeur pèserait trop lourd (masse de stockage) ou ne couvrirait pas les frais.
                return Err("clôture impossible pour l'instant : le total dû est trop petit pour être encaissé (frais et masse minimale)".into());
            }
            let art = ardoise::artifact(&pay_to_address_script(&address(&service)), &xonly(&service), &pay_to_address_script(&address(&owner)), &agent_pk(&agent), o.ardoise.timeout)?;
            let tx = ardoise::build_close(&art, &o.ardoise, &service, pay_to_address_script(&address(&owner)), hex::decode(&o.bon)?, o.total, FEE)?;
            let c = connect().await?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Ardoise close par le vendeur : {} TKAS encaissés, le reste revient au propriétaire : {}", o.total as f64 / 1e8, explorer(&txid.to_string()));
                    fs::remove_file(ARDOISE)?;
                }
                Err(err) => println!("Clôture REFUSÉE par le réseau : {err}"),
            }
            liberer(&c).await?;
        }
        "ardoise-rembourser" => {
            let o: ArdoiseOuverte = serde_json::from_str(&fs::read_to_string(ARDOISE).map_err(|_| "aucune ardoise ouverte")?)?;
            let art = ardoise::artifact(&pay_to_address_script(&address(&service)), &xonly(&service), &pay_to_address_script(&address(&owner)), &agent_pk(&agent), o.ardoise.timeout)?;
            let tx = ardoise::build_refund(&art, &o.ardoise, pay_to_address_script(&address(&owner)), FEE)?;
            let c = connect().await?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Ardoise remboursée au propriétaire (pas de clôture dans le délai) : {}", explorer(&txid.to_string()));
                    fs::remove_file(ARDOISE)?;
                }
                Err(err) => println!("Remboursement REFUSÉ par le réseau (délai pas écoulé ?) : {err}"),
            }
            liberer(&c).await?;
        }
        "sequestre-rembourser" => {
            let s: sequestre::Sequestre = serde_json::from_str(&fs::read_to_string(SEQUESTRE).map_err(|_| "aucun séquestre ouvert")?)?;
            let verifier = keypair_from_env("VERIFIER_SK")?;
            let merchant = pay_to_address_script(&address(&service));
            let refund = pay_to_address_script(&address(&owner));
            let art = sequestre::artifact(&merchant, &refund, &verifier, &s.requete, s.timeout)?;
            let tx = sequestre::build_refund(&art, &s, refund, FEE)?;
            let c = connect().await?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Séquestre remboursé au propriétaire (pas de livraison) : {}", explorer(&txid.to_string()));
                    fs::remove_file(SEQUESTRE)?;
                }
                Err(err) => println!("Remboursement REFUSÉ par le réseau : {err}"),
            }
            liberer(&c).await?;
        }
        "attaque" => {
            // Testnet uniquement : l'agent compromis attaque son propre coffre ; le réseau doit rejeter.
            let quoi = args.get(2).map(String::as_str).unwrap_or("tout");
            let attaquant = keypair_from_env("ATTAQUANT_SK")?;
            if !attaques::batterie(&xonly(&owner), &agent, &attaquant, quoi).await? {
                return Err("au moins une attaque n'a pas eu le résultat attendu".into());
            }
        }
        "course-gel" | "course-recharge" => {
            // Testnet uniquement : deux transactions sur la même pièce, en même temps (course.rs).
            let ok = if cmd == "course-gel" { course::gel(&owner, &agent).await? } else { course::recharge(&owner, &agent).await? };
            if !ok {
                return Err("la course n'a pas eu le résultat attendu".into());
            }
        }
        "tableau" => {
            println!("{}", serde_json::to_string_pretty(&console::tableau_json(&owner, &agent).await?)?);
        }
        "demo" => {
            demo::lancer(owner, agent).await?;
        }
        "console" => {
            // Console du propriétaire, sur SON ordinateur (127.0.0.1) ; la clé est déjà déverrouillée.
            CONNEXION_PARTAGEE.store(true, std::sync::atomic::Ordering::Relaxed);
            let h = tokio::runtime::Handle::current();
            let (o, a) = (owner, agent);
            tokio::task::spawn_blocking(move || console::lancer(h, o, a).map_err(|e| e.to_string())).await??;
        }
        "retrouver" => {
            let c = connect().await?;
            retrouver_coffre(&c, &xonly(&owner), &agent).await?;
            liberer(&c).await?;
        }
        "recuperer" | "recuperer-v04" | "recuperer-v05" => {
            let version = match cmd { "recuperer-v04" => 4, "recuperer-v05" => 5, _ => 0 };
            geler(&owner, &agent, args.iter().any(|a| a == "--sans-etat"), version).await?;
        }
        "recharger" => {
            let add: u64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            recharger(&owner, &agent, add).await?;
        }
        "demo-x402" => {
            x402::demo(&owner, &agent).await?;
        }
        _ => {
            println!("Commandes : cles | adresses | etat | deployer [adresse_retour] | payer <sompi> [--sans-verif] | recharger <sompi> | recuperer | ardoise-ouvrir <sompi> | ardoise-bon <sompi> | ardoise-clore | ardoise-rembourser | demo-x402");
        }
    }
    Ok(())
}

/// Annonce la connexion au réseau une seule fois par adresse de nœud : les interrogations répétées restent silencieuses.
fn annoncer_connexion(url: &str, erreur: bool) {
    static DEJA: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    let mut d = DEJA.lock().unwrap_or_else(|e| e.into_inner());
    if d.as_deref() == Some(url) { return; }
    *d = Some(url.to_string());
    if erreur { eprintln!("Connecté au testnet-10 : {url}") } else { println!("Connecté au testnet-10 : {url}") }
}

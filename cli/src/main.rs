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
//!   deployer              crée le coffre (couloir 0) avec les fonds du propriétaire
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
#[cfg_attr(not(test), allow(dead_code))]
mod attaques;
mod cle;
mod console;
mod retrouver;
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
const SILVERSCRIPT_REV: &str = "443d519e6688fa03d24c69432763b13e6abe4486";

// Réglages du coffre de test (en sompi : 1 KAS = 100 000 000 sompi).
const CAPACITY: i64 = 200_000_000; // 2 TKAS de budget
const REFILL: i64 = 36_000; // recharge complète en ~1 h (10 DAA/s)
const MAX_PER_PAYMENT: i64 = 50_000_000; // 0,5 TKAS max par paiement
const MAX_FEE: i64 = 3_000_000; // frais max autorisés par paiement (0,03 TKAS)
const FEE: u64 = 1_500_000; // frais par entrée (le testnet exige 100 sompi par unité de masse)
const FUND: u64 = 500_000_000; // 5 TKAS déposés dans le coffre
const LANE: i64 = 0;
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
            agent: hex::encode(xonly(agent)),
            lane: LANE,
            capacity: CAPACITY,
            refill_period: REFILL,
            max_per_payment: MAX_PER_PAYMENT,
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
    let mut r = String::new();
    r.push_str("# Empreintes reproductibles (blake2b-256). Régénérer : vault-cli empreintes > contracts/EMPREINTES.txt\n");
    r.push_str(&format!("compilateur silverscript : {}\n", SILVERSCRIPT_REV));
    r.push_str(&format!("source agent_budget.sil : {}\n", b2(SOURCE.as_bytes())));
    r.push_str(&format!("source delivery_escrow.sil : {}\n", b2(sequestre::SOURCE.as_bytes())));
    for (name, a) in [("AgentBudget (paramètres de référence)", &vault), ("DeliveryEscrow (paramètres de référence)", &escrow)] {
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

fn state_path() -> String {
    env::var("ETAT").unwrap_or_else(|_| "testnet/etat-coffre.json".into())
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
pub async fn retrouver_coffre(c: &KaspaRpcClient, owner_pk: &[u8], agent: &Keypair) -> Res<Etat> {
    let origine: Etat = serde_json::from_str(&fs::read_to_string(origine_path()).map_err(|_| "origine du coffre absente : impossible de le retrouver")?)?;
    let (pk, ag) = (owner_pk.to_vec(), agent.clone());
    let (issue, sauts) = tokio::task::spawn_blocking(move || retrouver::retrouver(&retrouver::Rest::depuis_env(), &pk, &ag, &origine).map_err(|e| e.to_string())).await??;
    match issue {
        retrouver::Issue::Ferme { txid } => Err(format!("coffre déjà fermé par le propriétaire (transaction {txid})").into()),
        retrouver::Issue::Courant(mut e) => {
            e.valeur = montant_coffre(c, owner_pk, agent, &e).await?; // le nœud fait foi, pas l'indexeur
            creation_coffre(c, owner_pk, agent, &e).await.map_err(|_| "l'indexeur indique un coffre que le nœud ne connaît pas (non confirmé ou indexeur en retard) : réessayer")?;
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

pub async fn connect() -> Res<KaspaRpcClient> {
    let net = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let client = KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, None, Some(Resolver::default()), Some(net), None)?;
    let opts = ConnectOptions {
        block_async_connect: true,
        strategy: ConnectStrategy::Fallback,
        connect_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    client.connect(Some(opts)).await?;
    println!("Connecté au testnet-10 : {}", client.url().unwrap_or_default());
    Ok(client)
}

/// Connexion sans message sur la sortie standard (les commandes du relais y écrivent du JSON).
pub async fn connect_silencieux() -> Res<KaspaRpcClient> {
    let net = NetworkId::with_suffix(NetworkType::Testnet, 10);
    let client = KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, None, Some(Resolver::default()), Some(net), None)?;
    let opts = ConnectOptions {
        block_async_connect: true,
        strategy: ConnectStrategy::Fallback,
        connect_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };
    client.connect(Some(opts)).await?;
    eprintln!("Connecté au testnet-10 : {}", client.url().unwrap_or_default());
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

/// Crée un coffre (paramètres de test actuels) ; renvoie l'identifiant de transaction.
pub async fn deployer(owner: &Keypair, agent: &Keypair) -> Res<String> {
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
            if total >= FUND + 2 * FEE + 100_000_000 {
                break;
            }
        }
        if total < FUND + FEE {
            return Err(format!("solde insuffisant : {} TKAS, il en faut {}", total as f64 / 1e8, (FUND + FEE) as f64 / 1e8).into());
        }
        let vault = compile(&owner, &agent, CAPACITY, now)?;
        let entries: Vec<UtxoEntry> = picked.iter().map(|u| u.utxo_entry.clone().into()).collect();
        let inputs: Vec<TransactionInput> =
            picked.iter().map(|u| TransactionInput::new_with_compute_budget(u.outpoint.clone().into(), vec![], 0, CB_P2PK)).collect();
        let fee = FEE * picked.len() as u64;
        // Genèse de la lignée (KIP-20) : identifiant calculé depuis la première entrée et la sortie du coffre.
        let mut vault_out = TransactionOutput::new(FUND, vault_spk(&vault));
        let cov = covenant_id(inputs[0].previous_outpoint, std::iter::once((0u32, &vault_out)));
        vault_out.covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: cov });
        let mut outputs = vec![vault_out];
        let change = total - FUND - fee;
        if change > 0 {
            outputs.push(TransactionOutput::new(change, pay_to_address_script(&address(&owner))));
        }
        let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
        for i in 0..tx.inputs.len() {
            let s = sign(&tx, &entries, i, &owner);
            tx.inputs[i].signature_script = ScriptBuilder::new().add_data(&s)?.drain();
        }
        tx.finalize();
        let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?;
        println!("Coffre déployé : {} TKAS, budget {} TKAS, lignée {}", FUND as f64 / 1e8, CAPACITY as f64 / 1e8, cov);
        println!("Transaction : {}", explorer(&txid.to_string()));
        let e0 = Etat { txid: txid.to_string(), index: 0, valeur: FUND, tokens: CAPACITY, last_daa: now, cov_id: cov.to_string() };
        save_state(&e0)?;
        fs::write(origine_path(), serde_json::to_string_pretty(&e0)?)?; // à garder par le propriétaire
        c.disconnect().await?;
        Ok(txid.to_string())
}

/// Ajoute des fonds au coffre (même lignée, état inchangé).
pub async fn recharger(owner: &Keypair, agent: &Keypair, add: u64) -> Res<String> {
        // Le propriétaire ajoute des fonds au coffre en restant dans la même lignée (état inchangé).
        let e = load_state()?;
        let cov = e.covenant()?;
        let c = connect().await?;
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
        c.disconnect().await?;
        Ok(txid.to_string())
}

/// Gel prioritaire du coffre par le propriétaire (voir la commande `recuperer`).
pub async fn geler(owner: &Keypair, agent: &Keypair, sans_etat: bool, version: u8) -> Res<String> {
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
        c.disconnect().await?;
        Ok(id_gel)
}

#[tokio::main]
async fn main() -> Res<()> {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("aide");

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

    let owner = charger_proprietaire()?;
    let agent = keypair_from_env("AGENT_SK")?;
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
            c.disconnect().await?;
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
            c.disconnect().await?;
        }
        "recharger-porte-monnaie" => {
            // Le coffre paie le porte-monnaie du relais, avec les règles du covenant (entrée `pay`).
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let pm = keypair_from_env("PORTE_MONNAIE_SK")?;
            let e = load_state()?;
            let c = connect_silencieux().await?;
            let (now, creation) = instants(&c, &xonly(&owner), &agent, &e).await?;
            let available = VaultParams::ours(&owner, &agent, e.tokens, e.last_daa).available(now, creation);
            if amount + FEE as i64 > available || amount > MAX_PER_PAYMENT {
                return Err(format!("coffre : budget épuisé ou plafond dépassé ({available} sompi disponibles)").into());
            }
            let (tx, next_state) = build_pay(&owner, &agent, &e, amount, pay_to_address_script(&address(&pm)), now, creation)?;
            let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?;
            eprintln!("Coffre → porte-monnaie : {} TKAS : {}", amount as f64 / 1e8, explorer(&txid.to_string()));
            save_state(&next_state)?;
            // Attendre que la pièce soit visible dans l'ensemble des UTXO du nœud.
            for _ in 0..40 {
                let u = c.get_utxos_by_addresses(vec![address(&pm)]).await?;
                if u.iter().any(|x| x.outpoint.transaction_id == txid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            print!("{}", serde_json::json!({ "transactionId": txid.to_string(), "amount": amount.to_string() }));
            c.disconnect().await?;
        }
        "etat" => {
            let c = connect().await?;
            let daa = virtual_daa(&c).await?;
            let utxos = c.get_utxos_by_addresses(vec![address(&owner)]).await?;
            let bal: u64 = utxos.iter().map(|u| u.utxo_entry.amount).sum();
            println!("Score DAA du réseau : {daa}");
            println!("Solde du propriétaire : {} TKAS ({} UTXO)", bal as f64 / 1e8, utxos.len());
            match load_state() {
                Ok(e) => {
                    // v0.5 : recharge comptée depuis l'inscription réelle du coffre (0 s'il n'est pas confirmé).
                    let avail = match creation_coffre(&c, &xonly(&owner), &agent, &e).await {
                        Ok(cr) => VaultParams::ours(&owner, &agent, e.tokens, e.last_daa).available(daa.saturating_sub(DAA_MARGIN) as i64, cr),
                        Err(_) => 0,
                    };
                    println!(
                        "Coffre : {} TKAS, budget disponible ~{} TKAS (sortie {}:{})",
                        e.valeur as f64 / 1e8,
                        avail as f64 / 1e8,
                        e.txid,
                        e.index
                    );
                }
                Err(_) => println!("Coffre : pas encore déployé"),
            }
            c.disconnect().await?;
        }
        "deployer" => {
            deployer(&owner, &agent).await?;
        }
        "payer" => {
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let no_check = args.iter().any(|a| a == "--sans-verif");
            let e = load_state()?;
            let c = connect().await?;
            let (now, creation) = instants(&c, &xonly(&owner), &agent, &e).await?;
            let available = VaultParams::ours(&owner, &agent, e.tokens, e.last_daa).available(now, creation);
            println!("Budget disponible : {} TKAS, paiement demandé : {} TKAS", available as f64 / 1e8, amount as f64 / 1e8);
            if !no_check && (amount + FEE as i64 > available || amount > MAX_PER_PAYMENT) {
                return Err("refusé localement : dépasse le budget ou le plafond par paiement (--sans-verif pour laisser le réseau trancher)".into());
            }
            let (tx, next_state) = build_pay(&owner, &agent, &e, amount, pay_to_address_script(&address(&service)), now, creation)?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Paiement accepté par le réseau : {}", explorer(&txid.to_string()));
                    save_state(&next_state)?;
                }
                Err(err) => {
                    println!("Paiement REFUSÉ par le réseau : {err}");
                    std::process::exit(2);
                }
            }
            c.disconnect().await?;
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
            let e = load_state()?;
            let c = connect().await?;
            let (now, creation) = instants(&c, &xonly(&owner), &agent, &e).await?;
            println!("Commande « {requete} » : {} TKAS mis en séquestre, délai {timeout} blocs (~{} s), contrat de {} octets",
                amount as f64 / 1e8, timeout / 10, sequestre::script_size(&art));
            let (tx, next_state) = build_pay(&owner, &agent, &e, amount, escrow_spk, now, creation)?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(txid) => {
                    println!("Séquestre ouvert depuis le coffre : {}", explorer(&txid.to_string()));
                    save_state(&next_state)?;
                    let s = sequestre::Sequestre { txid: txid.to_string(), index: 0, valeur: amount as u64, requete, timeout };
                    fs::write(SEQUESTRE, serde_json::to_string_pretty(&s)?)?;
                }
                Err(err) => {
                    println!("Séquestre REFUSÉ par le réseau : {err}");
                    std::process::exit(2);
                }
            }
            c.disconnect().await?;
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
            let (proof, result_hash) = sequestre::proof(signer, &s.requete, &resultat);
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
            c.disconnect().await?;
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
            c.disconnect().await?;
        }
        "attaque" => {
            // Testnet uniquement : l'agent compromis attaque son propre coffre ; le réseau doit rejeter.
            let quoi = args.get(2).map(String::as_str).unwrap_or("tout");
            let attaquant = keypair_from_env("ATTAQUANT_SK")?;
            if !attaques::batterie(&xonly(&owner), &agent, &attaquant, quoi).await? {
                return Err("au moins une attaque n'a pas eu le résultat attendu".into());
            }
        }
        "tableau" => {
            println!("{}", serde_json::to_string_pretty(&console::tableau_json(&owner, &agent).await?)?);
        }
        "console" => {
            // Console du propriétaire, sur SON ordinateur (127.0.0.1) ; la clé est déjà déverrouillée.
            let h = tokio::runtime::Handle::current();
            let (o, a) = (owner, agent);
            tokio::task::spawn_blocking(move || console::lancer(h, o, a).map_err(|e| e.to_string())).await??;
        }
        "retrouver" => {
            let c = connect().await?;
            retrouver_coffre(&c, &xonly(&owner), &agent).await?;
            c.disconnect().await?;
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
            println!("Commandes : cles | adresses | etat | deployer | payer <sompi> [--sans-verif] | recharger <sompi> | recuperer | demo-x402");
        }
    }
    Ok(())
}

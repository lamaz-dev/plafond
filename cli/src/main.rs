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
mod sequestre;
mod x402;

const SOURCE: &str = include_str!("../../contracts/agent_budget.sil");
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

#[derive(Serialize, Deserialize)]
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
        let zero = hex::encode([0u8; 32]);
        VaultParams {
            asset: ASSET_KAS.into(),
            owner: hex::encode(xonly(owner)),
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
    /// Budget disponible à l'instant `now` (même calcul que le contrat).
    pub fn available(&self, now: i64) -> i64 {
        let elapsed = (now - self.last_daa).clamp(0, self.refill_period);
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
    Ok(compile_to_sil_abi_artifact_with_options(SOURCE, &args, CompileOptions::default())?)
}

fn compile(owner: &Keypair, agent: &Keypair, tokens: i64, last_daa: i64) -> Res<SilAbiArtifact> {
    compile_params(&VaultParams::ours(owner, agent, tokens, last_daa))
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
) -> Res<(Transaction, Etat)> {
    let p = VaultParams::ours(owner, agent, e.tokens, e.last_daa);
    let available = p.available(now);
    let vault = compile_params(&p)?;
    let cov = e.covenant()?;
    let next_tokens = available - amount - FEE as i64; // les frais sont décomptés du budget
    let next = compile(owner, agent, next_tokens, now)?;
    let entry = UtxoEntry::new(e.valeur, vault_spk(&vault), 0, false, Some(cov));
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

pub async fn virtual_daa(c: &KaspaRpcClient) -> Res<u64> {
    Ok(c.get_block_dag_info().await?.virtual_daa_score)
}

pub fn explorer(txid: &str) -> String {
    format!("https://tn10.kaspa.stream/transactions/{txid}")
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
    let owner = keypair_from_env("OWNER_SK")?;
    let agent = keypair_from_env("AGENT_SK")?;
    let service = payee(&owner);

    match cmd {
        "adresses" => {
            println!("Propriétaire (à alimenter au faucet) : {}", address(&owner));
            println!("Agent                                : {}", address(&agent));
            println!("Service payé par l'agent             : {}", address(&service));
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
                    let elapsed = (daa.saturating_sub(DAA_MARGIN) as i64 - e.last_daa).clamp(0, REFILL);
                    let avail = (e.tokens + elapsed * CAPACITY / REFILL).min(CAPACITY);
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
            save_state(&Etat { txid: txid.to_string(), index: 0, valeur: FUND, tokens: CAPACITY, last_daa: now, cov_id: cov.to_string() })?;
            c.disconnect().await?;
        }
        "payer" => {
            let amount: i64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
            let no_check = args.iter().any(|a| a == "--sans-verif");
            let e = load_state()?;
            let c = connect().await?;
            let now = ((virtual_daa(&c).await? - DAA_MARGIN) as i64).max(e.last_daa);
            let elapsed = (now - e.last_daa).min(REFILL);
            let available = (e.tokens + elapsed * CAPACITY / REFILL).min(CAPACITY);
            println!("Budget disponible : {} TKAS, paiement demandé : {} TKAS", available as f64 / 1e8, amount as f64 / 1e8);
            if !no_check && (amount + FEE as i64 > available || amount > MAX_PER_PAYMENT) {
                return Err("refusé localement : dépasse le budget ou le plafond par paiement (--sans-verif pour laisser le réseau trancher)".into());
            }
            let (tx, next_state) = build_pay(&owner, &agent, &e, amount, pay_to_address_script(&address(&service)), now)?;
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
            let now = ((virtual_daa(&c).await? - DAA_MARGIN) as i64).max(e.last_daa);
            println!("Commande « {requete} » : {} TKAS mis en séquestre, délai {timeout} blocs (~{} s), contrat de {} octets",
                amount as f64 / 1e8, timeout / 10, sequestre::script_size(&art));
            let (tx, next_state) = build_pay(&owner, &agent, &e, amount, escrow_spk, now)?;
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
        "recuperer" => {
            let e = load_state()?;
            let c = connect().await?;
            let vault = compile(&owner, &agent, e.tokens, e.last_daa)?;
            let entry = UtxoEntry::new(e.valeur, vault_spk(&vault), 0, false, e.covenant().ok());
            let txid_in = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&e.txid)?.as_slice())?);
            let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid_in, e.index), vec![], 0, CB_VAULT);
            let outputs = vec![TransactionOutput::new(e.valeur - FEE, pay_to_address_script(&address(&owner)))];
            let mut tx = Transaction::new(1, vec![input], outputs, 0, Default::default(), 0, vec![]);
            let s = sign(&tx, &[entry], 0, &owner);
            tx.inputs[0].signature_script = vault_sigscript(&vault, "ownerControl", &[s.into()])?;
            tx.finalize();
            let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?;
            println!("Coffre récupéré par le propriétaire : {}", explorer(&txid.to_string()));
            fs::remove_file(state_path())?;
            c.disconnect().await?;
        }
        "recharger" => {
            // Le propriétaire ajoute des fonds au coffre en restant dans la même lignée (état inchangé).
            let add: u64 = args.get(2).ok_or("montant en sompi manquant")?.parse()?;
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

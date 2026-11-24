//! Profil x402 « covenant-budget » (v0) : un agent paie un service x402 directement depuis
//! son coffre AgentBudget, sans portefeuille intermédiaire.
//!
//! Ce que le vendeur vérifie, et qu'aucun portefeuille d'agent classique ne permet :
//!   1. coffre authentique : le script du coffre, recompilé à partir de ses paramètres publics
//!      et du code source AgentBudget, correspond exactement à la sortie présente sur la chaîne ;
//!   2. solvabilité : le budget restant du coffre (lisible dans son état) couvre le prix,
//!      et le prix respecte le plafond par paiement — vérifié AVANT toute diffusion ;
//!   3. autorisation : la clé agent inscrite dans le coffre a signé ce paiement pour CETTE requête.
//!
//! Transport : en-têtes x402 v2 PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE (base64 JSON).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use kaspa_addresses::{Address, Prefix};
use kaspa_consensus_core::tx::{Transaction, TransactionId, TransactionOutpoint};
use kaspa_txscript::{extract_script_pub_key_address, pay_to_address_script};
use kaspa_wrpc_client::prelude::*;
use secp256k1::{Keypair, Message, XOnlyPublicKey, schnorr::Signature};
use serde_json::{Value, json};
use tokio::runtime::Handle;

use crate::*;

const BINDING: &str = "kaspa-covenant-budget-v0";
const PROFILE: &str = "covenant-budget";
const NETWORK: &str = "kaspa:testnet-10";
const PORT: u16 = 8402;

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn h32(personal: &[u8], data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).personal(personal).hash(data);
    h.as_bytes().try_into().unwrap()
}

fn request_hash(method: &str, url: &str) -> String {
    hex::encode(h32(b"x402cov-request", format!("{method} {url}").as_bytes()))
}

fn auth_digest(txid: &str, req_hash: &str, pay_to: &str, amount: &str, expires_at: u64) -> [u8; 32] {
    h32(b"x402cov-auth-v0", format!("{txid}|{req_hash}|{pay_to}|{amount}|{expires_at}").as_bytes())
}

// ---------------------------------------------------------------------------------------------
// Vendeur
// ---------------------------------------------------------------------------------------------

struct Offer {
    path: &'static str,
    price: u64,
    content: &'static str,
}

const OFFERS: [Offer; 2] = [
    Offer { path: "/meteo-kaspa", price: 20_000_000, content: "Météo du réseau Kaspa : 10 blocs/s, mempool calme, frais bas." },
    Offer { path: "/rapport-premium", price: 100_000_000, content: "Rapport premium (ne devrait jamais être servi à ce coffre)." },
];

fn requirement(offer: &Offer, pay_to: &Address) -> Value {
    json!({
        "scheme": "exact",
        "network": NETWORK,
        "amount": offer.price.to_string(),
        "asset": "KAS",
        "payTo": pay_to.to_string(),
        "maxTimeoutSeconds": 60,
        "extra": {
            "binding": BINDING,
            "profile": PROFILE,
            "paymentFlow": "upfront",
            "finality": "accepted",
            "vaultTemplate": "plafond-coeur-v0.6"
        }
    })
}

fn payment_required(url: &str, offer: &Offer, pay_to: &Address, error: &str) -> String {
    let pr = json!({ "x402Version": 2, "error": error, "resource": { "url": url }, "accepts": [requirement(offer, pay_to)] });
    B64.encode(pr.to_string())
}

/// Appel au nœud avec relances : un nœud public peut couper la connexion WebSocket un instant
/// (observé sur testnet-10, essai 9). Lectures seulement ; la diffusion n'est jamais relancée ici.
macro_rules! relance {
    ($call:expr) => {{
        let mut essai = 0;
        loop {
            match $call.await {
                Ok(v) => break Ok(v),
                Err(_) if essai < 3 => {
                    essai += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                }
                Err(e) => break Err(format!("nœud injoignable après {} essais : {e}", essai + 1)),
            }
        }
    }};
}

/// Vérifie un paiement covenant-budget, le diffuse et attend son acceptation par le réseau.
async fn verify_and_settle(rpc: &KaspaRpcClient, url: &str, offer: &Offer, pay_to: &Address, payload_b64: &str) -> Result<Value, String> {
    let raw = B64.decode(payload_b64).map_err(|_| "en-tête PAYMENT-SIGNATURE illisible")?;
    let pl: Value = serde_json::from_slice(&raw).map_err(|_| "charge utile JSON invalide")?;
    if pl["accepted"] != requirement(offer, pay_to) {
        return Err("conditions acceptées différentes de l'offre".into());
    }
    let p = &pl["payload"];
    if p["type"] != "covenant-budget-transaction" {
        return Err("type de paiement non pris en charge".into());
    }

    // Ordre des contrôles (R12) : d'abord tout ce qui ne coûte rien (forme, prix, plafond,
    // signature de l'agent), ensuite seulement la recompilation et les appels au nœud.

    // a. Paramètres annoncés (lecture seule) : cœur v0.6, quatre paramètres publics.
    let publics: crate::coeur::Publics = serde_json::from_value(p["vault"]["params"].clone()).map_err(|_| "paramètres du coffre invalides")?;
    let txid_in = p["vault"]["outpoint"]["txid"].as_str().ok_or("outpoint manquant")?;
    let index_in = p["vault"]["outpoint"]["index"].as_u64().ok_or("outpoint manquant")? as u32;
    if pl["accepted"]["asset"].as_str() != Some("KAS") {
        return Err("la monnaie de l'offre n'est pas le KAS".into());
    }
    // b. Transaction : dépense bien cette pièce du coffre et paie exactement le prix au vendeur.
    let tx_bytes = hex::decode(p["transaction"].as_str().ok_or("transaction manquante")?).map_err(|_| "transaction illisible")?;
    let mut tx: Transaction = borsh::from_slice(&tx_bytes).map_err(|_| "transaction non décodable")?;
    tx.finalize();
    let txid = tx.id().to_string();
    // Entrée fournie par le client : aucune conversion ne doit pouvoir faire planter le serveur.
    let txid_bytes: [u8; 32] = hex::decode(txid_in).ok().and_then(|v| v.try_into().ok()).ok_or("outpoint invalide")?;
    let expected_in = TransactionOutpoint::new(TransactionId::from_bytes(txid_bytes), index_in);
    if tx.inputs.len() != 1 || tx.inputs[0].previous_outpoint != expected_in || tx.outputs.len() != 2 {
        return Err("transaction mal formée pour ce profil".into());
    }
    // Budget de calcul de l'entrée du coffre : au moins ce que coûte un paiement (11 unités mesurées).
    if tx.inputs[0].compute_commit.compute_budget().unwrap_or(0) < 11 {
        return Err("budget de calcul de l'entrée insuffisant pour un paiement depuis le coffre".into());
    }
    if tx.outputs[0].script_public_key != pay_to_address_script(pay_to) || tx.outputs[0].value != offer.price {
        return Err("la sortie 0 ne paie pas exactement le prix au vendeur".into());
    }

    // c. Plafond par paiement : la capacité du coffre (frais compris).
    let price = offer.price as i64;
    if price >= publics.capacite {
        return Err(format!(
            "refusé avant diffusion : prix {} TKAS ≥ plafond par paiement du coffre ({} TKAS, frais compris)",
            price as f64 / 1e8,
            publics.capacite as f64 / 1e8
        ));
    }
    // c bis. Autorisation de la requête par la clé agent inscrite dans le coffre.
    let a = &p["authorization"];
    let expires = a["expiresAt"].as_u64().ok_or("expiration manquante")?;
    if expires < now_unix() {
        return Err("autorisation expirée".into());
    }
    let req_hash = request_hash("GET", url);
    if p["requestHash"].as_str() != Some(req_hash.as_str()) {
        return Err("paiement destiné à une autre requête".into());
    }
    let digest = auth_digest(&txid, &req_hash, &pay_to.to_string(), &offer.price.to_string(), expires);
    let agent_pk = XOnlyPublicKey::from_slice(&hex::decode(&publics.agent).map_err(|_| "clé agent invalide")?).map_err(|_| "clé agent invalide")?;
    let sig = Signature::from_slice(&hex::decode(a["signature"].as_str().unwrap_or("")).unwrap_or_default()).map_err(|_| "signature invalide")?;
    secp256k1::SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(digest), &agent_pk)
        .map_err(|_| "autorisation : signature de l'agent invalide")?;
    println!("[VENDEUR] autorisation valide : signée par la clé agent du coffre pour cette requête");

    // d. Coffre authentique : script recompilé (mis en cache), pièce présente à son adresse. Le
    // script ne change jamais : l'adresse EST l'identité du coffre, sans lignée à suivre.
    let coeur = publics.coeur().map_err(|e| format!("paramètres du coffre refusés : {e}"))?;
    let spk = cached_spk(&publics)?;
    if tx.outputs[1].script_public_key != spk {
        return Err("la sortie 1 ne revient pas au coffre".into());
    }
    let vault_addr = extract_script_pub_key_address(&spk, Prefix::Testnet).map_err(|_| "adresse de coffre invalide")?;
    let utxos = relance!(rpc.get_utxos_by_addresses(vec![vault_addr.clone()]))?;
    let on_chain = utxos.iter().find(|u| u.outpoint.transaction_id.to_string() == txid_in && u.outpoint.index == index_in && u.utxo_entry.script_public_key == spk);
    let Some(vault_utxo) = on_chain else {
        return Err("coffre non authentique : aucune pièce de coffre Plafond avec ces paramètres n'existe sur la chaîne".into());
    };
    if vault_utxo.utxo_entry.block_daa_score == u64::MAX {
        return Err("pièce du coffre pas encore confirmée".into());
    }
    println!("[VENDEUR] coffre authentique : script Plafond recompilé = pièce on-chain ({} TKAS)", vault_utxo.utxo_entry.amount as f64 / 1e8);

    // e. Solvabilité, avant toute diffusion : la dépense (prix + frais) est permise par l'âge de la
    // pièce, et la transaction annonce un délai que le réseau acceptera.
    let now = relance!(rpc.get_block_dag_info())?.virtual_daa_score;
    let age = now.saturating_sub(vault_utxo.utxo_entry.block_daa_score);
    let spent = vault_utxo.utxo_entry.amount as i64 - tx.outputs[1].value as i64; // prix + frais
    if spent < price || spent > coeur.capacite {
        return Err("dépense de la transaction hors des limites du coffre".into());
    }
    let exige = coeur.attente(spent);
    let seq = tx.inputs[0].sequence;
    if seq & (1 << 63) != 0 || (seq & 0xffff_ffff) < exige {
        return Err("délai annoncé insuffisant : le réseau refuserait ce paiement".into());
    }
    if exige > age {
        return Err(format!("refusé avant diffusion : budget pas encore disponible (encore {} s)", (exige - age) / 10 + 1));
    }
    println!("[VENDEUR] solvable : âge de la pièce {age} ≥ délai exigé {exige} pour {} TKAS", spent as f64 / 1e8);

    // f. Diffusion puis attente de l'acceptation par le réseau.
    rpc.submit_transaction(crate::garde_diffusion(&tx).map_err(|e| e.to_string())?, false).await.map_err(|e| format!("rejetée par le réseau : {e}"))?;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let paid = relance!(rpc.get_utxos_by_addresses(vec![pay_to.clone()]))?;
        if paid.iter().any(|u| u.outpoint.transaction_id.to_string() == txid && u.outpoint.index == 0) {
            println!("[VENDEUR] paiement accepté par le réseau : {}", explorer(&txid));
            return Ok(json!({
                "success": true,
                "transaction": txid,
                "network": NETWORK,
                "payer": vault_utxo.address.as_ref().map(|a| a.to_string()).unwrap_or_default(),
                "amount": offer.price.to_string(),
                "extensions": { "kaspa": { "binding": BINDING, "profile": PROFILE, "finality": "accepted", "paymentOutputIndex": 0 } }
            }));
        }
    }
    Err("paiement diffusé mais pas encore accepté après 30 s".into())
}

/// Cache des scripts déjà recompilés (protège le vendeur contre un déluge de fausses demandes).
fn cached_spk(params: &crate::coeur::Publics) -> Result<kaspa_consensus_core::tx::ScriptPublicKey, String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, kaspa_consensus_core::tx::ScriptPublicKey>>> = OnceLock::new();
    let key = serde_json::to_string(params).map_err(|_| "paramètres invalides")?;
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(spk) = cache.lock().unwrap().get(&key) {
        return Ok(spk.clone());
    }
    let artifact = params.coeur().and_then(|c| c.artifact()).map_err(|e| format!("recompilation impossible : {e}"))?;
    let spk = vault_spk(&artifact);
    let mut c = cache.lock().unwrap();
    if c.len() > 10_000 {
        c.clear();
    }
    c.insert(key, spk.clone());
    Ok(spk)
}

fn serve(handle: Handle, pay_to: Address) {
    let server = tiny_http::Server::http(("127.0.0.1", PORT)).expect("port du vendeur");
    let rpc = handle.block_on(connect()).expect("connexion du vendeur");
    for mut req in server.incoming_requests() {
        let path = req.url().to_string();
        let url = format!("http://127.0.0.1:{PORT}{path}");
        let Some(offer) = OFFERS.iter().find(|o| o.path == path) else {
            let _ = req.respond(tiny_http::Response::from_string("introuvable").with_status_code(404));
            continue;
        };
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let sig = req.headers().iter().find(|h| h.field.equiv("PAYMENT-SIGNATURE")).map(|h| h.value.to_string());
        let header = |k: &str, v: String| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
        let resp = match sig {
            None => {
                println!("[VENDEUR] {path} : paiement requis ({} TKAS)", offer.price as f64 / 1e8);
                tiny_http::Response::from_string("paiement requis")
                    .with_status_code(402)
                    .with_header(header("PAYMENT-REQUIRED", payment_required(&url, offer, &pay_to, "payment required")))
            }
            Some(sig) => match handle.block_on(verify_and_settle(&rpc, &url, offer, &pay_to, &sig)) {
                Ok(settlement) => tiny_http::Response::from_string(offer.content)
                    .with_status_code(200)
                    .with_header(header("PAYMENT-RESPONSE", B64.encode(settlement.to_string()))),
                Err(reason) => {
                    println!("[VENDEUR] {path} : {reason}");
                    tiny_http::Response::from_string(reason.clone())
                        .with_status_code(402)
                        .with_header(header("PAYMENT-REQUIRED", payment_required(&url, offer, &pay_to, &reason)))
                }
            },
        };
        let _ = req.respond(resp);
    }
}

// ---------------------------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------------------------

/// Résultat d'un achat de l'agent, renvoyé par le routeur.
pub struct Achat {
    pub statut: u16,
    pub contenu: String,
    pub montant: i64,
    pub txid: Option<String>,
    pub refus: Option<String>,
}

impl Achat {
    fn refus(montant: i64, raison: impl Into<String>) -> Self {
        Achat { statut: 402, contenu: String::new(), montant, txid: None, refus: Some(raison.into()) }
    }
}

/// Achat normal (contrôles locaux actifs), pour le routeur. `max` : plafond par requête choisi par l'appelant.
pub fn acheter(handle: &Handle, owner_pk: &[u8], agent: &Keypair, url: &str, max: Option<i64>) -> Res<Achat> {
    agent_buy(handle, owner_pk, agent, url, Mode::Normal, max)
}

/// Vendeur de démonstration, lancé dans un fil à part.
pub fn lancer_vendeur(handle: Handle, pay_to: Address) {
    std::thread::spawn(move || serve(handle, pay_to));
}

#[derive(PartialEq)]
enum Mode {
    Normal,
    IgnoreLocalChecks,
    FakeVault,
}

/// Activé par le routeur hors démo : le client HTTP refuse toute adresse interne AU MOMENT DE LA
/// CONNEXION (et pas seulement lors du contrôle préalable), ce qui ferme le « DNS rebinding ».
pub static BLOQUER_INTERNE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Taille maximale d'une réponse de vendeur lue en mémoire.
pub const REPONSE_MAX: u64 = 1024 * 1024;

fn client_http() -> ureq::Agent {
    client_http_delai(Duration::from_secs(30))
}

/// Délai TOTAL de la requête, lecture du corps comprise : un vendeur qui répond goutte à goutte
/// (« slowloris » inversé) ne peut pas bloquer l'agent au-delà.
fn client_http_delai(total: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(5))
        .timeout(total)
        .resolver(|cible: &str| -> std::io::Result<Vec<std::net::SocketAddr>> {
            use std::net::ToSocketAddrs;
            let adresses: Vec<_> = cible.to_socket_addrs()?.collect();
            if BLOQUER_INTERNE.load(std::sync::atomic::Ordering::Relaxed) && (adresses.is_empty() || adresses.iter().any(|a| crate::routeur::ip_interne(a.ip()))) {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "adresse interne refusée"));
            }
            Ok(adresses)
        })
        .build()
}

/// Lit une réponse en refusant tout ce qui dépasse REPONSE_MAX.
fn lire_borne(r: ureq::Response) -> Res<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    r.into_reader().take(REPONSE_MAX + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > REPONSE_MAX {
        return Err("réponse du vendeur trop volumineuse".into());
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn agent_buy(handle: &Handle, owner_pk: &[u8], agent: &Keypair, url: &str, mode: Mode, max: Option<i64>) -> Res<Achat> {
    println!("\n[AGENT] GET {url}");
    let http = client_http();
    let challenge = match http.get(url).call() {
        Err(ureq::Error::Status(402, r)) => r.header("PAYMENT-REQUIRED").ok_or("402 sans PAYMENT-REQUIRED")?.to_string(),
        Ok(r) => return Ok(Achat { statut: r.status(), contenu: lire_borne(r)?, montant: 0, txid: None, refus: None }),
        Err(e) => return Err(format!("requête : {e}").into()),
    };
    let pr: Value = serde_json::from_slice(&B64.decode(challenge)?)?;
    let req = pr["accepts"].as_array().and_then(|a| a.iter().find(|r| r["extra"]["binding"] == BINDING)).ok_or("aucune offre covenant-budget")?.clone();
    let amount: i64 = req["amount"].as_str().unwrap_or("0").parse()?;
    let pay_to = Address::try_from(req["payTo"].as_str().unwrap_or(""))?;
    println!("[AGENT] 402 reçu : {} TKAS à payer à {}", amount as f64 / 1e8, pay_to);

    if let Some(m) = max {
        if amount > m {
            println!("[AGENT] je refuse : prix supérieur au plafond de cette requête");
            return Ok(Achat::refus(amount, format!("prix {amount} sompi supérieur au plafond demandé ({m})")));
        }
    }
    let rpc = handle.block_on(connect())?;
    let vue = handle.block_on(coffre::vue(&rpc, owner_pk, &xonly(agent)));
    handle.block_on(liberer(&rpc))?;
    let vue = vue?;
    let spent = amount as u64 + FEE;
    let prete = vue.pieces.iter().filter(|p| p.valeur > spent && p.creation.is_some_and(|cr| cr + vue.coeur.attente(spent as i64) + 20 <= vue.now)).max_by_key(|p| p.valeur);
    let piece = match (&mode, prete) {
        (_, Some(p)) => p.clone(),
        (&Mode::Normal, None) => {
            let attente = coffre::delai(&vue.coeur, &vue.pieces, vue.now, spent).map(|d| format!(" (disponible dans {} s)", d / 10 + 1)).unwrap_or_default();
            println!("[AGENT] je refuse moi-même : prix hors du budget disponible de mon coffre{attente}");
            return Ok(Achat::refus(amount, format!("hors du budget du coffre : plafond par paiement ou budget disponible dépassé{attente}")));
        }
        (_, None) => vue.pieces.iter().filter(|p| p.creation.is_some()).max_by_key(|p| p.valeur).cloned().ok_or("aucune pièce confirmée dans le coffre")?,
    };
    if mode == Mode::Normal && spent as i64 > vue.coeur.capacite {
        println!("[AGENT] je refuse moi-même : prix au-delà du plafond par paiement");
        return Ok(Achat::refus(amount, "hors du budget du coffre : plafond par paiement dépassé"));
    }
    let art = vue.coeur.artifact()?;
    let tx = crate::coeur::build_pay(&vue.coeur, &art, piece.outpoint, piece.valeur, pay_to_address_script(&pay_to), amount as u64, FEE, agent, None)
        .or_else(|_| {
            // Agent tricheur (tests) : la transaction est construite quand même, le vendeur et le réseau tranchent.
            crate::coeur::build_pay(&crate::coeur::Coeur { capacite: i64::MAX / vue.coeur.periode, ..vue.coeur.clone() }, &art, piece.outpoint, piece.valeur, pay_to_address_script(&pay_to), amount as u64, FEE, agent, Some(vue.now.saturating_sub(piece.creation.unwrap_or(vue.now)).min(u32::MAX as u64)))
        })?;
    let mut params = vue.coeur.publics();
    if mode == Mode::FakeVault {
        params.capacite *= 100; // l'agent ment sur son budget
        println!("[AGENT] (test) j'annonce un faux coffre avec un budget 100 fois plus grand");
    }
    let outpoint = json!({ "txid": piece.outpoint.transaction_id.to_string(), "index": piece.outpoint.index });
    let txid = tx.id().to_string();
    let req_hash = request_hash("GET", url);
    let expires = now_unix() + 60;
    let digest = auth_digest(&txid, &req_hash, &pay_to.to_string(), &amount.to_string(), expires);
    let sig = agent.sign_schnorr(Message::from_digest(digest));
    let payload = json!({
        "x402Version": 2,
        "accepted": req,
        "payload": {
            "type": "covenant-budget-transaction",
            "profile": PROFILE,
            "transaction": hex::encode(borsh::to_vec(&tx)?),
            "vault": { "params": params, "outpoint": outpoint },
            "requestHash": req_hash,
            "authorization": { "version": "x402cov-auth-v0", "expiresAt": expires, "signature": hex::encode(sig.as_ref()) }
        }
    });
    println!("[AGENT] paiement signé depuis le coffre, envoi au vendeur");
    match http.get(url).set("PAYMENT-SIGNATURE", &B64.encode(payload.to_string())).call() {
        Ok(r) => {
            let settlement: Value = serde_json::from_slice(&B64.decode(r.header("PAYMENT-RESPONSE").unwrap_or(""))?)?;
            let content = lire_borne(r)?;
            println!("[AGENT] ✅ contenu reçu : « {content} »");
            let tx = settlement["transaction"].as_str().unwrap_or("?").to_string();
            println!("[AGENT] reçu de paiement : transaction {tx}");
            Ok(Achat { statut: 200, contenu: content, montant: amount, txid: Some(tx), refus: None })
        }
        Err(ureq::Error::Status(402, r)) => {
            let raison = lire_borne(r).unwrap_or_default();
            println!("[AGENT] ❌ refusé par le vendeur : {raison}");
            Ok(Achat::refus(amount, format!("refusé par le vendeur : {raison}")))
        }
        Err(e) => Err(format!("requête : {e}").into()),
    }
}

/// Démo complète sur le testnet-10 : un vendeur x402 local et trois achats de l'agent.
pub async fn demo(owner: &Keypair, agent: &Keypair) -> Res<()> {
    let handle = Handle::current();
    let pay_to = address(&payee(owner));
    println!("Vendeur de démo sur http://127.0.0.1:{PORT}, paiements reçus sur {pay_to}");
    let h = handle.clone();
    std::thread::spawn(move || serve(h, pay_to));
    tokio::time::sleep(Duration::from_secs(3)).await;

    let (o, a) = (xonly(owner), *agent);
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let h = Handle::current();
        let base = format!("http://127.0.0.1:{PORT}");
        println!("\n=== Scénario 1 : achat normal, payé directement depuis le coffre ===");
        agent_buy(&h, &o, &a, &format!("{base}/meteo-kaspa"), Mode::Normal, None).map_err(|e| e.to_string())?;
        println!("\n=== Scénario 2 : prix au-dessus du plafond, le vendeur refuse avant toute diffusion ===");
        agent_buy(&h, &o, &a, &format!("{base}/rapport-premium"), Mode::IgnoreLocalChecks, None).map_err(|e| e.to_string())?;
        println!("\n=== Scénario 3 : l'agent présente un faux coffre, le vendeur le démasque ===");
        agent_buy(&h, &o, &a, &format!("{base}/meteo-kaspa"), Mode::FakeVault, None).map_err(|e| e.to_string())?;
        Ok(())
    })
    .await??;
    Ok(())
}

#[cfg(test)]
mod vendeurs_malveillants {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Faux vendeur local : écrit l'en-tête puis appelle `corps` sur la connexion.
    fn vendeur(entete: &'static str, corps: impl Fn(&mut std::net::TcpStream) + Send + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut tampon = [0u8; 2048];
                let _ = std::io::Read::read(&mut c, &mut tampon);
                let _ = c.write_all(entete.as_bytes());
                corps(&mut c);
            }
        });
        format!("http://127.0.0.1:{port}/ressource")
    }

    #[test]
    fn flux_sans_fin_coupe_a_un_mo() {
        let url = vendeur("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n", |c| {
            let bloc = [b'x'; 16 * 1024];
            while c.write_all(&bloc).is_ok() {}
        });
        let r = client_http_delai(Duration::from_secs(20)).get(&url).call().unwrap();
        let e = lire_borne(r).unwrap_err().to_string();
        assert!(e.contains("trop volumineuse"), "{e}");
    }

    #[test]
    fn reponse_goutte_a_goutte_coupee_par_le_delai() {
        let url = vendeur("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n", |c| {
            for _ in 0..100 {
                if c.write_all(b"x").is_err() { break; }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let debut = std::time::Instant::now();
        let r = client_http_delai(Duration::from_secs(1)).get(&url).call();
        let lu = r.map_err(|e| e.to_string()).and_then(|r| lire_borne(r).map_err(|e| e.to_string()));
        assert!(lu.is_err(), "la lecture devait échouer");
        assert!(debut.elapsed() < Duration::from_secs(5), "l'agent est resté bloqué {:?}", debut.elapsed());
    }

    #[test]
    fn reponse_tronquee_detectee() {
        let url = vendeur("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n", |c| {
            let _ = c.write_all(b"debut seulement");
        });
        let r = client_http_delai(Duration::from_secs(5)).get(&url).call().unwrap();
        assert!(lire_borne(r).is_err(), "une réponse tronquée ne doit pas passer pour complète");
    }

    #[test]
    fn redirection_jamais_suivie() {
        let url = vendeur("HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\n\r\n", |_| {});
        match client_http_delai(Duration::from_secs(5)).get(&url).call() {
            Ok(r) => assert_eq!(r.status(), 302),
            Err(ureq::Error::Status(c, _)) => assert_eq!(c, 302),
            Err(e) => panic!("{e}"),
        }
    }
}

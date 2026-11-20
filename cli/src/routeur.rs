//! Routeur : l'API HTTP que les agents appellent pour acheter une ressource payante.
//!
//! L'agent ne manipule ni UTXO, ni score DAA, ni covenant : il envoie une URL, le routeur paie
//! depuis le coffre si le vendeur répond 402, et renvoie le contenu avec le reçu.
//!
//! Garde des clés (MVP, testnet) : le routeur détient la clé de l'AGENT. La clé du PROPRIÉTAIRE ne
//! sert ici qu'à reconstruire les paramètres publics du coffre ; dans la version de production, le
//! routeur ne reçoit que la clé publique du propriétaire. Si le routeur est piraté, la perte reste
//! bornée par le covenant (budget, plafond par paiement) : c'est la promesse du produit.
//!
//! Configuration (variables d'environnement) :
//!   ROUTEUR_CLE        clé d'API (32 caractères minimum), comparée en temps constant
//!   AGENT_SK / VAULT_PHRASE   clé de l'agent
//!   PROPRIETAIRE_PUB   clé publique x-only du propriétaire (hex) ; obligatoire hors démo
//!   ROUTEUR_ORIGINES   vendeurs autorisés, ex. `https://api.exemple.org,https://data.exemple.net`
//!   ROUTEUR_MAX_REQUETE plafond par requête en sompi (défaut : plafond par paiement du coffre)
//!   ROUTEUR_DEBIT      requêtes payantes par minute (défaut 30)
//!   ROUTEUR_ECOUTE     adresse d'écoute (défaut 127.0.0.1:8403, derrière un proxy TLS)
//!   ROUTEUR_JOURNAL    journal d'audit JSON Lines (défaut routeur-journal.jsonl)
//!   ROUTEUR_DEMO=1     démo testnet : autorise les vendeurs locaux et le point d'entrée agent-compromis
//!
//! Points d'entrée (JSON, `Authorization: Bearer <ROUTEUR_CLE>`) :
//!   GET  /v1/coffre                     état du budget
//!   POST /v1/fetch   {url, max_sompi?}  achète la ressource, paie si 402 ;
//!        en-tête `Idempotency-Key` : une même clé ne paie jamais deux fois (réponse rejouée)
//!   POST /v1/demo/agent-compromis {montant_sompi}
//!        (seulement avec ROUTEUR_DEMO=1) : diffuse un paiement sans aucun contrôle local, pour
//!        montrer que le réseau le refuse s'il dépasse les règles du covenant.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kaspa_addresses::Address;
use kaspa_txscript::pay_to_address_script;
use secp256k1::Keypair;
use serde_json::{Value, json};
use tokio::runtime::Handle;

use crate::*;

pub const PORT: u16 = 8403;

fn reponse(statut: u16, corps: Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_string(corps.to_string())
        .with_status_code(statut)
        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
}

/// Budget disponible maintenant, selon l'état du coffre et le score DAA du réseau.
async fn etat_budget(owner_pk: &[u8], agent: &Keypair) -> Res<Value> {
    let e = load_state()?;
    let c = connect().await?;
    let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
    c.disconnect().await?;
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    Ok(json!({
        "coffre": { "txid": e.txid, "index": e.index, "valeur_sompi": e.valeur },
        "disponible_sompi": p.available(now, creation),
        "capacite_sompi": p.capacity,
        "max_par_paiement_sompi": p.max_per_payment,
        "frais_par_paiement_sompi": FEE,
        "recharge_complete_daa": p.refill_period,
        "garanti_par": "covenant AgentBudget (consensus Kaspa)",
    }))
}

/// Paiement de démonstration diffusé sans contrôle local (agent compromis simulé).
async fn agent_compromis(owner_pk: &[u8], agent: &Keypair, service: &Address, montant: i64) -> Res<Value> {
    let e = load_state()?;
    let c = connect().await?;
    let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let (tx, next) = build_pay_pk(owner_pk, agent, &e, montant, pay_to_address_script(service), now, creation)?;
    let r = match c.submit_transaction(garde_diffusion(&tx)?, false).await {
        Ok(txid) => {
            save_state(&next)?;
            json!({ "accepte_par_le_reseau": true, "transaction": txid.to_string(), "explorateur": explorer(&txid.to_string()) })
        }
        Err(err) => json!({
            "accepte_par_le_reseau": false,
            "raison_du_noeud": err.to_string(),
            "montant_sompi": montant,
            "max_par_paiement_sompi": p.max_per_payment,
            "disponible_sompi": p.available(now, creation),
        }),
    };
    c.disconnect().await?;
    Ok(r)
}

fn lire_json(req: &mut tiny_http::Request) -> Result<Value, String> {
    let mut corps = String::new();
    req.as_reader().take(64 * 1024).read_to_string(&mut corps).map_err(|_| "corps illisible")?;
    serde_json::from_str(&corps).map_err(|_| "JSON invalide".to_string())
}

/// Comparaison en temps constant (la durée ne dépend pas de la position de la première différence).
pub fn egal_temps_constant(a: &[u8], b: &[u8]) -> bool {
    let mut d = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        d |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    d == 0
}

/// `https://Hote:443/chemin?x` → (`https://hote:443`, `hote`). `None` si l'URL n'est pas http(s).
pub fn origine(url: &str) -> Option<(String, String)> {
    let (schema, reste) = url.split_once("://")?;
    let schema = schema.to_ascii_lowercase();
    if schema != "http" && schema != "https" {
        return None;
    }
    let autorite = reste.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if autorite.is_empty() || autorite.contains('@') {
        return None; // pas d'identifiants dans l'URL
    }
    let hote = if let Some(h) = autorite.strip_prefix('[') { h.split(']').next()?.to_string() } else { autorite.split(':').next()?.to_string() };
    Some((format!("{schema}://{autorite}"), hote))
}

/// Adresse interne (boucle locale, réseau privé, lien local, métadonnées cloud, non spécifiée).
pub fn ip_interne(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast() || v.is_documentation()
                || o[0] == 0                                   // 0.0.0.0/8
                || (o[0] == 100 && (o[1] & 0xC0) == 64)        // 100.64.0.0/10 (CGNAT)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xFE) == 18)        // 198.18.0.0/15
                || o[0] >= 240                                 // 240.0.0.0/4 réservé
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            let v4_dans = |a: u16, b: u16| ip_interne(IpAddr::V4(std::net::Ipv4Addr::new((a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8)));
            v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00                   // fc00::/7 (ULA)
                || (s[0] & 0xffc0) == 0xfe80                   // fe80::/10 (lien local)
                || (s[0] & 0xffc0) == 0xfec0                   // fec0::/10 (site local, obsolète)
                || (s[0] == 0x2001 && s[1] == 0x0db8)          // documentation
                || v.to_ipv4_mapped().is_some_and(|m| ip_interne(IpAddr::V4(m)))           // ::ffff:a.b.c.d
                || (s[..6] == [0; 6] && v4_dans(s[6], s[7]))                                // ::a.b.c.d (compatible)
                || (s[0] == 0x0064 && s[1] == 0xff9b && v4_dans(s[6], s[7]))                 // 64:ff9b::/96 (NAT64)
                || (s[0] == 0x2002 && v4_dans(s[1], s[2]))                                  // 2002::/16 (6to4)
        }
    }
}

/// Politique de l'agent, appliquée AVANT tout appel réseau vers le vendeur.
pub struct Politique {
    pub origines: Vec<String>,
    pub max_requete: i64,
    pub demo: bool,
}

impl Politique {
    pub fn verifier_url(&self, url: &str) -> Result<(), String> {
        let (orig, hote) = origine(url).ok_or("url http(s) attendue, sans identifiants")?;
        if !self.origines.is_empty() && !self.origines.iter().any(|o| *o == orig) {
            return Err(format!("vendeur non autorisé : {orig}"));
        }
        if self.demo {
            return Ok(());
        }
        if !url.to_ascii_lowercase().starts_with("https://") {
            return Err("https obligatoire hors démo".into());
        }
        let adresses: Vec<IpAddr> = (hote.as_str(), 443).to_socket_addrs().map_err(|_| "nom de vendeur introuvable")?.map(|a| a.ip()).collect();
        if adresses.is_empty() || adresses.iter().any(|ip| ip_interne(*ip)) {
            return Err("adresse interne refusée".into());
        }
        Ok(())
    }
}

/// Limite de débit : au plus `n` requêtes payantes par fenêtre de 60 s.
pub struct Debit {
    n: usize,
    instants: VecDeque<Instant>,
}

impl Debit {
    pub fn new(n: usize) -> Self {
        Debit { n, instants: VecDeque::new() }
    }
    pub fn autoriser(&mut self, maintenant: Instant) -> bool {
        while self.instants.front().is_some_and(|t| maintenant.duration_since(*t) >= Duration::from_secs(60)) {
            self.instants.pop_front();
        }
        if self.instants.len() >= self.n {
            return false;
        }
        self.instants.push_back(maintenant);
        true
    }
}

/// Réponses déjà servies, par clé d'idempotence (bornée à 1 000 entrées).
pub struct Idempotence {
    reponses: HashMap<String, (u16, Value)>,
    ordre: VecDeque<String>,
}

impl Idempotence {
    pub fn new() -> Self {
        Idempotence { reponses: HashMap::new(), ordre: VecDeque::new() }
    }
    pub fn lire(&self, cle: &str) -> Option<(u16, Value)> {
        self.reponses.get(cle).cloned()
    }
    pub fn garder(&mut self, cle: String, r: (u16, Value)) {
        if self.reponses.insert(cle.clone(), r).is_none() {
            self.ordre.push_back(cle);
            if self.ordre.len() > 1000 {
                if let Some(vieille) = self.ordre.pop_front() {
                    self.reponses.remove(&vieille);
                }
            }
        }
    }
}

fn journaliser(chemin: &str, entree: Value) {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut e = entree;
    e["horodatage_unix"] = json!(t);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(chemin) {
        let _ = writeln!(f, "{e}");
    }
}

pub struct Config {
    pub owner_pk: Vec<u8>,
    pub agent: Keypair,
    /// Démo testnet : adresse payée par l'agent compromis simulé, et vendeur local à lancer.
    pub demo: Option<(Address, Option<Address>)>,
}

/// Lance le routeur (bloquant). Les requêtes sont traitées une par une : l'état du coffre ne peut
/// pas être dépensé deux fois en parallèle.
pub fn lancer(handle: Handle, cfg: Config) -> Res<()> {
    let cle = env::var("ROUTEUR_CLE").map_err(|_| "ROUTEUR_CLE manquante (clé d'API du routeur, 32 caractères minimum)")?;
    if cle.len() < 32 {
        return Err("ROUTEUR_CLE trop courte (32 caractères minimum)".into());
    }
    let demo = cfg.demo.is_some();
    let p0 = VaultParams::pour(&cfg.owner_pk, &cfg.agent, 0, 0);
    let politique = Politique {
        origines: env::var("ROUTEUR_ORIGINES").map(|v| v.split(',').map(|s| s.trim().trim_end_matches('/').to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        max_requete: env::var("ROUTEUR_MAX_REQUETE").ok().and_then(|v| v.parse().ok()).unwrap_or(p0.max_per_payment).min(p0.max_per_payment),
        demo,
    };
    x402::BLOQUER_INTERNE.store(!demo, std::sync::atomic::Ordering::Relaxed);
    if !demo && politique.origines.is_empty() {
        eprintln!("[ROUTEUR] attention : aucun vendeur autorisé configuré (ROUTEUR_ORIGINES) ; seules les adresses publiques en https sont acceptées");
    }
    let mut debit = Debit::new(env::var("ROUTEUR_DEBIT").ok().and_then(|v| v.parse().ok()).unwrap_or(30));
    let mut idem = Idempotence::new();
    let journal = env::var("ROUTEUR_JOURNAL").unwrap_or_else(|_| "routeur-journal.jsonl".into());
    let ecoute = env::var("ROUTEUR_ECOUTE").unwrap_or_else(|_| format!("127.0.0.1:{PORT}"));

    if let Some((_, Some(pay_to))) = &cfg.demo {
        x402::lancer_vendeur(handle.clone(), pay_to.clone());
        std::thread::sleep(Duration::from_secs(2));
    }
    let serveur = tiny_http::Server::http(ecoute.as_str()).map_err(|e| format!("écoute {ecoute} : {e}"))?;
    println!("[ROUTEUR] à l'écoute sur http://{ecoute} (démo : {}, plafond par requête : {} sompi)", if demo { "oui" } else { "non" }, politique.max_requete);
    let attendu = format!("Bearer {cle}");
    for mut req in serveur.incoming_requests() {
        let autorise = req.headers().iter().any(|h| h.field.equiv("Authorization") && egal_temps_constant(h.value.as_str().as_bytes(), attendu.as_bytes()));
        let chemin = req.url().split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        let cle_idem = req.headers().iter().find(|h| h.field.equiv("Idempotency-Key")).map(|h| h.value.as_str().chars().take(128).collect::<String>());
        let (statut, corps) = if !autorise {
            (401, json!({ "erreur": "clé d'API invalide" }))
        } else {
            match (methode.as_str(), chemin.as_str()) {
                ("GET", "/v1/coffre") => match handle.block_on(etat_budget(&cfg.owner_pk, &cfg.agent)) {
                    Ok(v) => (200, v),
                    Err(e) => (503, json!({ "erreur": e.to_string() })),
                },
                ("POST", "/v1/fetch") => {
                    if let Some(r) = cle_idem.as_deref().and_then(|k| idem.lire(k)) {
                        (r.0, json!({ "rejoue": true, "reponse": r.1 }))
                    } else {
                        let r = traiter_fetch(&handle, &cfg, &politique, &mut debit, &mut req, &journal);
                        if let (Some(k), true) = (cle_idem, r.0 == 200 || r.0 == 402) {
                            idem.garder(k, r.clone());
                        }
                        r
                    }
                }
                ("POST", "/v1/demo/agent-compromis") if demo => match lire_json(&mut req) {
                    Err(e) => (400, json!({ "erreur": e })),
                    Ok(v) => {
                        let montant = v["montant_sompi"].as_i64().unwrap_or(0);
                        let service = cfg.demo.as_ref().map(|d| d.0.clone()).expect("démo");
                        println!("[ROUTEUR] démo : paiement de {} TKAS diffusé SANS contrôle local", montant as f64 / 1e8);
                        match handle.block_on(agent_compromis(&cfg.owner_pk, &cfg.agent, &service, montant)) {
                            Ok(v) => {
                                journaliser(&journal, json!({ "evenement": "demo-agent-compromis", "montant_sompi": montant, "resultat": v.clone() }));
                                (200, v)
                            }
                            Err(e) => (502, json!({ "erreur": e.to_string() })),
                        }
                    }
                },
                _ => (404, json!({ "erreur": "point d'entrée inconnu" })),
            }
        };
        let _ = req.respond(reponse(statut, corps));
    }
    Ok(())
}

fn traiter_fetch(handle: &Handle, cfg: &Config, pol: &Politique, debit: &mut Debit, req: &mut tiny_http::Request, journal: &str) -> (u16, Value) {
    let v = match lire_json(req) {
        Ok(v) => v,
        Err(e) => return (400, json!({ "erreur": e })),
    };
    let url = v["url"].as_str().unwrap_or("").to_string();
    if url.len() > 2048 {
        return (400, json!({ "erreur": "url trop longue" }));
    }
    if let Err(e) = pol.verifier_url(&url) {
        journaliser(journal, json!({ "evenement": "refus-politique", "url": url, "raison": e }));
        return (403, json!({ "erreur": e }));
    }
    if !debit.autoriser(Instant::now()) {
        return (429, json!({ "erreur": "trop de requêtes payantes par minute" }));
    }
    let max = v["max_sompi"].as_i64().map(|m| m.min(pol.max_requete)).unwrap_or(pol.max_requete);
    println!("[ROUTEUR] l'agent demande {url}");
    match x402::acheter(handle, &cfg.owner_pk, &cfg.agent, &url, Some(max)) {
        Ok(a) => {
            let paiement = a.txid.as_ref().map(|t| json!({ "montant_sompi": a.montant, "transaction": t, "explorateur": explorer(t) }));
            journaliser(journal, json!({ "evenement": "fetch", "url": url, "statut_vendeur": a.statut, "paiement": paiement.clone(), "refus": a.refus.clone() }));
            let statut = if a.refus.is_some() { 402 } else { 200 };
            (statut, json!({ "statut_vendeur": a.statut, "contenu": a.contenu, "paiement": paiement, "refus": a.refus }))
        }
        Err(e) => {
            journaliser(journal, json!({ "evenement": "erreur", "url": url, "erreur": e.to_string() }));
            (502, json!({ "erreur": e.to_string() }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cle_comparee_en_temps_constant() {
        assert!(egal_temps_constant(b"Bearer abc", b"Bearer abc"));
        assert!(!egal_temps_constant(b"Bearer abc", b"Bearer abd"));
        assert!(!egal_temps_constant(b"Bearer ab", b"Bearer abc"));
        assert!(!egal_temps_constant(b"", b"x"));
        let long = vec![b'a'; 300];
        let mut autre = long.clone();
        autre.push(b'a');
        assert!(!egal_temps_constant(&long, &autre)); // longueurs différant de 256 : pas d'égalité par débordement
    }

    #[test]
    fn origines_normalisees_et_identifiants_refuses() {
        assert_eq!(origine("https://API.exemple.org/v1?x=1"), Some(("https://api.exemple.org".into(), "api.exemple.org".into())));
        assert_eq!(origine("http://127.0.0.1:8402/meteo"), Some(("http://127.0.0.1:8402".into(), "127.0.0.1".into())));
        assert_eq!(origine("https://[::1]:8443/x").map(|o| o.1), Some("::1".into()));
        assert_eq!(origine("https://user:pass@exemple.org/"), None);
        assert_eq!(origine("ftp://exemple.org/"), None);
        assert_eq!(origine("https:///chemin"), None);
    }

    #[test]
    fn adresses_internes_reconnues() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(ip_interne(ip.parse().unwrap()), "{ip} devrait être interne");
        }
        for ip in ["8.8.8.8", "104.16.0.1", "2606:4700::1"] {
            assert!(!ip_interne(ip.parse().unwrap()), "{ip} est publique");
        }
    }

    #[test]
    fn adresses_internes_toutes_familles() {
        for a in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "240.0.0.1",
                  "::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::"] {
            assert!(ip_interne(a.parse().unwrap()), "{a} devrait être interne");
        }
        for a in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808", "2002:808:808::"] {
            assert!(!ip_interne(a.parse().unwrap()), "{a} devrait être public");
        }
    }

    #[test]
    fn politique_hors_demo() {
        let pol = Politique { origines: vec!["https://api.exemple.org".into()], max_requete: 10, demo: false };
        assert!(pol.verifier_url("https://autre.exemple.org/x").unwrap_err().contains("non autorisé"));
        assert!(pol.verifier_url("http://api.exemple.org/x").is_err());
        let ouverte = Politique { origines: vec![], max_requete: 10, demo: false };
        assert!(ouverte.verifier_url("https://127.0.0.1/x").unwrap_err().contains("interne"));
        assert!(ouverte.verifier_url("https://localhost/x").is_err());
        assert!(ouverte.verifier_url("http://exemple.org/x").unwrap_err().contains("https"));
        let demo = Politique { origines: vec![], max_requete: 10, demo: true };
        assert!(demo.verifier_url("http://127.0.0.1:8402/meteo").is_ok());
    }

    #[test]
    fn debit_limite_par_minute() {
        let mut d = Debit::new(2);
        let t0 = Instant::now();
        assert!(d.autoriser(t0));
        assert!(d.autoriser(t0));
        assert!(!d.autoriser(t0 + Duration::from_secs(30)));
        assert!(d.autoriser(t0 + Duration::from_secs(61)));
    }

    #[test]
    fn idempotence_bornee() {
        let mut i = Idempotence::new();
        i.garder("a".into(), (200, json!({"x": 1})));
        assert_eq!(i.lire("a").unwrap().0, 200);
        i.garder("a".into(), (402, json!({})));
        assert_eq!(i.lire("a").unwrap().0, 402);
        for n in 0..1001 {
            i.garder(format!("k{n}"), (200, json!({})));
        }
        assert!(i.lire("a").is_none());
        assert_eq!(i.reponses.len(), 1000);
    }
}

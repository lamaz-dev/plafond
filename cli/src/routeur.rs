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

pub(crate) fn reponse(statut: u16, corps: Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_string(corps.to_string())
        .with_status_code(statut)
        .with_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
}

/// Budget disponible maintenant, lu sur le nœud (pièces du coffre et leur âge).
pub(crate) async fn etat_budget(owner_pk: &[u8], agent: &Keypair) -> Res<Value> {
    let c = connect().await?;
    let v = coffre::vue(&c, owner_pk, &xonly(agent)).await;
    liberer(&c).await?;
    let v = v?;
    // Coffre à lignée : la fiche de dépôt (adresse recalculée et signée par le propriétaire), que
    // celui qui paie vérifie lui-même. Jamais une adresse nue.
    let depot = v.lignee.and_then(|_| crate::coffre092::fiche(owner_pk, &xonly(agent)).ok());
    Ok(json!({
        "coffre": { "adresse": v.adresse, "pieces": v.pieces.len(), "valeur_sompi": v.solde(), "lignee": v.lignee.map(|x| x.to_string()) },
        "depot": depot,
        "disponible_sompi": v.immediate(),
        "capacite_sompi": v.coeur.capacite,
        "max_par_paiement_sompi": (v.coeur.capacite as u64).saturating_sub(FEE),
        "frais_par_paiement_sompi": FEE,
        "recharge_complete_daa": v.coeur.periode,
        "prochain_paiement_plafond_secondes": coffre::delai(&v.coeur, &v.pieces, v.now, v.coeur.capacite as u64).map(|d| d / 10),
        "garanti_par": if v.lignee.is_some() { "covenant Plafond cœur v0.9.2 (lignée de pièces, verrou relatif du consensus Kaspa)" } else if v.coeur.retour.is_some() { "covenant Plafond cœur v0.7 (verrou relatif du consensus Kaspa)" } else { "covenant Plafond cœur v0.6 (verrou relatif du consensus Kaspa)" },
    }))
}

/// Paiement de démonstration diffusé sans contrôle local (agent compromis simulé) : la
/// transaction annonce tout l'âge réel de la pièce, et c'est le réseau qui tranche.
async fn agent_compromis(owner_pk: &[u8], agent: &Keypair, service: &Address, montant: i64) -> Res<Value> {
    Ok(match coffre::payer(owner_pk, agent, montant.max(0) as u64, pay_to_address_script(service), true, 0).await {
        Ok(txid) => json!({ "accepte_par_le_reseau": true, "transaction": txid, "explorateur": explorer(&txid) }),
        Err(err) => json!({
            "accepte_par_le_reseau": false,
            "raison_du_noeud": err.to_string(),
            "montant_sompi": montant,
            "max_par_paiement_sompi": (regles().capacite as u64).saturating_sub(FEE),
        }),
    })
}

pub(crate) fn lire_json(req: &mut tiny_http::Request) -> Result<Value, String> {
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
                || (s[..4] == [0; 4] && s[4] == 0xffff && s[5] == 0 && v4_dans(s[6], s[7])) // ::ffff:0:a.b.c.d (SIIT)
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
        // Le client HTTP lit l'URL selon la norme WHATWG (crate `url`), qui normalise certains
        // caractères (barres obliques inverses, tabulations, IPv4 en hexadécimal ou en octal…).
        // On exige que les deux lectures désignent le même hôte : sinon, l'URL vérifiée et l'URL
        // contactée pourraient différer.
        let lu = url::Url::parse(url).map_err(|_| "url invalide")?;
        let hote_client = match lu.host() {
            Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
            Some(url::Host::Ipv4(a)) => a.to_string(),
            Some(url::Host::Ipv6(a)) => a.to_string(),
            None => return Err("url sans hôte".into()),
        };
        if !lu.username().is_empty() || lu.password().is_some() {
            return Err("identifiants interdits dans l'url".into());
        }
        let hote_client_ip = hote_client.parse::<IpAddr>().ok();
        if hote_client_ip.is_some_and(ip_interne) && !self.demo {
            return Err("adresse interne refusée".into());
        }
        if hote_client != hote && hote_client_ip.is_none_or(|a| hote.parse::<IpAddr>().ok() != Some(a)) {
            return Err("url ambiguë : l'hôte lu par le client diffère de l'hôte vérifié".into());
        }
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

/// URL sans paramètres ni fragment pour le journal (ils peuvent contenir des secrets).
pub(crate) fn url_journal(u: &str) -> String {
    u.split(['?', '#']).next().unwrap_or("").to_string()
}

/// Nom affiché dans le direct de la console (ROUTEUR_NOM, défaut « routeur »).
fn nom_routeur() -> String {
    std::env::var("ROUTEUR_NOM").unwrap_or_else(|_| "routeur".into())
}

fn journaliser(chemin: &str, entree: Value) {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut e = entree;
    e["horodatage_unix"] = json!(t);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(chemin) {
        let _ = writeln!(f, "{e}");
    }
    crate::sobriete::borner(chemin, crate::sobriete::JOURNAL_MAX);
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
    let plafond = (regles().capacite as u64).saturating_sub(FEE) as i64;
    let politique = Politique {
        origines: env::var("ROUTEUR_ORIGINES").map(|v| v.split(',').map(|s| s.trim().trim_end_matches('/').to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        max_requete: env::var("ROUTEUR_MAX_REQUETE").ok().and_then(|v| v.parse().ok()).unwrap_or(plafond).min(plafond),
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
    servir(&serveur, &attendu, &mut idem, |methode, chemin, req| match (methode, chemin) {
        ("GET", "/v1/coffre") => match handle.block_on(etat_budget(&cfg.owner_pk, &cfg.agent)) {
            Ok(v) => (200, v),
            Err(e) => (503, json!({ "erreur": e.to_string() })),
        },
        ("POST", "/v1/fetch") => traiter_fetch(&handle, &cfg, &politique, &mut debit, req, &journal),
        ("POST", "/v1/demo/agent-compromis") if demo => match lire_json(req) {
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
    });
    Ok(())
}

/// Boucle du serveur. Les requêtes sont traitées UNE PAR UNE, dans l'ordre d'arrivée : deux achats
/// ne peuvent jamais lire le même état du coffre ni signer deux dépenses de la même sortie en même
/// temps. La clé d'API est vérifiée avant toute lecture du corps ; une clé d'idempotence déjà vue
/// rejoue la réponse enregistrée sans nouvel achat.
pub fn servir(serveur: &tiny_http::Server, attendu: &str, idem: &mut Idempotence, mut routage: impl FnMut(&str, &str, &mut tiny_http::Request) -> (u16, Value)) {
    for mut req in serveur.incoming_requests() {
        let autorise = req.headers().iter().any(|h| h.field.equiv("Authorization") && egal_temps_constant(h.value.as_str().as_bytes(), attendu.as_bytes()));
        let chemin = req.url().split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        let cle_idem = req.headers().iter().find(|h| h.field.equiv("Idempotency-Key")).map(|h| h.value.as_str().chars().take(128).collect::<String>());
        let (statut, corps) = if !autorise {
            (401, json!({ "erreur": "clé d'API invalide" }))
        } else if methode == "POST" && chemin == "/v1/fetch" {
            if let Some(r) = cle_idem.as_deref().and_then(|k| idem.lire(k)) {
                (r.0, json!({ "rejoue": true, "reponse": r.1 }))
            } else {
                let r = routage(&methode, &chemin, &mut req);
                if let (Some(k), true) = (cle_idem, r.0 == 200 || r.0 == 402) {
                    idem.garder(k, r.clone());
                }
                r
            }
        } else {
            routage(&methode, &chemin, &mut req)
        };
        let _ = req.respond(reponse(statut, corps));
    }
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
        journaliser(journal, json!({ "evenement": "refus-politique", "url": url_journal(&url), "raison": e }));
        crate::agents::noter(&crate::etat_par_defaut(), &nom_routeur(), "bloque", None);
        return (403, json!({ "erreur": e }));
    }
    if !debit.autoriser(Instant::now()) {
        return (429, json!({ "erreur": "trop de requêtes payantes par minute" }));
    }
    let max = v["max_sompi"].as_i64().map(|m| m.min(pol.max_requete)).unwrap_or(pol.max_requete);
    println!("[ROUTEUR] l'agent demande {}", url_journal(&url));
    match x402::acheter(handle, &cfg.owner_pk, &cfg.agent, &url, Some(max)) {
        Ok(a) => {
            let paiement = a.txid.as_ref().map(|t| json!({ "montant_sompi": a.montant, "transaction": t, "explorateur": explorer(t) }));
            journaliser(journal, json!({ "evenement": "fetch", "url": url_journal(&url), "statut_vendeur": a.statut, "paiement": paiement.clone(), "refus": a.refus.clone() }));
            match (&a.txid, &a.refus) {
                (Some(_), _) => crate::agents::noter(&crate::etat_par_defaut(), &nom_routeur(), "paiement", Some(a.montant as i64)),
                (None, Some(_)) => crate::agents::noter(&crate::etat_par_defaut(), &nom_routeur(), "bloque", None),
                _ => {}
            }
            let statut = if a.refus.is_some() { 402 } else { 200 };
            (statut, json!({ "statut_vendeur": a.statut, "contenu": a.contenu, "paiement": paiement, "refus": a.refus }))
        }
        Err(e) => {
            journaliser(journal, json!({ "evenement": "erreur", "url": url_journal(&url), "erreur": e.to_string() }));
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
                  "::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0:127.0.0.1", "::ffff:0:a9fe:a9fe", "::127.0.0.1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::"] {
            assert!(ip_interne(a.parse().unwrap()), "{a} devrait être interne");
        }
        for a in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808", "2002:808:808::"] {
            assert!(!ip_interne(a.parse().unwrap()), "{a} devrait être public");
        }
    }

    /// Adresses internes déguisées (décimal, hexadécimal, octal, forme courte, IPv6 mappée) et
    /// URLs ambiguës (barre oblique inverse, tabulation, identifiants) : toutes refusées hors démo.
    #[test]
    fn adresses_deguisees_et_urls_ambigues_refusees() {
        let pol = Politique { origines: vec![], max_requete: 1, demo: false };
        for u in [
            "https://2130706433/", "https://0x7f000001/", "https://0x7f.0.0.1/", "https://017700000001/",
            "https://0177.0.0.1/", "https://127.1/", "https://[::ffff:127.0.0.1]/", "https://[::1]/",
            "https://169.254.169.254/latest/meta-data", "https://0/", "https://localhost/",
            "https://exemple.com\\@127.0.0.1/", "https://ex\tample.com/", "https://u:p@exemple.com/",
            "file:///etc/passwd", "gopher://exemple.com/",
        ] {
            assert!(pol.verifier_url(u).is_err(), "devrait être refusée : {u}");
        }
        // liste blanche : une URL ambiguë ne passe pas pour un vendeur autorisé
        let pol = Politique { origines: vec!["https://exemple.com".into()], max_requete: 1, demo: true };
        assert!(pol.verifier_url("https://exemple.com/x").is_ok());
        for u in ["https://exemple.com\\.evil.com/", "https://exemple.com.evil.com/", "https://evil.com/#https://exemple.com", "https://EXEMPLE.com:8443/"] {
            assert!(pol.verifier_url(u).is_err(), "ne doit pas passer pour le vendeur autorisé : {u}");
        }
    }

    /// 50 requêtes d'achat simultanées : jamais deux traitements en même temps (pas de double
    /// signature possible sur la même sortie) ; avec la même clé d'idempotence, un seul achat.
    #[test]
    fn cinquante_requetes_paralleles() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;
        for meme_cle in [false, true] {
            let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let port = serveur.server_addr().to_ip().unwrap().port();
            let (en_cours, max, achats) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let (s2, e2, m2, a2) = (serveur.clone(), en_cours.clone(), max.clone(), achats.clone());
            let boucle = std::thread::spawn(move || {
                let mut idem = Idempotence::new();
                servir(&s2, "Bearer cle-de-test-suffisamment-longue-0123456789", &mut idem, |_, _, _| {
                    let n = e2.fetch_add(1, SeqCst) + 1;
                    m2.fetch_max(n, SeqCst);
                    a2.fetch_add(1, SeqCst);
                    std::thread::sleep(Duration::from_millis(5));
                    e2.fetch_sub(1, SeqCst);
                    (200, json!({ "paye": true }))
                });
            });
            let clients: Vec<_> = (0..50)
                .map(|i| {
                    std::thread::spawn(move || {
                        let cle = if meme_cle { "meme-achat".to_string() } else { format!("achat-{i}") };
                        ureq::post(&format!("http://127.0.0.1:{port}/v1/fetch"))
                            .set("Authorization", "Bearer cle-de-test-suffisamment-longue-0123456789")
                            .set("Idempotency-Key", &cle)
                            .send_string("{}")
                            .map(|r| r.status())
                            .unwrap_or(0)
                    })
                })
                .collect();
            let statuts: Vec<u16> = clients.into_iter().map(|c| c.join().unwrap()).collect();
            serveur.unblock();
            boucle.join().unwrap();
            assert!(statuts.iter().all(|s| *s == 200), "toutes les requêtes reçoivent une réponse : {statuts:?}");
            assert_eq!(max.load(SeqCst), 1, "deux achats traités en même temps");
            assert_eq!(achats.load(SeqCst), if meme_cle { 1 } else { 50 });
        }
    }

    /// R64 : un achat dont l'issue est incertaine (paiement remis, réponse perdue) est rendu comme un
    /// refus 402 ; il est gardé sous la clé d'idempotence, donc la même clé ne paie pas deux fois.
    /// Une erreur 502 (rien n'a été remis au vendeur) n'est pas gardée : elle peut être rejouée.
    #[test]
    fn idempotence_garde_les_refus_pas_les_erreurs() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;
        for (statut, appels_attendus) in [(402u16, 1usize), (502, 3)] {
            let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let port = serveur.server_addr().to_ip().unwrap().port();
            let appels = Arc::new(AtomicUsize::new(0));
            let (s2, a2) = (serveur.clone(), appels.clone());
            let boucle = std::thread::spawn(move || {
                let mut idem = Idempotence::new();
                servir(&s2, "Bearer cle-de-test-suffisamment-longue-0123456789", &mut idem, |_, _, _| {
                    a2.fetch_add(1, SeqCst);
                    (statut, json!({ "refus": "issue incertaine après remise du paiement" }))
                });
            });
            for _ in 0..3 {
                let _ = ureq::post(&format!("http://127.0.0.1:{port}/v1/fetch"))
                    .set("Authorization", "Bearer cle-de-test-suffisamment-longue-0123456789")
                    .set("Idempotency-Key", "meme-achat")
                    .send_string("{}");
            }
            serveur.unblock();
            boucle.join().unwrap();
            assert_eq!(appels.load(SeqCst), appels_attendus, "statut {statut}");
        }
    }

    /// Sans la bonne clé d'API : refus, et le corps n'est même pas lu.
    #[test]
    fn mauvaise_cle_refusee_avant_tout_traitement() {
        use std::sync::Arc;
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let s2 = serveur.clone();
        let boucle = std::thread::spawn(move || {
            let mut idem = Idempotence::new();
            servir(&s2, "Bearer bonne-cle-de-test-0123456789abcdef", &mut idem, |_, _, _| panic!("ne doit jamais être appelé"));
        });
        let r = ureq::post(&format!("http://127.0.0.1:{port}/v1/fetch")).set("Authorization", "Bearer mauvaise").send_string("{}");
        assert!(matches!(r, Err(ureq::Error::Status(401, _))));
        serveur.unblock();
        boucle.join().unwrap();
    }

    /// R68 : les paramètres d'URL peuvent porter un secret (clé d'API du service acheté). Ils ne
    /// doivent apparaître ni dans le journal du routeur, ni dans l'erreur renvoyée, même quand la
    /// requête échoue (le message d'erreur du client HTTP cite l'URL complète).
    #[test]
    fn r68_parametres_d_url_jamais_dans_le_journal() {
        use std::sync::Arc;
        // vendeur local qui répond 500
        let vendeur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port_vendeur = vendeur.server_addr().to_ip().unwrap().port();
        let v2 = vendeur.clone();
        let fil_vendeur = std::thread::spawn(move || {
            for req in v2.incoming_requests() {
                let _ = req.respond(tiny_http::Response::from_string("panne").with_status_code(500));
            }
        });
        let journal = std::env::temp_dir().join(format!("routeur-r68-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&journal);
        let j2 = journal.to_string_lossy().into_owned();
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let s2 = serveur.clone();
        let boucle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let cfg = Config { owner_pk: vec![1; 32], agent: Keypair::from_seckey_slice(secp256k1::SECP256K1, &[3; 32]).unwrap(), demo: None };
            let pol = Politique { origines: vec![], max_requete: 1_000, demo: true };
            let mut debit = Debit::new(30);
            let mut idem = Idempotence::new();
            servir(&s2, "Bearer cle-de-test-suffisamment-longue-0123456789", &mut idem, |_, _, req| traiter_fetch(rt.handle(), &cfg, &pol, &mut debit, req, &j2));
        });
        let secret = "CLE-SECRETE-DE-TEST-123";
        let r = ureq::post(&format!("http://127.0.0.1:{port}/v1/fetch"))
            .set("Authorization", "Bearer cle-de-test-suffisamment-longue-0123456789")
            .send_string(&json!({ "url": format!("http://127.0.0.1:{port_vendeur}/donnees?api_key={secret}#f") }).to_string());
        let corps = match r {
            Err(ureq::Error::Status(502, r)) => r.into_string().unwrap(),
            autre => panic!("502 attendu : {autre:?}"),
        };
        serveur.unblock();
        vendeur.unblock();
        boucle.join().unwrap();
        fil_vendeur.join().unwrap();
        let ecrit = std::fs::read_to_string(&journal).unwrap();
        let _ = std::fs::remove_file(&journal);
        assert!(ecrit.contains("/donnees"), "l'URL sans paramètres reste journalisée : {ecrit}");
        assert!(!ecrit.contains(secret), "secret d'URL dans le journal du routeur : {ecrit}");
        assert!(!corps.contains(secret), "secret d'URL dans l'erreur renvoyée : {corps}");
        // ce que le routeur écrit sur sa sortie (reprise par les journaux système) suit la même règle
        assert_eq!(url_journal(&format!("https://api.exemple.org/v1?cle={secret}")), "https://api.exemple.org/v1");
    }

    /// Appeler le routeur sans sa clé : aucune variante ne passe (clé absente, autre schéma, casse,
    /// préfixe, clé dans l'URL ou dans le corps), sur aucun point d'entrée, et le refus ne dit rien.
    #[test]
    fn routeur_ferme_sans_la_cle_exacte() {
        use std::sync::Arc;
        let cle = "bonne-cle-de-test-0123456789abcdef";
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let s2 = serveur.clone();
        let boucle = std::thread::spawn(move || {
            let mut idem = Idempotence::new();
            servir(&s2, "Bearer bonne-cle-de-test-0123456789abcdef", &mut idem, |_, _, _| panic!("ne doit jamais être appelé"));
        });
        let base = format!("http://127.0.0.1:{port}");
        let refuse = |r: Result<ureq::Response, ureq::Error>, quoi: &str| match r {
            Err(ureq::Error::Status(401, r)) => {
                let corps = r.into_string().unwrap();
                assert!(!corps.contains(cle) && !corps.contains("bonne-cle"), "{quoi} : le refus ne cite pas la clé");
            }
            autre => panic!("{quoi} : 401 attendu, obtenu {autre:?}"),
        };
        for chemin in ["/v1/coffre", "/v1/fetch", "/v1/demo/agent-compromis", "/"] {
            refuse(ureq::get(&format!("{base}{chemin}")).call(), "sans clé");
            refuse(ureq::post(&format!("{base}{chemin}")).send_string("{}"), "sans clé");
        }
        for entete in [cle.to_string(), format!("bearer {cle}"), format!("Bearer  {cle}"), format!("Bearer {}", &cle[..cle.len() - 1]), format!("Bearer {cle}x"), format!("Basic {cle}"), "Bearer ".to_string(), format!("Bearer {}", cle.to_uppercase())] {
            refuse(ureq::post(&format!("{base}/v1/fetch")).set("Authorization", &entete).send_string("{}"), &entete);
        }
        refuse(ureq::post(&format!("{base}/v1/fetch?cle={cle}&Authorization=Bearer%20{cle}")).send_string(&json!({ "cle": cle, "Authorization": format!("Bearer {cle}") }).to_string()), "clé dans l'URL ou le corps");
        refuse(ureq::post(&format!("{base}/v1/fetch")).set("X-Authorization", &format!("Bearer {cle}")).set("Idempotency-Key", "deja-vue").send_string("{}"), "autre en-tête");
        serveur.unblock();
        boucle.join().unwrap();
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

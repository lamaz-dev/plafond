//! Console du propriétaire (tableau de bord, alimenter, historique, arrêt d'urgence).
//!
//! Elle tourne sur l'ORDINATEUR du propriétaire, jamais sur le serveur de l'agent : c'est elle qui
//! tient la clé du propriétaire (fichier chiffré, déverrouillé dans le terminal au lancement ; le
//! mot de passe ne passe jamais par le navigateur). Protections :
//!  - écoute uniquement sur 127.0.0.1 ;
//!  - jeton de session aléatoire, transmis dans le fragment de l'URL (jamais envoyé au serveur
//!    ni journalisé), exigé sur chaque appel d'API (comparaison en temps constant) ;
//!  - en-tête Host vérifié (contre le « DNS rebinding ») et Origin vérifiée pour les actions ;
//!  - actions irréversibles soumises à une confirmation explicite ;
//!  - requêtes traitées une par une.

use crate::retrouver::{self, Mouvement};
use crate::*;
use serde_json::{json, Value};
use std::io::Read;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;

pub const PORT: u16 = 8404;
const PAGE: &str = include_str!("../console/index.html");

fn egal(a: &[u8], b: &[u8]) -> bool {
    let mut d = (a.len() != b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        d |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    d == 0
}

fn reponse(statut: u16, type_: &str, corps: Vec<u8>) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let h = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).expect("en-tête");
    tiny_http::Response::from_data(corps)
        .with_status_code(statut)
        .with_header(h("Content-Type", type_))
        .with_header(h("Cache-Control", "no-store"))
        .with_header(h("X-Frame-Options", "DENY"))
        .with_header(h("X-Content-Type-Options", "nosniff"))
        .with_header(h("Referrer-Policy", "no-referrer"))
        .with_header(h("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))
}

fn json_rep(statut: u16, v: Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    reponse(statut, "application/json; charset=utf-8", v.to_string().into_bytes())
}

/// Cours indicatif du KAS (EUR, USD), mis en cache 5 minutes ; absent si l'API ne répond pas.
struct Cours {
    valeur: Option<(f64, f64)>,
    lu: Option<Instant>,
}

impl Cours {
    fn lire(&mut self) -> Option<(f64, f64)> {
        if self.lu.is_some_and(|t| t.elapsed() < Duration::from_secs(300)) {
            return self.valeur;
        }
        self.lu = Some(Instant::now());
        let r = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()
            .get("https://api.coingecko.com/api/v3/simple/price?ids=kaspa&vs_currencies=eur,usd")
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .and_then(|t| serde_json::from_str::<Value>(&t).ok());
        self.valeur = r.and_then(|v| Some((v["kaspa"]["eur"].as_f64()?, v["kaspa"]["usd"].as_f64()?)));
        self.valeur
    }
}

fn origine() -> Option<Etat> {
    serde_json::from_str(&fs::read_to_string(state_path().replace(".json", "-origine.json")).ok()?).ok()
}

/// Tableau de bord : tout est lu sur la chaîne (état, historique vérifié saut par saut).
async fn tableau(owner: &Keypair, agent: &Keypair, cours: Option<(f64, f64)>) -> Res<Value> {
    let pk = xonly(owner);
    let p0 = VaultParams::pour(&pk, agent, 0, 0);
    let regles = json!({
        "budget_garanti_par_periode_sompi": 2 * p0.capacity,
        "reserve_sompi": p0.capacity,
        "plafond_par_achat_sompi": p0.max_per_payment,
        "frais_max_par_achat_sompi": p0.max_fee,
        "periode_daa": p0.refill_period,
        "periode_secondes": p0.refill_period / 10,
    });
    let cours_json = cours.map(|(e, u)| json!({ "eur": e, "usd": u, "source": "CoinGecko (indicatif)" }));
    let Some(orig) = origine() else {
        return Ok(json!({ "sante": "aucun", "regles": regles, "cours": cours_json, "adresse_proprietaire": address(owner).to_string() }));
    };
    // Historique vérifié depuis l'origine (indexeur public, chaque saut recalculé).
    let (pk2, ag2, o2) = (pk.clone(), agent.clone(), orig.clone());
    let (issue, _, historique): (retrouver::Issue, usize, Vec<Mouvement>) =
        tokio::task::spawn_blocking(move || retrouver::retrouver_avec_historique(&retrouver::Rest::depuis_env(), &pk2, &ag2, &o2).map_err(|e| e.to_string())).await??;
    let c = connect_silencieux().await?;
    let solde_proprio: u64 = c.get_utxos_by_addresses(vec![address(owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
    let etat = match issue {
        retrouver::Issue::Ferme { txid } => {
            c.disconnect().await?;
            return Ok(json!({ "sante": "gele", "gel": txid, "regles": regles, "historique": historique, "cours": cours_json,
                "solde_proprietaire_sompi": solde_proprio, "adresse_proprietaire": address(owner).to_string() }));
        }
        retrouver::Issue::Courant(mut e) => {
            e.valeur = montant_coffre(&c, &pk, agent, &e).await?;
            save_state(&e)?;
            e
        }
    };
    let creation = creation_coffre(&c, &pk, agent, &etat).await?;
    let now = (virtual_daa(&c).await? - DAA_MARGIN) as i64;
    c.disconnect().await?;
    let p = VaultParams::pour(&pk, agent, etat.tokens, etat.last_daa);
    let disponible = p.available(now, creation);
    let depense_periode: i64 = historique
        .iter()
        .filter(|m| m.genre == "achat" && m.instant_daa.is_some_and(|t| t > now - p.refill_period))
        .map(|m| m.montant_sompi + m.frais_sompi)
        .sum();
    let min_achat = 2_000_000 + FEE as i64;
    let sante = if disponible < min_achat { "epuise" } else if disponible * 5 < p.capacity { "alerte" } else { "normal" };
    Ok(json!({
        "sante": sante,
        "regles": regles,
        "solde_coffre_sompi": etat.valeur,
        "exposition_immediate_sompi": disponible.min(etat.valeur as i64),
        "depense_periode_sompi": depense_periode,
        "solde_proprietaire_sompi": solde_proprio,
        "adresse_proprietaire": address(owner).to_string(),
        "historique": historique.iter().rev().take(50).collect::<Vec<_>>(),
        "cours": cours_json,
        "technique": {
            "reseau": "Kaspa testnet-10",
            "contrat": "AgentBudget v0.5.1 (covenant SilverScript)",
            "lignee": etat.cov_id,
            "sortie_courante": format!("{}:{}", etat.txid, etat.index),
            "explorateur": explorer(&etat.txid),
            "empreinte_source_contrat": hex::encode(blake2b_simd::Params::new().hash_length(32).hash(include_str!("../../contracts/agent_budget.sil").as_bytes()).as_bytes()),
        },
    }))
}

fn journal(entree: Value) {
    use std::io::Write;
    let ligne = json!({ "instant": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0), "action": entree });
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open("console-journal.jsonl") {
        let _ = writeln!(f, "{ligne}");
    }
}

pub fn lancer(handle: Handle, owner: Keypair, agent: Keypair) -> Res<()> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| format!("aléa : {e}"))?;
    let jeton = hex::encode(b);
    let serveur = tiny_http::Server::http(format!("127.0.0.1:{PORT}")).map_err(|e| format!("écoute 127.0.0.1:{PORT} : {e}"))?;
    println!("Console du propriétaire : ouvrez http://127.0.0.1:{PORT}/#jeton={jeton}");
    println!("(lien personnel valable pour cette session ; ne le partagez pas ; Ctrl+C pour arrêter)");
    servir(&serveur, &jeton, handle, owner, agent);
    Ok(())
}

/// Boucle de la console (séparée pour être testée sur un port libre).
pub fn servir(serveur: &tiny_http::Server, jeton: &str, handle: Handle, owner: Keypair, agent: Keypair) {
    let port = serveur.server_addr().to_ip().map(|a| a.port()).unwrap_or(PORT);
    let hotes = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let origines = [format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")];
    let mut cours = Cours { valeur: None, lu: None };
    for mut req in serveur.incoming_requests() {
        let entetes: Vec<(String, String)> = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_string())).collect();
        let entete = |nom: &str| entetes.iter().find(|(k, _)| k == &nom.to_ascii_lowercase()).map(|(_, v)| v.clone());
        let hote_ok = entete("Host").is_some_and(|h| hotes.contains(&h));
        let chemin = req.url().split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        let jeton_ok = entete("X-Jeton").is_some_and(|j| egal(j.as_bytes(), jeton.as_bytes()));
        let origine_ok = entete("Origin").is_none_or(|o| origines.contains(&o));
        let rep = if !hote_ok {
            json_rep(421, json!({ "erreur": "hôte non autorisé" }))
        } else if methode == "GET" && chemin == "/" {
            reponse(200, "text/html; charset=utf-8", PAGE.as_bytes().to_vec())
        } else if !jeton_ok {
            json_rep(401, json!({ "erreur": "jeton de session invalide : rouvrez le lien affiché dans le terminal" }))
        } else if methode == "POST" && !origine_ok {
            json_rep(403, json!({ "erreur": "origine refusée" }))
        } else {
            let mut corps = String::new();
            let _ = req.as_reader().take(16 * 1024).read_to_string(&mut corps);
            let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
            match (methode.as_str(), chemin.as_str()) {
                ("GET", "/api/tableau") => {
                    let c = cours.lire();
                    match handle.block_on(tableau(&owner, &agent, c)) {
                        Ok(t) => json_rep(200, t),
                        Err(e) => json_rep(503, json!({ "erreur": e.to_string() })),
                    }
                }
                ("POST", "/api/geler") => {
                    if v["confirmation"].as_str() != Some("GELER") {
                        json_rep(400, json!({ "erreur": "confirmation requise" }))
                    } else {
                        let r = handle.block_on(geler(&owner, &agent, false, 0));
                        journal(json!({ "geler": r.as_ref().map_err(|e| e.to_string()) }));
                        match r {
                            Ok(txid) => json_rep(200, json!({ "transaction": txid, "explorateur": explorer(&txid) })),
                            Err(e) => json_rep(502, json!({ "erreur": e.to_string() })),
                        }
                    }
                }
                ("POST", "/api/alimenter") => match v["montant_sompi"].as_u64().filter(|m| (10_000_000..=100_000_000_000).contains(m)) {
                    None => json_rep(400, json!({ "erreur": "montant invalide (0,1 à 1 000)" })),
                    Some(m) => {
                        let r = handle.block_on(recharger(&owner, &agent, m));
                        journal(json!({ "alimenter": m, "resultat": r.as_ref().map_err(|e| e.to_string()) }));
                        match r {
                            Ok(txid) => json_rep(200, json!({ "transaction": txid, "explorateur": explorer(&txid) })),
                            Err(e) => json_rep(502, json!({ "erreur": e.to_string() })),
                        }
                    }
                },
                ("POST", "/api/creer") => {
                    if v["confirmation"].as_str() != Some("CREER") {
                        json_rep(400, json!({ "erreur": "confirmation requise" }))
                    } else {
                        let r = handle.block_on(deployer(&owner, &agent));
                        journal(json!({ "creer": r.as_ref().map_err(|e| e.to_string()) }));
                        match r {
                            Ok(txid) => json_rep(200, json!({ "transaction": txid, "explorateur": explorer(&txid) })),
                            Err(e) => json_rep(502, json!({ "erreur": e.to_string() })),
                        }
                    }
                }
                _ => json_rep(404, json!({ "erreur": "inconnu" })),
            }
        };
        let _ = req.respond(rep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Protections de la console, sans réseau : hôte, jeton, origine, confirmation.
    #[test]
    fn protections_de_la_console() {
        use std::sync::Arc;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let (s2, h) = (serveur.clone(), rt.handle().clone());
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let fil = std::thread::spawn(move || servir(&s2, "jeton-de-test", h, k(1), k(2)));
        let base = format!("http://127.0.0.1:{port}");
        let statut = |r: Result<ureq::Response, ureq::Error>| match r {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        };
        // la page s'affiche sans jeton (le jeton reste dans le fragment de l'URL)
        assert_eq!(statut(ureq::get(&format!("{base}/")).call()), 200);
        // API sans jeton ou avec un mauvais jeton : refusée
        assert_eq!(statut(ureq::get(&format!("{base}/api/tableau")).call()), 401);
        assert_eq!(statut(ureq::get(&format!("{base}/api/tableau")).set("X-Jeton", "faux").call()), 401);
        // DNS rebinding : un autre nom d'hôte est refusé, même avec le bon jeton
        assert_eq!(statut(ureq::get(&format!("{base}/api/tableau")).set("Host", "attaquant.example").set("X-Jeton", "jeton-de-test").call()), 421);
        // action depuis une autre origine (CSRF) : refusée
        assert_eq!(statut(ureq::post(&format!("{base}/api/geler")).set("X-Jeton", "jeton-de-test").set("Origin", "https://attaquant.example").send_string("{\"confirmation\":\"GELER\"}")), 403);
        // gel sans la confirmation explicite : refusé
        assert_eq!(statut(ureq::post(&format!("{base}/api/geler")).set("X-Jeton", "jeton-de-test").send_string("{}")), 400);
        assert_eq!(statut(ureq::post(&format!("{base}/api/creer")).set("X-Jeton", "jeton-de-test").send_string("{\"confirmation\":\"oui\"}")), 400);
        // montant d'alimentation hors bornes : refusé avant toute transaction
        assert_eq!(statut(ureq::post(&format!("{base}/api/alimenter")).set("X-Jeton", "jeton-de-test").send_string("{\"montant_sompi\":1}")), 400);
        serveur.unblock();
        fil.join().unwrap();
    }

    #[test]
    fn page_sans_ressource_externe() {
        // aucune ressource tierce : la politique CSP de la console l'interdirait de toute façon
        for motif in ["<script src", "<link ", "http://", "https://fonts", "cdn."] {
            assert!(!PAGE.contains(motif), "ressource externe dans la page : {motif}");
        }
    }
}

/// Données du tableau de bord, une fois (commande `tableau`, utile en CI et pour le support).
pub async fn tableau_json(owner: &Keypair, agent: &Keypair) -> Res<Value> {
    tableau(owner, agent, None).await
}

//! Console du propriétaire (tableau de bord, alimenter, historique, arrêt d'urgence).
//!
//! Elle tourne sur l'ORDINATEUR du propriétaire, jamais sur le serveur de l'agent : c'est elle qui
//! tient la clé du propriétaire (fichier chiffré, déverrouillé dans le terminal au lancement ; le
//! mot de passe ne passe jamais par le navigateur). Protections :
//!  - écoute uniquement sur 127.0.0.1 ;
//!  - jeton de session aléatoire, exigé sur chaque appel d'API (comparaison en temps constant) ; il
//!    n'est jamais dans un lien : le lien d'ouverture porte un ticket à usage unique et de courte
//!    durée, que la page échange contre le jeton (R73) ;
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

/// Cours indicatifs du KAS dans plusieurs unités de lecture, mis en cache 5 minutes ; absents si
/// l'API ne répond pas. USDT, USDC, BTC, ETH et SOL sont calculés à partir de leur propre cours en
/// dollars (aucune parité supposée).
struct Cours {
    valeur: Option<Value>,
    lu: Option<Instant>,
}

impl Cours {
    fn lire(&mut self) -> Option<Value> {
        if self.lu.is_some_and(|t| t.elapsed() < Duration::from_secs(300)) {
            return self.valeur.clone();
        }
        self.lu = Some(Instant::now());
        let v = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build()
            .get("https://api.coingecko.com/api/v3/simple/price?ids=kaspa,tether,usd-coin,bitcoin,ethereum,solana&vs_currencies=usd,eur,jpy,gbp")
            .call()
            .ok()
            .and_then(|r| r.into_string().ok())
            .and_then(|t| serde_json::from_str::<Value>(&t).ok());
        self.valeur = v.and_then(|v| {
            let usd = |id: &str| v[id]["usd"].as_f64().filter(|x| *x > 0.0);
            let kas = usd("kaspa")?;
            let mut c = json!({ "usd": kas, "eur": v["kaspa"]["eur"].as_f64()?, "source": "CoinGecko (indicatif)" });
            for f in ["jpy", "gbp"] {
                if let Some(x) = v["kaspa"][f].as_f64() {
                    c[f] = json!(x);
                }
            }
            for (cle, id) in [("usdt", "tether"), ("usdc", "usd-coin"), ("btc", "bitcoin"), ("eth", "ethereum"), ("sol", "solana")] {
                if let Some(x) = usd(id) {
                    c[cle] = json!(kas / x);
                }
            }
            Some(c)
        });
        self.valeur.clone()
    }
}

/// Tarif de référence d'une requête standard (frais inclus), pour exprimer les budgets en requêtes.
fn tarif_reference() -> i64 {
    std::env::var("TARIF_REQUETE_SOMPI").ok().and_then(|v| v.parse().ok()).filter(|t| *t > 0).unwrap_or(40_000_000)
}

/// QR code (SVG en URI data:) d'une adresse, généré localement, sans service tiers.
fn qr(texte: &str) -> Option<String> {
    use base64::Engine;
    let code = qrcode::QrCode::new(texte.as_bytes()).ok()?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(180, 180).quiet_zone(true).build();
    Some(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

/// Règles d'un mandat : budget, période, plafond par achat et, en option, durée en jours.
/// Avec une durée, le capital alloué vaut budget × nombre de périodes : c'est la perte maximale
/// garantie du mandat sur toute sa vie (le coffre ne peut pas dépenser plus que ce qu'il contient).
fn regles_mandat(v: &Value) -> Res<(crate::Regles, Option<i64>)> {
    let (Some(b), Some(p), Some(m)) = (v["budget_sompi"].as_i64(), v["periode_daa"].as_i64(), v["plafond_sompi"].as_i64()) else {
        return Err("budget, période et plafond par achat requis".into());
    };
    let mut r = crate::Regles::calculer(b, p, m)?;
    let duree = v["duree_jours"].as_i64().filter(|j| *j > 0);
    if let Some(j) = duree {
        if j > 366 {
            return Err("durée du mandat : 366 jours au plus".into());
        }
        let periodes = (j * crate::JOUR_DAA + p - 1) / p;
        r.depot = (b as u64).saturating_mul(periodes as u64).max(100_000_000);
    }
    Ok((r, duree))
}

/// Règles telles que l'utilisateur les lit (budget sur sa période, plafond, expositions).
fn regles_json(r: &crate::Regles) -> Value {
    json!({
        "budget_sompi": r.budget,
        "periode_daa": r.periode_daa,
        "periode_secondes": r.periode_daa / 10,
        "plafond_par_achat_sompi": r.plafond,
        "exposition_immediate_max_sompi": r.capacite * r.pieces.max(1),
        "pieces": r.pieces.max(1),
        "maximum_24h_sompi": r.maximum_sur(crate::JOUR_DAA),
        "maximum_periode_sompi": r.maximum_sur(r.periode_daa),
        "recharge_secondes": r.recharge_daa / 10,
        "depot_initial_sompi": r.depot,
        // le mandat : capital alloué = perte maximale garantie sur toute sa vie
        "capital_alloue_sompi": r.depot,
        "perte_max_mandat_sompi": r.depot,
        "frais_max_par_achat_sompi": 3_000_000,
        // compatibilité
        "budget_garanti_par_periode_sompi": r.budget,
        "reserve_sompi": r.capacite,
    })
}

fn origine() -> Option<Etat> {
    serde_json::from_str(&fs::read_to_string(state_path().replace(".json", "-origine.json")).ok()?).ok()
}

/// Tableau de bord du coffre (cœur v0.6) : tout est lu sur le nœud (les pièces de l'adresse).
async fn tableau(owner: &Keypair, agent: &Keypair, cours: Option<Value>) -> Res<Value> {
    // Ancien coffre v0.5.1 : seulement s'il n'y a pas de coffre v0.6 (l'origine d'un ancien coffre
    // gelé peut rester sur le disque).
    if crate::coffre::charger().is_none() && (crate::load_state().is_ok() || origine().is_some()) {
        return tableau_ancien(owner, agent, cours).await;
    }
    let pk = xonly(owner);
    let rg = crate::regles();
    let regles = regles_json(&rg);
    let adresse = address(owner).to_string();
    let commun = json!({ "tarif_reference_sompi": tarif_reference(), "qr_adresse": qr(&adresse), "mot_de_passe_requis": std::env::var("PROPRIETAIRE_CLE").is_ok() });
    let Some(mut etat) = crate::coffre::charger() else {
        let mut r = json!({ "sante": "aucun", "regles": regles, "cours": cours, "adresse_proprietaire": adresse });
        fusion(&mut r, &commun);
        return Ok(r);
    };
    let c = connect_silencieux().await?;
    let v = crate::coffre::vue(&c, &pk, &crate::agent_pk(agent)).await;
    let solde_proprio: Res<u64> = async { Ok(c.get_utxos_by_addresses(vec![address(owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum()) }.await;
    liberer(&c).await?;
    let (mut v, solde_proprio) = (v?, solde_proprio?);
    if crate::coffre::suivre(&mut etat, &v.pieces, v.now) {
        crate::coffre::memoriser(&etat);
        v.etat = Some(etat.clone()); // la courbe affichée part des dates recalées (R57)
    }
    let solde = v.solde();
    let apports = v.apports();
    // Perte nette depuis la création : ce qui est sorti du coffre (paiements et frais).
    let depense = apports.saturating_sub(solde);
    let reserve = crate::coeur_plancher();
    let sante = if solde == 0 || solde <= reserve { "epuise" } else if depense * 5 >= apports * 4 { "alerte" } else { "normal" };
    let jour = crate::JOUR_DAA as u64;
    let delai_s = |montant: u64| crate::coffre::delai(&v.coeur, &v.pieces, v.now, montant + FEE).map(|d| d / 10);
    // La promesse faite à la création : perte nette maximale à chaque date (spec v0.6, §1b).
    let courbe: Vec<Value> = [0u64, 3_600, 86_400, 7 * 86_400, 30 * 86_400, 90 * 86_400]
        .iter()
        .map(|s| json!({ "secondes": s, "perte_max_sompi": v.courbe(etat.cree_daa + s * 10) }))
        .collect();
    // Achats reconnus sur la chaîne (dépense frais compris), puis apports du propriétaire.
    let historique: Vec<Value> = etat
        .achats
        .iter()
        .rev()
        .map(|a| json!({ "genre": "achat", "txid": a.txid, "destinataire": format!("tx {}", &a.txid[..a.txid.len().min(12)]), "montant_sompi": a.sompi, "frais_sompi": 0, "instant_daa": a.daa }))
        .chain(etat.apports.iter().rev().map(|a| json!({ "genre": "apport", "txid": a.txid, "montant_sompi": a.sompi, "frais_sompi": 0, "instant_daa": a.daa })))
        .collect();
    let mut r = json!({
        "sante": sante,
        "regles": regles,
        "solde_coffre_sompi": solde,
        "exposition_immediate_sompi": v.immediate(),
        "pire_24h_sompi": v.fenetre(jour),
        "risque_pieces": v.pieces.iter().map(|p| json!({ "params": { "capacite": v.coeur.capacite, "periode": v.coeur.periode }, "creation": p.creation.unwrap_or(v.now), "valeur": p.valeur })).collect::<Vec<_>>(),
        "risque_now": v.now,
        "reserve_technique_sompi": reserve.min(solde),
        "depense_periode_sompi": depense,
        "depense_depuis_creation_sompi": depense,
        "apports_sompi": apports,
        "courbe": courbe,
        "perte_nette_depuis_creation_sompi": depense,
        "courbe_maintenant_sompi": v.courbe(v.now),
        "prochain_achat_min_secondes": delai_s(2_000_000),
        "prochain_achat_plafond_secondes": delai_s((rg.plafond as u64).saturating_sub(FEE)),
        "solde_proprietaire_sompi": solde_proprio,
        "adresse_proprietaire": adresse,
        "historique": historique,
        "cours": cours,
        "technique": {
            "reseau": "Kaspa testnet-10",
            "contrat": "Plafond, cœur v0.6 (sans mémoire, covenant SilverScript)",
            "adresse_coffre": v.adresse,
            "pieces": v.pieces.len(),
            "capacite_sompi": v.coeur.capacite,
            "periode_daa": v.coeur.periode,
            "empreinte_source_contrat": hex::encode(blake2b_simd::Params::new().hash_length(32).hash(crate::coeur::SOURCE.as_bytes()).as_bytes()),
        },
    });
    fusion(&mut r, &commun);
    Ok(r)
}

/// Tableau de bord d'un ancien coffre v0.5.1 (historique vérifié saut par saut).
async fn tableau_ancien(owner: &Keypair, agent: &Keypair, cours: Option<Value>) -> Res<Value> {
    let pk = xonly(owner);
    let rg = crate::regles();
    let regles = regles_json(&rg);
    let cours_json = cours;
    let adresse = address(owner).to_string();
    let commun = json!({ "tarif_reference_sompi": tarif_reference(), "qr_adresse": qr(&adresse), "mot_de_passe_requis": std::env::var("PROPRIETAIRE_CLE").is_ok() });
    let Some(orig) = origine() else {
        let mut r = json!({ "sante": "aucun", "regles": regles, "cours": cours_json, "adresse_proprietaire": adresse });
        fusion(&mut r, &commun);
        return Ok(r);
    };
    // Historique vérifié depuis l'origine (chaîne du nœud, chaque saut recalculé ; indexeur en repli).
    let c = connect_silencieux().await?;
    let (issue, _, historique): (retrouver::Issue, usize, Vec<Mouvement>) = match crate::retrouver_lignee(&c, &pk, agent, &orig).await {
        Ok(r) => r,
        Err(e) => {
            liberer(&c).await?;
            return Err(e);
        }
    };
    // Bénéficiaire lisible : adresse plutôt que script brut ; plus récent en premier.
    let historique: Vec<Value> = historique
        .iter()
        .rev()
        .take(50)
        .map(|m| {
            let mut v = serde_json::to_value(m).unwrap_or(Value::Null);
            if let Some(h) = &m.destinataire {
                let adr = hex::decode(h).ok().and_then(|octets| {
                    let spk = kaspa_consensus_core::tx::ScriptPublicKey::new(0, octets.into());
                    kaspa_txscript::extract_script_pub_key_address(&spk, Prefix::Testnet).ok().map(|a| a.to_string())
                });
                v["destinataire"] = adr.map(Value::String).unwrap_or(Value::String(h.clone()));
            }
            v
        })
        .collect();
    let solde_proprio: u64 = c.get_utxos_by_addresses(vec![address(owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
    let etat = match issue {
        retrouver::Issue::Ferme { txid } => {
            liberer(&c).await?;
            let mut r = json!({ "sante": "gele", "gel": txid, "regles": regles, "historique": historique, "cours": cours_json,
                "solde_proprietaire_sompi": solde_proprio, "adresse_proprietaire": adresse });
            fusion(&mut r, &commun);
            return Ok(r);
        }
        retrouver::Issue::Courant(mut e) => {
            e.valeur = montant_coffre(&c, &pk, agent, &e).await?;
            save_state(&e)?;
            e
        }
    };
    let creation = creation_coffre(&c, &pk, agent, &etat).await?;
    let now = (virtual_daa(&c).await? - DAA_MARGIN) as i64;
    liberer(&c).await?;
    let p = VaultParams::pour(&pk, agent, etat.tokens, etat.last_daa);
    let disponible = p.available(now, creation);
    let depense_periode: i64 = historique
        .iter()
        .filter(|m| m["genre"] == "achat" && m["instant_daa"].as_i64().is_some_and(|t| t > now - rg.periode_daa))
        .map(|m| m["montant_sompi"].as_i64().unwrap_or(0) + m["frais_sompi"].as_i64().unwrap_or(0))
        .sum();
    let min_achat = 2_000_000 + FEE as i64;
    // État vu par l'utilisateur : part du budget de la période déjà consommée (une attente de recharge
    // de quelques minutes n'est pas une alerte).
    let presque = depense_periode * 5 >= rg.budget * 4;
    let sante = if presque && disponible < min_achat { "epuise" } else if presque { "alerte" } else { "normal" };
    // Réserve technique : sous ce solde, plus aucun paiement n'est diffusable (masse de stockage,
    // KIP-9) ; elle reste dans le coffre jusqu'à ce que le propriétaire la récupère.
    let reserve = masse::survival_floor(FEE) as i64;
    // Moteur de risque (spec/moteur-de-risque.md) : bornes garanties par le contrat, sans déduire la
    // réserve technique (borne prudente : le chiffre affiché n'est jamais en dessous du vrai pire cas).
    let a = p.available(now, creation).clamp(0, etat.valeur as i64);
    let expo = a;
    let pire_24h = (a as i128 + p.capacity as i128 * crate::JOUR_DAA as i128 / p.refill_period.max(1) as i128).min(etat.valeur as i128) as i64;
    let mut r = json!({
        "sante": sante,
        "regles": regles,
        "solde_coffre_sompi": etat.valeur,
        "exposition_immediate_sompi": expo,
        "pire_24h_sompi": pire_24h,
        "reserve_technique_sompi": reserve.min(etat.valeur as i64),
        "depense_periode_sompi": depense_periode,
        "solde_proprietaire_sompi": solde_proprio,
        "adresse_proprietaire": adresse,
        "historique": historique,
        "cours": cours_json,
        "technique": {
            "reseau": "Kaspa testnet-10",
            "contrat": "AgentBudget v0.5.1 (covenant SilverScript)",
            "lignee": etat.cov_id,
            "sortie_courante": format!("{}:{}", etat.txid, etat.index),
            "explorateur": explorer(&etat.txid),
            "empreinte_source_contrat": hex::encode(blake2b_simd::Params::new().hash_length(32).hash(include_str!("../../contracts/agent_budget.sil").as_bytes()).as_bytes()),
        },
    });
    fusion(&mut r, &commun);
    Ok(r)
}

fn fusion(r: &mut Value, commun: &Value) {
    if let (Some(a), Some(b)) = (r.as_object_mut(), commun.as_object()) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
}

fn journal(entree: Value) {
    use std::io::Write;
    let ligne = json!({ "instant": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0), "action": entree });
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open("console-journal.jsonl") {
        let _ = writeln!(f, "{ligne}");
    }
    crate::sobriete::borner("console-journal.jsonl", crate::sobriete::JOURNAL_MAX);
}

/// La démo ouvre la console dans le navigateur par défaut (rien à recopier pour la filmer).
pub static OUVRIR_NAVIGATEUR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Ouvre un lien local dans le navigateur par défaut ; un échec n'empêche rien (le lien est affiché).
fn ouvrir_navigateur(lien: &str) {
    #[cfg(windows)]
    let r = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", lien]).spawn();
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg(lien).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let r = std::process::Command::new("xdg-open").arg(lien).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    if r.is_err() {
        eprintln!("(navigateur non ouvert automatiquement : ouvrez le lien ci-dessus)");
    }
}

/// Durée de vie d'un ticket d'ouverture : le temps d'ouvrir le lien, pas plus.
const TICKET_DUREE: Duration = Duration::from_secs(120);

/// Session de la console (R73). Le jeton de session n'apparaît jamais dans un lien : le lien affiché
/// dans le terminal et remis au navigateur ne porte qu'un ticket à usage unique, valable deux
/// minutes, que la page échange contre le jeton. Les arguments d'une commande étant lisibles par les
/// autres utilisateurs de l'ordinateur, un ticket lu trop tard ne vaut plus rien. Et si quelqu'un
/// l'échange avant le propriétaire, celui-ci le voit (« ce lien a déjà servi ») et reprend la main :
/// chaque échange ouvre une session neuve et ferme la précédente.
pub struct Session {
    jeton: std::sync::Mutex<String>,
    /// Tickets en attente (valeur, échéance).
    tickets: std::sync::Mutex<Vec<(String, Instant)>>,
    /// Tickets déjà échangés ou expirés (pour un message clair ; ils ne valent plus rien).
    servis: std::sync::Mutex<Vec<String>>,
    /// Faux dans les tests à jeton fixe : l'échange rend alors le jeton sans le renouveler.
    tournant: bool,
}

/// Pourquoi un ticket est refusé.
#[derive(Debug, PartialEq)]
pub enum TicketRefuse {
    DejaServi,
    Inconnu,
}

fn alea_hex() -> Res<String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| format!("aléa : {e}"))?;
    Ok(hex::encode(b))
}

impl Session {
    pub fn nouvelle() -> Res<Self> {
        Ok(Session { jeton: std::sync::Mutex::new(alea_hex()?), tickets: Default::default(), servis: Default::default(), tournant: true })
    }

    /// Session à jeton fixe, pour les tests des autres protections.
    #[cfg(test)]
    pub fn fixe(jeton: &str) -> Self {
        Session { jeton: std::sync::Mutex::new(jeton.into()), tickets: Default::default(), servis: Default::default(), tournant: false }
    }

    fn ranger_expires(&self, maintenant: Instant) {
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        let mut servis = self.servis.lock().unwrap_or_else(|e| e.into_inner());
        let (vivants, morts): (Vec<_>, Vec<_>) = tickets.drain(..).partition(|(_, fin)| maintenant < *fin);
        *tickets = vivants;
        servis.extend(morts.into_iter().map(|(t, _)| t));
        let trop = servis.len().saturating_sub(64);
        servis.drain(..trop);
    }

    /// Nouveau ticket à usage unique (8 en attente au plus : les plus anciens sont annulés).
    pub fn ticket(&self) -> Res<String> {
        self.ticket_a(Instant::now())
    }

    fn ticket_a(&self, maintenant: Instant) -> Res<String> {
        self.ranger_expires(maintenant);
        let t = alea_hex()?;
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        if tickets.len() >= 8 {
            tickets.remove(0);
        }
        tickets.push((t.clone(), maintenant + TICKET_DUREE));
        Ok(t)
    }

    /// Échange un ticket contre le jeton de session : une seule fois. La session précédente est fermée.
    pub fn echanger(&self, ticket: &str) -> Result<String, TicketRefuse> {
        self.echanger_a(ticket, Instant::now())
    }

    fn echanger_a(&self, ticket: &str, maintenant: Instant) -> Result<String, TicketRefuse> {
        self.ranger_expires(maintenant);
        let trouve = {
            let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
            let i = tickets.iter().position(|(t, _)| egal(t.as_bytes(), ticket.as_bytes()));
            i.map(|i| tickets.remove(i).0)
        };
        let mut servis = self.servis.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = trouve else {
            return Err(if servis.iter().any(|s| egal(s.as_bytes(), ticket.as_bytes())) { TicketRefuse::DejaServi } else { TicketRefuse::Inconnu });
        };
        servis.push(t);
        let mut jeton = self.jeton.lock().unwrap_or_else(|e| e.into_inner());
        if self.tournant {
            *jeton = alea_hex().map_err(|_| TicketRefuse::Inconnu)?;
        }
        Ok(jeton.clone())
    }

    fn jeton_ok(&self, presente: Option<String>) -> bool {
        let jeton = self.jeton.lock().unwrap_or_else(|e| e.into_inner());
        presente.is_some_and(|j| egal(j.as_bytes(), jeton.as_bytes()))
    }

    /// Réponse à `POST /api/session` (en-tête `X-Ticket`).
    fn repondre_echange(&self, ticket: Option<String>) -> Rep {
        match self.echanger(ticket.as_deref().unwrap_or("")) {
            Ok(jeton) => {
                journal(json!({ "session": "ouverte par un lien à usage unique" }));
                json_rep(200, json!({ "jeton": jeton }))
            }
            Err(TicketRefuse::DejaServi) => {
                journal(json!({ "session": "lien déjà utilisé présenté de nouveau" }));
                json_rep(410, json!({ "erreur": "ce lien a déjà servi ou a expiré (il ne s'ouvre qu'une fois, dans les deux minutes) : appuyez sur Entrée dans le terminal pour en obtenir un nouveau", "motif": "deja_servi" }))
            }
            Err(TicketRefuse::Inconnu) => json_rep(401, json!({ "erreur": "lien invalide : appuyez sur Entrée dans le terminal pour en obtenir un nouveau", "motif": "inconnu" })),
        }
    }
}

/// Lien affiché dans le terminal et remis au navigateur : il porte un ticket à usage unique dans
/// son fragment (jamais envoyé au serveur dans l'URL), jamais le jeton de session (R73).
fn lien_de_session(port: u16, session: &Session) -> Res<String> {
    Ok(format!("http://127.0.0.1:{port}/#ticket={}", session.ticket()?))
}

/// Affiche le lien d'ouverture, l'ouvre si demandé, puis écoute le clavier : chaque appui sur Entrée
/// affiche un nouveau lien (le précédent ne s'ouvre qu'une fois).
fn annoncer_lien(titre: &str, session: &std::sync::Arc<Session>) -> Res<()> {
    let lien = lien_de_session(PORT, session)?;
    println!("{titre} : ouvrez {lien}");
    println!("(lien personnel : il ne s'ouvre qu'une fois, dans les deux minutes. Pour un nouveau lien, appuyez sur Entrée ici. Ctrl+C pour arrêter)");
    if OUVRIR_NAVIGATEUR.load(std::sync::atomic::Ordering::Relaxed) {
        ouvrir_navigateur(&lien);
    }
    let s = session.clone();
    std::thread::spawn(move || {
        let mut ligne = String::new();
        // fin de l'entrée (lancement sans terminal) : on arrête d'écouter, la console continue
        while std::io::stdin().read_line(&mut ligne).is_ok_and(|n| n > 0) {
            ligne.clear();
            match lien_de_session(PORT, &s) {
                Ok(l) => println!("Nouveau lien (une seule ouverture, deux minutes ; il ferme la session précédente) : {l}"),
                Err(e) => eprintln!("nouveau lien impossible : {e}"),
            }
        }
    });
    Ok(())
}

pub fn lancer(handle: Handle, owner: Keypair, agent: Keypair) -> Res<()> {
    let session = std::sync::Arc::new(Session::nouvelle()?);
    let serveur = tiny_http::Server::http(format!("127.0.0.1:{PORT}")).map_err(|e| format!("écoute 127.0.0.1:{PORT} : {e}"))?;
    annoncer_lien("Console du propriétaire", &session)?;
    servir(&serveur, &session, handle, owner, agent, std::env::var("PROPRIETAIRE_CLE").ok(), None);
    Ok(())
}

/// Fichiers du compte dans `dossier` : clé du propriétaire chiffrée, clé de l'agent principal, état.
pub struct FichiersCompte {
    pub cle: String,
    pub agent: String,
}

pub fn fichiers_compte(dossier: &str) -> FichiersCompte {
    let p = std::path::Path::new(dossier);
    FichiersCompte {
        cle: p.join("proprietaire.json").to_string_lossy().into_owned(),
        agent: p.join("agent-principal.key").to_string_lossy().into_owned(),
    }
}

/// Clé de l'agent principal du compte, chiffrée sur le disque par le mot de passe du propriétaire
/// (même dérivation et même format que sa propre clé, `cle::Enveloppe`). Rend aussi l'enveloppe de la
/// session, qui chiffrera les clés des nouveaux agents sans redemander le mot de passe.
///  - fichier absent (premier lancement, ou restauration sur un autre ordinateur) : clé neuve, chiffrée ;
///  - fichier en clair (version précédente) : migration, le clair est effacé ;
///  - fichier chiffré : ouvert avec le mot de passe. S'il a été chiffré sous un ancien mot de passe
///    (compte restauré depuis la phrase), la clé privée n'est plus lisible mais la clé publique l'est :
///    la console n'a besoin que d'elle (surveiller, alimenter, geler restent possibles).
fn cle_agent_compte(chemin: &str, mot_de_passe: &str) -> Res<(agents::Principal, cle::Enveloppe)> {
    match agents::lire_cle_stockee(chemin)? {
        Some(agents::CleStockee::Chiffree(f)) => {
            let enveloppe = cle::Enveloppe::du_fichier(&f, mot_de_passe)?;
            match enveloppe.dechiffrer(&f) {
                Ok(k) => Ok((k.into(), enveloppe)),
                Err(_) => {
                    journal(json!({ "agent_principal": "clé chiffrée sous un autre mot de passe : clé publique seule" }));
                    Ok((agents::Principal::publique_seule(secp256k1::PublicKey::from_slice(&hex::decode(&f.publique)?)?), enveloppe))
                }
            }
        }
        Some(agents::CleStockee::Claire(k)) => {
            let enveloppe = cle::Enveloppe::nouvelle(mot_de_passe)?;
            agents::chiffrer_fichier(chemin, &enveloppe)?;
            journal(json!({ "agent_principal": "clé chiffrée sur le disque (elle était en clair)" }));
            Ok((k.into(), enveloppe))
        }
        None => {
            let enveloppe = cle::Enveloppe::nouvelle(mot_de_passe)?;
            let k = cle::nouvelle()?;
            if let Some(d) = std::path::Path::new(chemin).parent() {
                fs::create_dir_all(d)?;
            }
            agents::ecrire_cle(std::path::Path::new(chemin), &k, Some(&enveloppe))?;
            Ok((k.into(), enveloppe))
        }
    }
}

/// Console du compte : s'ouvre verrouillée. La page propose de créer le compte (aucun fichier de clé)
/// ou de s'y connecter (mot de passe, puis code à 6 chiffres si la double authentification est active).
/// Rien ne quitte l'ordinateur : il n'y a ni serveur de comptes ni e-mail.
pub fn lancer_compte(handle: Handle, dossier: String) -> Res<()> {
    fs::create_dir_all(&dossier)?;
    *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::path::Path::new(&dossier).join("etat-coffre.json").to_string_lossy().into_owned());
    let session = std::sync::Arc::new(Session::nouvelle()?);
    let serveur = tiny_http::Server::http(format!("127.0.0.1:{PORT}")).map_err(|e| format!("écoute 127.0.0.1:{PORT} : {e}"))?;
    annoncer_lien("Plafond", &session)?;
    let fichiers = fichiers_compte(&dossier);
    let (owner, agent, enveloppe) = porte(&serveur, &session, &fichiers)?;
    println!("Compte ouvert.");
    servir(&serveur, &session, handle, owner, agent, Some(fichiers.cle), Some(enveloppe));
    Ok(())
}

/// Compte ouvert : clé du propriétaire, agent principal, et enveloppe qui chiffre les clés d'agent.
pub type CompteOuvert = (Keypair, agents::Principal, cle::Enveloppe);

/// Phase verrouillée : seules la page, l'état du compte, la création et la connexion répondent.
pub fn porte(serveur: &tiny_http::Server, session: &Session, fichiers: &FichiersCompte) -> Res<CompteOuvert> {
    let port = serveur.server_addr().to_ip().map(|a| a.port()).unwrap_or(PORT);
    let hotes = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let origines = [format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")];
    let mut garde = Garde::neuve();
    for mut req in serveur.incoming_requests() {
        let entetes: Vec<(String, String)> = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_string())).collect();
        let entete = |nom: &str| entetes.iter().find(|(k, _)| k == &nom.to_ascii_lowercase()).map(|(_, v)| v.clone());
        let chemin = req.url().split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        let mut ouvert = None;
        let rep = if !entete("Host").is_some_and(|h| hotes.contains(&h)) {
            json_rep(421, json!({ "erreur": "hôte non autorisé" }))
        } else if methode == "GET" && chemin == "/" {
            reponse(200, "text/html; charset=utf-8", PAGE.as_bytes().to_vec())
        } else if methode == "POST" && chemin == "/api/session" {
            if entete("Origin").is_none_or(|o| origines.contains(&o)) { session.repondre_echange(entete("X-Ticket")) } else { json_rep(403, json!({ "erreur": "origine refusée" })) }
        } else if !session.jeton_ok(entete("X-Jeton")) {
            json_rep(401, json!({ "erreur": "session fermée ou invalide : appuyez sur Entrée dans le terminal pour obtenir un nouveau lien" }))
        } else if methode == "POST" && !entete("Origin").is_none_or(|o| origines.contains(&o)) {
            json_rep(403, json!({ "erreur": "origine refusée" }))
        } else {
            let mut corps = String::new();
            let _ = req.as_reader().take(16 * 1024).read_to_string(&mut corps);
            let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
            zeroize::Zeroize::zeroize(&mut corps);
            let existe = std::path::Path::new(&fichiers.cle).exists();
            match (methode.as_str(), chemin.as_str()) {
                ("GET", "/api/compte/etat") => json_rep(200, json!({ "ouvert": false, "existe": existe, "double_auth": lire_compte(Some(&fichiers.cle)).double_auth })),
                ("POST", "/api/compte/creer") => {
                    let mdp = zeroize::Zeroizing::new(v["mot_de_passe"].as_str().unwrap_or("").to_string());
                    let conf = zeroize::Zeroizing::new(v["confirmation"].as_str().unwrap_or("").to_string());
                    if existe {
                        json_rep(409, json!({ "erreur": "un compte existe déjà sur cet ordinateur : connectez-vous" }))
                    } else if mdp.chars().count() < 12 {
                        json_rep(400, json!({ "erreur": "mot de passe trop court (12 caractères minimum)" }))
                    } else if *mdp != *conf {
                        json_rep(400, json!({ "erreur": "les deux mots de passe diffèrent" }))
                    } else {
                        let cree = (|| -> Res<CompteOuvert> {
                            if let Some(d) = std::path::Path::new(&fichiers.cle).parent() {
                                fs::create_dir_all(d)?;
                            }
                            let c = cle::nouveau_coffret()?;
                            cle::ecrire(&fichiers.cle, &cle::chiffrer_coffret(&c, &mdp)?)?;
                            ecrire_compte(&fichiers.cle, &Compte::default())?;
                            let (agent, enveloppe) = cle_agent_compte(&fichiers.agent, &mdp)?;
                            Ok((cle::cle_du_coffret(&c)?, agent, enveloppe))
                        })();
                        match cree {
                            Ok(k) => {
                                journal(json!({ "compte": "créé" }));
                                ouvert = Some(k);
                                json_rep(200, json!({ "ouvert": true, "cree": true }))
                            }
                            Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                        }
                    }
                }
                ("POST", "/api/compte/restaurer") => {
                    // Mot de passe oublié : la phrase de 24 mots recrée la clé, chiffrée par un nouveau mot de
                    // passe. L'ancien fichier n'est jamais effacé : il est mis de côté sous un autre nom.
                    let phrase = zeroize::Zeroizing::new(v["phrase"].as_str().unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" "));
                    let mdp = zeroize::Zeroizing::new(v["mot_de_passe"].as_str().unwrap_or("").to_string());
                    let conf = zeroize::Zeroizing::new(v["confirmation"].as_str().unwrap_or("").to_string());
                    if garde.verrou.is_some_and(|t| Instant::now() < t) {
                        json_rep(429, json!({ "erreur": "trop d'essais : réessayez dans une minute" }))
                    } else if mdp.chars().count() < 12 {
                        json_rep(400, json!({ "erreur": "mot de passe trop court (12 caractères minimum)" }))
                    } else if *mdp != *conf {
                        json_rep(400, json!({ "erreur": "les deux mots de passe diffèrent" }))
                    } else {
                        match cle::depuis_phrase(&phrase) {
                            Err(_) => garde.echec("phrase de récupération invalide"),
                            Ok(c) => {
                                let fait = (|| -> Res<CompteOuvert> {
                                    if let Some(d) = std::path::Path::new(&fichiers.cle).parent() {
                                        fs::create_dir_all(d)?;
                                    }
                                    if existe {
                                        fs::rename(&fichiers.cle, format!("{}.ancien-{}", fichiers.cle, double_auth::maintenant()))?;
                                    }
                                    cle::ecrire(&fichiers.cle, &cle::chiffrer_coffret(&c, &mdp)?)?;
                                    ecrire_compte(&fichiers.cle, &Compte { sauvegarde_faite: true, double_auth: false })?;
                                    let (agent, enveloppe) = cle_agent_compte(&fichiers.agent, &mdp)?;
                                    Ok((cle::cle_du_coffret(&c)?, agent, enveloppe))
                                })();
                                match fait {
                                    Ok(k) => {
                                        journal(json!({ "compte": "restauré depuis la phrase" }));
                                        ouvert = Some(k);
                                        json_rep(200, json!({ "ouvert": true }))
                                    }
                                    Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                                }
                            }
                        }
                    }
                }
                ("POST", "/api/compte/ouvrir") if !existe => json_rep(404, json!({ "erreur": "aucun compte sur cet ordinateur : créez-en un" })),
                ("POST", "/api/compte/ouvrir") => match garde.ouvrir_avec(Some(fichiers.cle.as_str()), None, &v, true) {
                    Ok((owner, _)) => match cle_agent_compte(&fichiers.agent, &zeroize::Zeroizing::new(v["mot_de_passe"].as_str().unwrap_or("").to_string())) {
                        Ok((agent, enveloppe)) => {
                            journal(json!({ "compte": "ouvert" }));
                            ouvert = Some((owner, agent, enveloppe));
                            json_rep(200, json!({ "ouvert": true }))
                        }
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                    Err(r) => r,
                },
                _ => json_rep(423, json!({ "erreur": "compte verrouillé : connectez-vous", "verrouille": true })),
            }
        };
        let _ = req.respond(rep);
        if let Some(k) = ouvert {
            return Ok(k);
        }
    }
    Err("console arrêtée avant l'ouverture du compte".into())
}

/// Indicateurs non secrets du compte (à côté du fichier de clé) : affichage seulement. Ce qui fait
/// foi pour la double authentification est le fichier de clé chiffré lui-même.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Compte {
    sauvegarde_faite: bool,
    double_auth: bool,
}

fn chemin_compte(chemin_cle: &str) -> String {
    match chemin_cle.strip_suffix(".json") {
        Some(base) => format!("{base}-compte.json"),
        None => format!("{chemin_cle}-compte.json"),
    }
}

fn lire_compte(chemin_cle: Option<&str>) -> Compte {
    chemin_cle.and_then(|c| fs::read_to_string(chemin_compte(c)).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn ecrire_compte(chemin_cle: &str, c: &Compte) -> Res<()> {
    fs::write(chemin_compte(chemin_cle), serde_json::to_string_pretty(c)?)?;
    Ok(())
}

type Rep = tiny_http::Response<std::io::Cursor<Vec<u8>>>;

fn connexion_json(a: &agents::Agent) -> Value {
    if a.cle == "env" {
        json!({ "etat": "environnement" })
    } else if let Some(t) = a.connecte_le {
        json!({ "etat": "connecte", "connecte_le": t })
    } else {
        json!({ "etat": "local" })
    }
}

/// Kit de connexion d'un agent : sa clé, les règles et l'état de son coffre, ses secrets chiffrés.
/// La clé de l'agent est chiffrée sur le disque de la console : il faut l'enveloppe de la session ou le
/// mot de passe du propriétaire (déjà exigé pour cette action depuis R72) pour l'ouvrir.
pub(crate) fn preparer_kit(a: &agents::Agent, owner: &Keypair, defaut: &str, mot_de_passe: Option<&str>, enveloppe: Option<&cle::Enveloppe>) -> Res<(connexion::Scelle, zeroize::Zeroizing<String>)> {
    let k = agents::cle_privee(a, mot_de_passe, enveloppe)?;
    let hexa = zeroize::Zeroizing::new(hex::encode(k.secret_bytes()));
    let lire = |p: &str| fs::read_to_string(p).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let base = agents::base_fichiers(a, defaut);
    let kit = connexion::Kit {
        agent_id: a.id.clone(),
        nom: a.nom.clone(),
        cle_agent: hexa.trim().to_string(),
        publique: hex::encode(k.public_key().serialize()),
        proprietaire: hex::encode(xonly(owner)),
        regles: a.regles,
        origine: lire(&a.etat.replace(".json", "-origine.json")),
        etat: lire(&a.etat),
        secrets: lire(&base.strip_suffix(".key").map(|b| format!("{b}.secrets.json")).unwrap_or_default()).unwrap_or(json!({})),
        reseau: "testnet-10".into(),
        cree_le: double_auth::maintenant(),
    };
    let code = connexion::nouveau_code()?;
    Ok((connexion::sceller(&kit, &code)?, code))
}

/// Garde des actions sensibles (voir la phrase, exporter la clé, activer la double authentification) :
/// mot de passe, puis code à 6 chiffres si la double authentification est active ; 5 échecs = 60 s.
struct Garde {
    echecs: u32,
    verrou: Option<Instant>,
    dernier_pas: u64,
    /// Échecs de code à 6 chiffres : comptés à part, jamais remis à zéro par un mot de passe seul (R67).
    echecs_code: u32,
    /// Verrous consécutifs dus aux codes : chaque nouveau verrou dure deux fois plus (1 h au plus).
    verrous_code: u32,
    /// Console lancée sans enveloppe (clé déverrouillée dans le terminal) : le prochain mot de passe
    /// vérifié est retenu le temps de dériver l'enveloppe des clés d'agent, puis effacé.
    retenir_mdp: bool,
    mdp_verifie: Option<zeroize::Zeroizing<String>>,
}

impl Garde {
    fn neuve() -> Self {
        Garde { echecs: 0, verrou: None, dernier_pas: 0, echecs_code: 0, verrous_code: 0, retenir_mdp: false, mdp_verifie: None }
    }

    fn ouvrir(&mut self, chemin_cle: Option<&str>, owner: &Keypair, v: &Value, exiger_code: bool) -> Result<(Keypair, Option<cle::Coffret>), Rep> {
        self.ouvrir_avec(chemin_cle, Some(owner), v, exiger_code)
    }

    /// `attendu` : clé que le fichier doit contenir (None à la connexion, quand rien n'est encore chargé).
    fn ouvrir_avec(&mut self, chemin_cle: Option<&str>, attendu: Option<&Keypair>, v: &Value, exiger_code: bool) -> Result<(Keypair, Option<cle::Coffret>), Rep> {
        let Some(chemin) = chemin_cle else {
            return Err(json_rep(409, json!({ "erreur": "mode test : clés dérivées d'une phrase de test, aucun fichier de clé" })));
        };
        if self.verrou.is_some_and(|t| Instant::now() < t) {
            return Err(json_rep(429, json!({ "erreur": "trop d'essais : réessayez dans une minute" })));
        }
        let mdp = zeroize::Zeroizing::new(v["mot_de_passe"].as_str().unwrap_or("").to_string());
        let ouvert = cle::lire(chemin).and_then(|f| cle::ouvrir_tout(&f, &mdp)).ok().filter(|(k, _)| attendu.is_none_or(|o| k.x_only_public_key() == o.x_only_public_key()));
        let Some((k, coffret)) = ouvert else {
            return Err(self.echec("mot de passe incorrect"));
        };
        if exiger_code {
            if let Some(secret) = coffret.as_ref().and_then(|c| c.totp.as_ref()) {
                match double_auth::verifier(secret, v["code"].as_str().unwrap_or(""), double_auth::maintenant(), self.dernier_pas) {
                    Some(pas) => {
                        self.dernier_pas = pas;
                        self.echecs_code = 0;
                        self.verrous_code = 0;
                    }
                    None => {
                        self.echecs = 0; // le mot de passe, lui, était bon
                        self.echec_secret("code de double authentification incorrect ou expiré");
                        return Err(json_rep(403, json!({ "erreur": "code de double authentification incorrect ou expiré" })));
                    }
                }
            }
        }
        self.echecs = 0;
        if self.retenir_mdp {
            self.mdp_verifie = Some(mdp);
        }
        Ok((k, coffret))
    }

    /// Échec sur un secret autre que le mot de passe (code à 6 chiffres, mots de la phrase). Compté à
    /// part : un mot de passe juste ne le remet pas à zéro (R67). 5 échecs = verrou d'une minute, doublé
    /// à chaque verrou consécutif (1 h au plus) ; seul un code juste remet ces compteurs à zéro.
    fn echec_secret(&mut self, quoi: &str) {
        self.echecs_code += 1;
        if self.echecs_code >= 5 {
            let duree = 60u64.saturating_mul(1 << self.verrous_code.min(6)).min(3600);
            self.verrou = Some(Instant::now() + Duration::from_secs(duree));
            self.echecs_code = 0;
            self.verrous_code = self.verrous_code.saturating_add(1);
        }
        journal(json!({ "action_sensible": "refusée", "motif": quoi }));
    }

    fn echec(&mut self, quoi: &str) -> Rep {
        self.echecs += 1;
        if self.echecs >= 5 {
            self.verrou = Some(Instant::now() + Duration::from_secs(60));
            self.echecs = 0;
        }
        journal(json!({ "action_sensible": "refusée", "motif": quoi }));
        json_rep(403, json!({ "erreur": quoi }))
    }
}

fn param(url: &str, nom: &str) -> Option<String> {
    url::Url::parse(&format!("http://h{url}")).ok()?.query_pairs().find(|(k, _)| k == nom).map(|(_, v)| v.into_owned())
}

fn resultat(r: Res<String>) -> Rep {
    match r {
        Ok(txid) => json_rep(200, json!({ "transaction": txid, "explorateur": explorer(&txid) })),
        Err(e) => json_rep(502, json!({ "erreur": e.to_string() })),
    }
}

/// Boucle de la console (séparée pour être testée sur un port libre).
///
/// `enveloppe` : clé de chiffrement des clés d'agent, dérivée du mot de passe à l'ouverture du compte.
/// Absente quand la console est lancée avec une clé déjà déverrouillée dans le terminal (commande
/// `console`) : elle est alors dérivée à la première action qui demande le mot de passe, et les clés
/// d'agent encore en clair sont chiffrées à ce moment-là. Sans fichier de clé (clés de test), il n'y a
/// pas de mot de passe : les clés d'agent restent en clair, protégées par les seuls droits du fichier.
pub fn servir(serveur: &tiny_http::Server, session: &Session, handle: Handle, owner: Keypair, agent_principal: impl Into<agents::Principal>, chemin_cle: Option<String>, enveloppe: Option<cle::Enveloppe>) {
    let agent_principal: agents::Principal = agent_principal.into();
    let mut enveloppe = enveloppe;
    let port = serveur.server_addr().to_ip().map(|a| a.port()).unwrap_or(PORT);
    let hotes = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let origines = [format!("http://127.0.0.1:{port}"), format!("http://localhost:{port}")];
    let mut cours = Cours { valeur: None, lu: None };
    let mut garde = Garde::neuve();
    // Secret de double authentification en cours d'activation (en mémoire seulement).
    let mut double_auth_en_attente: Option<zeroize::Zeroizing<Vec<u8>>> = None;
    // Agent dont le kit de connexion a été remis, en attente de confirmation (mémoire seulement).
    let mut connexion_en_attente: Option<String> = None;
    let defaut = etat_par_defaut();
    let cle_ch = chemin_cle.as_deref();
    // Migration : les clés d'agent encore en clair sont chiffrées dès que le mot de passe est connu.
    let migrer = |e: &cle::Enveloppe| {
        let n = agents::chiffrer_cles_en_clair(&defaut, e);
        if n > 0 {
            journal(json!({ "cles_agent": "chiffrées sur le disque (elles étaient en clair)", "nombre": n }));
        }
    };
    if let Some(e) = &enveloppe {
        migrer(e);
    }
    garde.retenir_mdp = enveloppe.is_none() && cle_ch.is_some();
    for mut req in serveur.incoming_requests() {
        let entetes: Vec<(String, String)> = req.headers().iter().map(|h| (h.field.as_str().as_str().to_ascii_lowercase(), h.value.as_str().to_string())).collect();
        let entete = |nom: &str| entetes.iter().find(|(k, _)| k == &nom.to_ascii_lowercase()).map(|(_, v)| v.clone());
        let hote_ok = entete("Host").is_some_and(|h| hotes.contains(&h));
        let url = req.url().to_string();
        let chemin = url.split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        let jeton_ok = session.jeton_ok(entete("X-Jeton"));
        let origine_ok = entete("Origin").is_none_or(|o| origines.contains(&o));
        let rep = if !hote_ok {
            json_rep(421, json!({ "erreur": "hôte non autorisé" }))
        } else if methode == "GET" && chemin == "/" {
            reponse(200, "text/html; charset=utf-8", PAGE.as_bytes().to_vec())
        } else if methode == "POST" && chemin == "/api/session" {
            if origine_ok { session.repondre_echange(entete("X-Ticket")) } else { json_rep(403, json!({ "erreur": "origine refusée" })) }
        } else if !jeton_ok {
            json_rep(401, json!({ "erreur": "session fermée ou invalide : appuyez sur Entrée dans le terminal pour obtenir un nouveau lien" }))
        } else if methode == "POST" && !origine_ok {
            json_rep(403, json!({ "erreur": "origine refusée" }))
        } else {
            let mut corps = String::new();
            let _ = req.as_reader().take(16 * 1024).read_to_string(&mut corps);
            let v: Value = serde_json::from_str(&corps).unwrap_or(Value::Null);
            zeroize::Zeroize::zeroize(&mut corps); // le corps peut contenir un secret d'agent
            let liste = agents::charger(&defaut);
            // Agent visé : paramètre `agent` (URL ou corps), le principal par défaut.
            let id = param(&url, "agent").or_else(|| v["agent"].as_str().map(String::from)).unwrap_or_else(|| agents::PRINCIPAL.into());
            let cible = liste.iter().find(|a| a.id == id).cloned();
            let cle_cible = cible.as_ref().map(|a| agents::cle(a, &agent_principal));
            match (methode.as_str(), chemin.as_str()) {
                ("GET", "/api/compte/etat") => json_rep(200, json!({ "ouvert": true })),
                ("POST", "/api/compte/creer" | "/api/compte/ouvrir" | "/api/compte/restaurer") => json_rep(409, json!({ "erreur": "compte déjà ouvert" })),
                // ---------- Trésorerie et agents ----------
                ("GET", "/api/agents") => {
                    let c = cours.lire();
                    let mut vus = Vec::new();
                    let mut solde = None;
                    let mut couloirs = Vec::new();
                    let mut instant = 0i64;
                    for a in &liste {
                        let Ok(k) = agents::cle(a, &agent_principal) else { continue };
                        let t = avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(tableau(&owner, &k, c.clone())));
                        let mut ligne = json!({ "id": a.id, "nom": a.nom, "identifiant": agents::xonly_pub(a, &agent_principal).map(hex::encode), "connexion": connexion_json(a), "echeance": a.echeance });
                        match t {
                            Ok(t) => {
                                // Échéance du mandat atteinte : révocation automatique (les fonds reviennent en
                                // trésorerie). Confort : la garantie reste le capital alloué.
                                let actif = !matches!(t["sante"].as_str(), Some("gele") | Some("aucun") | None);
                                if actif && a.echeance.is_some_and(|e| crate::double_auth::maintenant() >= e) {
                                    let r = avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(geler(&owner, &k, false, 0)));
                                    journal(json!({ "echeance": a.id, "resultat": r.as_ref().map_err(|e| e.to_string()) }));
                                    if r.is_ok() {
                                        agents::noter(&defaut, &a.nom, "echeance", None);
                                    }
                                }
                                if t["solde_proprietaire_sompi"].is_u64() {
                                    solde = t["solde_proprietaire_sompi"].as_u64();
                                }
                                for cle in ["sante", "solde_coffre_sompi", "exposition_immediate_sompi", "pire_24h_sompi", "depense_periode_sompi", "regles"] {
                                    ligne[cle] = t[cle].clone();
                                }
                                ligne["achats"] = json!(t["historique"].as_array().map(|h| h.iter().filter(|m| m["genre"] == "achat").count()).unwrap_or(0));
                                if let Some(now) = t["risque_now"].as_i64() {
                                    instant = instant.max(now); // le plus tard : borne prudente (le disponible ne fait que croître)
                                }
                                for rc in t["risque_pieces"].as_array().into_iter().flatten() {
                                    if let (Ok(params), Some(creation), Some(valeur)) = (serde_json::from_value(rc["params"].clone()), rc["creation"].as_i64(), rc["valeur"].as_u64()) {
                                        couloirs.push(crate::risque::Couloir { agent: a.nom.clone(), params, creation, valeur });
                                    }
                                }
                            }
                            Err(e) => ligne["erreur"] = json!(e.to_string()),
                        }
                        vus.push(ligne);
                    }
                    if solde.is_none() {
                        solde = handle.block_on(async {
                            let c = connect_silencieux().await?;
                            let s: u64 = c.get_utxos_by_addresses(vec![address(&owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
                            liberer(&c).await?;
                            Ok::<u64, Box<dyn std::error::Error>>(s)
                        }).ok();
                    }
                    let compte = lire_compte(cle_ch);
                    json_rep(200, json!({
                        "agents": vus, "solde_proprietaire_sompi": solde, "adresse_proprietaire": address(&owner).to_string(),
                        "risque": crate::risque::rapport(&couloirs, &[], instant, crate::JOUR_DAA), "cours": c, "tarif_reference_sompi": tarif_reference(),
                        "compte": { "mode": if cle_ch.is_some() { "fichier_chiffre" } else { "cles_de_test" }, "sauvegarde_faite": compte.sauvegarde_faite, "double_auth": compte.double_auth },
                    }))
                }
                ("GET", "/api/evenements") => json_rep(200, json!({ "evenements": agents::evenements(&defaut, 30) })),
                ("GET", "/api/tableau") => match (&cible, cle_cible) {
                    (Some(a), Some(Ok(k))) => {
                        let c = cours.lire();
                        match avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(tableau(&owner, &k, c))) {
                            Ok(mut t) => {
                                t["agent"] = json!({ "id": a.id, "nom": a.nom, "identifiant": agents::xonly_pub(a, &agent_principal).map(hex::encode), "connexion": connexion_json(a) });
                                json_rep(200, t)
                            }
                            Err(e) => json_rep(503, json!({ "erreur": e.to_string() })),
                        }
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                // Créer un agent = l'inscrire (clé neuve) puis ouvrir son coffre. Si l'ouverture échoue
                // (trésorerie vide), l'agent reste inscrit et son coffre pourra être ouvert ensuite.
                ("POST", "/api/agents") => {
                    if v["confirmation"].as_str() != Some("CREER") {
                        json_rep(400, json!({ "erreur": "confirmation requise" }))
                    } else {
                        let mandat = regles_mandat(&v);
                        let duree = mandat.as_ref().ok().and_then(|(_, d)| *d);
                        match mandat.and_then(|(r, _)| agents::nouveau(&defaut, v["nom"].as_str().unwrap_or(""), Some(r), enveloppe.as_ref())) {
                            Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                            Ok(a) => {
                                if let Some(j) = duree {
                                    let _ = agents::fixer_echeance(&defaut, &a.id, Some(crate::double_auth::maintenant() + j as u64 * 86_400));
                                }
                                let r = agents::cle(&a, &agent_principal).and_then(|k| avec_coffre(&a.etat, a.regles, agents::xonly_pub(&a, &agent_principal), || handle.block_on(deployer(&owner, &k))));
                                journal(json!({ "nouvel_agent": a.id, "coffre": r.as_ref().map_err(|e| e.to_string()) }));
                                match r {
                                    Ok(txid) => json_rep(200, json!({ "agent": a.id, "transaction": txid, "explorateur": explorer(&txid) })),
                                    Err(e) => json_rep(200, json!({ "agent": a.id, "coffre_ouvert": false, "detail": e.to_string() })),
                                }
                            }
                        }
                    }
                }
                // Aperçu des règles avant création : la plateforme calcule, l'utilisateur ne règle que 3 choses.
                ("POST", "/api/regles") => match regles_mandat(&v) {
                    Ok((r, duree)) => {
                        let mut j = regles_json(&r);
                        j["duree_jours"] = json!(duree);
                        json_rep(200, j)
                    }
                    Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                },
                // ---------- Secrets de l'agent : écriture seule ----------
                // La valeur est chiffrée pour la clé publique de l'agent puis effacée ; aucune route ne la
                // renvoie, et le journal n'en garde que le nom, le fournisseur et la date.
                ("GET", "/api/secrets") => match &cible {
                    Some(a) => json_rep(200, json!({ "secrets": secrets::lister(&agents::base_fichiers(a, &defaut)) })),
                    None => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                ("POST", "/api/secrets") => match (&cible, cible.as_ref().map(|a| agents::publique(a, &agent_principal))) {
                    (Some(a), Some(Ok(k))) => {
                        let valeur = zeroize::Zeroizing::new(v["valeur"].as_str().unwrap_or("").to_string());
                        let (nom, fournisseur) = (v["nom"].as_str().unwrap_or(""), v["fournisseur"].as_str().unwrap_or(""));
                        match secrets::enregistrer(&agents::base_fichiers(a, &defaut), &k, nom, fournisseur, valeur) {
                            Ok(()) => {
                                journal(json!({ "secret": "enregistré", "agent": a.id, "nom": nom, "fournisseur": fournisseur }));
                                json_rep(200, json!({ "ok": true }))
                            }
                            Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                        }
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                ("POST", "/api/secrets/supprimer") => match &cible {
                    Some(a) => match secrets::supprimer(&agents::base_fichiers(a, &defaut), v["nom"].as_str().unwrap_or("")) {
                        Ok(()) => {
                            journal(json!({ "secret": "supprimé", "agent": a.id, "nom": v["nom"] }));
                            json_rep(200, json!({ "ok": true }))
                        }
                        Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                    },
                    None => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                // ---------- Connecter l'agent ----------
                // 1. Préparer : kit scellé par un code à usage unique (affiché une seule fois). La console
                //    garde la clé tant que l'utilisateur n'a pas confirmé la remise.
                //    R72 : le kit et son code sortent la clé privée de l'agent ; comme pour l'export d'une clé,
                //    le mot de passe du propriétaire est exigé (et le code à 6 chiffres si la double
                //    authentification est active). Sans fichier de clé (clés de test), rien à demander.
                ("POST", "/api/connecter/preparer") => match (cle_ch.map(|_| garde.ouvrir(cle_ch, &owner, &v, true).map(|_| ())).unwrap_or(Ok(())), &cible) {
                    (Err(r), _) => r,
                    (_, None) => json_rep(404, json!({ "erreur": "agent inconnu" })),
                    (_, Some(a)) if a.cle == "env" => json_rep(409, json!({ "erreur": "agent de test : sa clé est fournie par l'environnement, il n'y a rien à remettre" })),
                    (_, Some(a)) if agents::est_connecte(a) => json_rep(409, json!({ "erreur": "agent déjà connecté : la console n'a plus sa clé" })),
                    (_, Some(a)) => match preparer_kit(a, &owner, &defaut, v["mot_de_passe"].as_str(), enveloppe.as_ref()) {
                        Ok((scelle, code)) => {
                            connexion_en_attente = Some(a.id.clone());
                            journal(json!({ "connexion": "kit préparé", "agent": a.id }));
                            json_rep(200, json!({ "kit": scelle, "code": code.as_str(), "fichier": format!("kit-connexion-{}.json", a.id) }))
                        }
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                },
                // 2. Confirmer : la remise est faite, la console efface sa copie de la clé privée.
                ("POST", "/api/connecter/confirmer") => match &cible {
                    Some(a) if connexion_en_attente.as_deref() == Some(a.id.as_str()) && v["confirmation"].as_str() == Some("CONNECTER") => {
                        connexion_en_attente = None;
                        match connexion::effacer_fichier(&a.cle).and_then(|_| agents::marquer_connecte(&defaut, &a.id)) {
                            Ok(()) => {
                                journal(json!({ "connexion": "clé remise à l'agent et effacée de la console", "agent": a.id }));
                                json_rep(200, json!({ "ok": true }))
                            }
                            Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                        }
                    }
                    _ => json_rep(409, json!({ "erreur": "aucune connexion en cours pour cet agent" })),
                },
                // Secrets chiffrés à transmettre à un agent déjà connecté (seul l'agent sait les lire).
                // Signés par le propriétaire (R71) : l'agent refuse tout fichier fabriqué ou modifié en route.
                ("GET", "/api/secrets-chiffres") => match (&cible, cible.as_ref().map(|a| agents::publique(a, &agent_principal))) {
                    (Some(a), Some(Ok(k))) => match secrets::exporter(&owner, &k, &agents::base_fichiers(a, &defaut), double_auth::maintenant()) {
                        Ok(e) => json_rep(200, json!({ "secrets": e, "fichier": format!("secrets-{}.json", a.id) })),
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                ("POST", "/api/renommer") => match agents::renommer(&defaut, &id, v["nom"].as_str().unwrap_or("")) {
                    Ok(()) => json_rep(200, json!({ "ok": true })),
                    Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                },
                ("POST", "/api/creer") => match (&cible, cle_cible) {
                    _ if v["confirmation"].as_str() != Some("CREER") => json_rep(400, json!({ "erreur": "confirmation requise" })),
                    (Some(a), Some(Ok(k))) => {
                        let r = avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(deployer(&owner, &k)));
                        journal(json!({ "creer": a.id, "resultat": r.as_ref().map_err(|e| e.to_string()) }));
                        resultat(r)
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                // Arrêt d'urgence : sans mot de passe, pour qu'il ne soit jamais freiné. Il ne peut que
                // rapatrier les fonds vers la trésorerie du propriétaire (imposé par le contrat).
                ("POST", "/api/geler") => match (&cible, cle_cible) {
                    _ if v["confirmation"].as_str() != Some("GELER") => json_rep(400, json!({ "erreur": "confirmation requise" })),
                    (Some(a), Some(Ok(k))) => {
                        let r = avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(geler(&owner, &k, false, 0)));
                        journal(json!({ "geler": a.id, "resultat": r.as_ref().map_err(|e| e.to_string()) }));
                        if r.is_ok() {
                            agents::noter(&defaut, &a.nom, "arret", None);
                        }
                        resultat(r)
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                ("POST", "/api/geler-tout") => {
                    if v["confirmation"].as_str() != Some("GELER") {
                        json_rep(400, json!({ "erreur": "confirmation requise" }))
                    } else {
                        let mut bilan = Vec::new();
                        for a in &liste {
                            let r = agents::cle(a, &agent_principal).and_then(|k| avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || if load_state().is_err() { Err("aucun coffre ouvert".into()) } else { handle.block_on(geler(&owner, &k, false, 0)) }));
                            if r.is_ok() {
                                agents::noter(&defaut, &a.nom, "arret", None);
                            }
                            bilan.push(json!({ "agent": a.id, "nom": a.nom, "transaction": r.as_ref().ok(), "erreur": r.as_ref().err().map(|e| e.to_string()) }));
                        }
                        journal(json!({ "geler_tout": bilan }));
                        json_rep(200, json!({ "bilan": bilan }))
                    }
                }
                ("POST", "/api/alimenter") => match (v["montant_sompi"].as_u64().filter(|m| (10_000_000..=100_000_000_000).contains(m)), &cible, cle_cible) {
                    (None, _, _) => json_rep(400, json!({ "erreur": "montant invalide" })),
                    (Some(m), Some(a), Some(Ok(k))) => {
                        let r = avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(recharger(&owner, &k, m)));
                        journal(json!({ "alimenter": m, "agent": a.id, "resultat": r.as_ref().map_err(|e| e.to_string()) }));
                        resultat(r)
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                ("GET", "/api/solde") => match handle.block_on(async {
                    let c = connect_silencieux().await?;
                    let s: u64 = c.get_utxos_by_addresses(vec![address(&owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
                    liberer(&c).await?;
                    Ok::<u64, Box<dyn std::error::Error>>(s)
                }) {
                    Ok(s) => json_rep(200, json!({ "solde_proprietaire_sompi": s })),
                    Err(e) => json_rep(503, json!({ "erreur": e.to_string() })),
                },
                ("GET", "/api/verifier-lignee") => match (&cible, cle_cible) {
                    (Some(a), Some(Ok(k))) => {
                        let pk = xonly(&owner);
                        match avec_coffre(&a.etat, a.regles, agents::xonly_pub(a, &agent_principal), || handle.block_on(async {
                            let c = connect_silencieux().await?;
                            let e = retrouver_coffre(&c, &pk, &k).await;
                            liberer(&c).await?;
                            e
                        })) {
                            Ok(e) => json_rep(200, json!({ "ok": true, "lignee": e.cov_id, "sortie": format!("{}:{}", e.txid, e.index), "contrat": "AgentBudget v0.5.1" })),
                            Err(e) => json_rep(200, json!({ "ok": false, "detail": e.to_string() })),
                        }
                    }
                    _ => json_rep(404, json!({ "erreur": "agent inconnu" })),
                },
                // ---------- Ajout de fonds à la trésorerie ----------
                // Dépôt crypto : seul Kaspa est réellement encaissable aujourd'hui ; les autres monnaies
                // demandent un prestataire (phase 2) : refus explicite, jamais d'adresse inventée.
                ("POST", "/api/depot") => match v["monnaie"].as_str() {
                    Some("kas") => {
                        let adresse = address(&owner).to_string();
                        json_rep(200, json!({ "adresse": adresse, "qr": qr(&adresse), "demo": false }))
                    }
                    Some(m) => json_rep(501, json!({ "erreur": format!("Paiement en {} : disponible en phase 2. Utilisez Kaspa.", m.to_uppercase()) })),
                    None => json_rep(400, json!({ "erreur": "monnaie manquante" })),
                },
                // Carte / virement : aucun prestataire branché ; la console ne crédite jamais un solde fictif.
                ("POST", "/api/paiement") => json_rep(501, json!({ "erreur": "Paiement par carte ou virement : disponible en phase 2. Utilisez Kaspa ou les fonds de test." })),
                // ---------- Paramètres > Sécurité ----------
                ("GET", "/api/securite") => {
                    let adresse = address(&owner).to_string();
                    let compte = lire_compte(cle_ch);
                    let chiffrement = match cle_ch.map(cle::lire) {
                        Some(Ok(f)) => json!({ "mode": "fichier_chiffre", "algorithme": "Argon2id + XChaCha20-Poly1305", "memoire_kio": f.m_kio, "passes": f.t, "version": f.version, "phrase_disponible": f.version >= 2 }),
                        Some(Err(e)) => json!({ "mode": "erreur", "detail": e.to_string() }),
                        None => json!({ "mode": "cles_de_test" }),
                    };
                    json_rep(200, json!({ "adresse": adresse, "qr": qr(&adresse), "chiffrement": chiffrement, "sauvegarde_faite": compte.sauvegarde_faite, "double_auth": compte.double_auth, "chemin_derivation": cle::CHEMIN_DERIVATION, "reseau": "testnet-10" }))
                }
                // Phrase de récupération : mot de passe + code si la double authentification est active.
                ("POST", "/api/recuperation") => match garde.ouvrir(cle_ch, &owner, &v, true) {
                    Err(r) => r,
                    Ok((_, None)) => json_rep(409, json!({ "erreur": "compte créé avant les phrases de récupération : sauvegardez le fichier de clé chiffré" })),
                    Ok((_, Some(c))) => match cle::phrase(&c) {
                        Ok(p) => {
                            journal(json!({ "recuperation": "phrase affichée" }));
                            json_rep(200, json!({ "mots": p.split(' ').collect::<Vec<_>>() }))
                        }
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                },
                // Confirmation de la sauvegarde : 3 mots demandés au hasard par la page.
                ("POST", "/api/recuperation/confirmer") => match garde.ouvrir(cle_ch, &owner, &v, false) {
                    Err(r) => r,
                    Ok((_, None)) => json_rep(409, json!({ "erreur": "aucune phrase pour ce compte" })),
                    Ok((_, Some(c))) => {
                        let phrase = cle::phrase(&c).unwrap_or_default();
                        let mots: Vec<&str> = phrase.split(' ').collect();
                        let essais: Vec<(usize, String)> = v["positions"].as_array().into_iter().flatten().zip(v["mots"].as_array().into_iter().flatten()).filter_map(|(p, m)| Some((p.as_u64()? as usize, m.as_str()?.trim().to_lowercase()))).collect();
                        // R66 : trois positions DISTINCTES au moins (sinon un mot se devine seul, en 2048 essais),
                        // et chaque essai manqué compte pour le verrouillage.
                        let distinctes = essais.iter().map(|(p, _)| *p).collect::<std::collections::BTreeSet<_>>().len();
                        let juste = distinctes >= 3 && essais.iter().all(|(p, m)| mots.get(*p).is_some_and(|x| *x == m));
                        if !juste {
                            garde.echec_secret("mots de la phrase de récupération incorrects");
                            json_rep(400, json!({ "erreur": "un ou plusieurs mots ne correspondent pas : vérifiez votre sauvegarde" }))
                        } else {
                            let mut compte = lire_compte(cle_ch);
                            compte.sauvegarde_faite = true;
                            match ecrire_compte(cle_ch.unwrap_or_default(), &compte) {
                                Ok(()) => json_rep(200, json!({ "ok": true })),
                                Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                            }
                        }
                    }
                },
                // Export de la clé privée en clair : mot de passe + double authentification ; journalisé.
                ("POST", "/api/cle-export") => match garde.ouvrir(cle_ch, &owner, &v, true) {
                    Err(r) => r,
                    Ok((k, _)) => {
                        journal(json!({ "export_cle": "clé privée exportée" }));
                        json_rep(200, json!({ "cle_privee": hex::encode(k.secret_bytes()), "adresse": address(&k).to_string(), "chemin_derivation": cle::CHEMIN_DERIVATION }))
                    }
                },
                // R65 : ce fichier et le mot de passe suffisent, hors ligne, à retrouver la phrase : le code
                // de double authentification est donc exigé ici aussi quand elle est active.
                ("POST", "/api/cle-chiffree") => match garde.ouvrir(cle_ch, &owner, &v, true) {
                    Err(r) => r,
                    Ok(_) => match fs::read_to_string(cle_ch.unwrap_or_default()) {
                        Ok(t) => json_rep(200, json!({ "fichier": serde_json::from_str::<Value>(&t).unwrap_or(Value::Null) })),
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                },
                ("POST", "/api/double-auth/preparer") => match garde.ouvrir(cle_ch, &owner, &v, true) {
                    Err(r) => r,
                    Ok((_, None)) => json_rep(409, json!({ "erreur": "double authentification : nécessite un compte avec phrase de récupération" })),
                    Ok((_, Some(c))) if c.totp.is_some() => json_rep(409, json!({ "erreur": "double authentification déjà active" })),
                    Ok(_) => match double_auth::nouveau_secret() {
                        Ok(s) => {
                            let lien = double_auth::lien(&s, "proprietaire");
                            let r = json_rep(200, json!({ "qr": qr(&lien), "secret": double_auth::base32(&s) }));
                            double_auth_en_attente = Some(zeroize::Zeroizing::new(s));
                            r
                        }
                        Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                    },
                },
                ("POST", "/api/double-auth/activer") => match (double_auth_en_attente.take(), garde.ouvrir(cle_ch, &owner, &v, false)) {
                    (None, _) => json_rep(409, json!({ "erreur": "aucune activation en cours" })),
                    (_, Err(r)) => r,
                    (Some(_), Ok((_, None))) => json_rep(409, json!({ "erreur": "aucune phrase pour ce compte" })),
                    (Some(s), Ok((_, Some(mut c)))) => {
                        if double_auth::verifier(&s, v["code"].as_str().unwrap_or(""), double_auth::maintenant(), 0).is_none() {
                            double_auth_en_attente = Some(s);
                            json_rep(400, json!({ "erreur": "code incorrect : vérifiez l'heure de votre téléphone et réessayez" }))
                        } else {
                            c.totp = Some(s);
                            let mdp = zeroize::Zeroizing::new(v["mot_de_passe"].as_str().unwrap_or("").to_string());
                            let ch = cle_ch.unwrap_or_default();
                            match cle::chiffrer_coffret(&c, &mdp).and_then(|f| cle::remplacer(ch, &f)) {
                                Ok(()) => {
                                    let mut compte = lire_compte(cle_ch);
                                    compte.double_auth = true;
                                    let _ = ecrire_compte(ch, &compte);
                                    journal(json!({ "double_auth": "activée" }));
                                    json_rep(200, json!({ "ok": true }))
                                }
                                Err(e) => json_rep(500, json!({ "erreur": e.to_string() })),
                            }
                        }
                    }
                },
                // Restaurer un compte depuis sa phrase : crée un NOUVEAU fichier de clé (jamais d'écrasement),
                // à ouvrir au prochain lancement de la console.
                ("POST", "/api/restaurer") => {
                    let mdp = zeroize::Zeroizing::new(v["nouveau_mot_de_passe"].as_str().unwrap_or("").to_string());
                    let phrase = zeroize::Zeroizing::new(v["phrase"].as_str().unwrap_or("").to_string());
                    let base = cle_ch.and_then(|c| std::path::Path::new(c).parent().map(|p| p.to_path_buf())).unwrap_or_else(|| std::path::PathBuf::from("."));
                    let sortie = base.join(format!("cle-proprietaire-restauree-{}.json", double_auth::maintenant()));
                    match cle::depuis_phrase(&phrase).and_then(|c| {
                        let k = cle::cle_du_coffret(&c)?;
                        cle::ecrire(sortie.to_str().ok_or("chemin invalide")?, &cle::chiffrer_coffret(&c, &mdp)?)?;
                        Ok(k)
                    }) {
                        Ok(k) => {
                            journal(json!({ "restauration": address(&k).to_string() }));
                            json_rep(200, json!({ "adresse": address(&k).to_string(), "meme_compte": k.x_only_public_key() == owner.x_only_public_key(), "fichier": sortie.to_string_lossy() }))
                        }
                        Err(e) => json_rep(400, json!({ "erreur": e.to_string() })),
                    }
                }
                _ => json_rep(404, json!({ "erreur": "inconnu" })),
            }
        };
        // Console lancée sans enveloppe : le mot de passe vient d'être vérifié, on en dérive l'enveloppe
        // des clés d'agent et on chiffre celles qui étaient encore en clair. Il n'est pas gardé.
        if let Some(mdp) = garde.mdp_verifie.take() {
            if enveloppe.is_none() {
                if let Ok(e) = cle::Enveloppe::nouvelle(&mdp) {
                    migrer(&e);
                    enveloppe = Some(e);
                    garde.retenir_mdp = false;
                }
            }
        }
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
        let fil = std::thread::spawn(move || servir(&s2, &Session::fixe("jeton-de-test"), h, k(1), k(2), None, None));
        let base = format!("http://127.0.0.1:{port}");
        let statut = |r: Result<ureq::Response, ureq::Error>| match r {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        };
        // la page s'affiche sans jeton (elle l'obtient ensuite en échangeant le ticket du lien)
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

    /// Compte créé puis rouvert depuis la page : verrouillé tant qu'on n'est pas connecté, mot de passe
    /// vérifié, fichiers de clé lisibles par le seul utilisateur, et même clé du propriétaire à la réouverture.
    #[test]
    fn compte_cree_puis_rouvert_depuis_la_page() {
        let dossier = std::env::temp_dir().join(format!("plafond-compte-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dossier);
        let fichiers = fichiers_compte(&dossier.to_string_lossy());
        let statut = |r: Result<ureq::Response, ureq::Error>| match r {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        };
        let mdp = "un mot de passe assez long";
        let mut cles = Vec::new();
        for tour in 0..2 {
            let serveur = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let base = format!("http://127.0.0.1:{}", serveur.server_addr().to_ip().unwrap().port());
            let (s2, f2) = (serveur.clone(), fichiers_compte(&dossier.to_string_lossy()));
            let fil = std::thread::spawn(move || porte(&s2, &Session::fixe("jeton-de-test"), &f2).map_err(|e| e.to_string()));
            let get = |c: &str| ureq::get(&format!("{base}{c}")).set("X-Jeton", "jeton-de-test").call();
            let post = |c: &str, corps: Value| ureq::post(&format!("{base}{c}")).set("X-Jeton", "jeton-de-test").send_string(&corps.to_string());
            let etat: Value = serde_json::from_str(&get("/api/compte/etat").unwrap().into_string().unwrap()).unwrap();
            assert_eq!(etat["existe"], json!(tour == 1), "tour {tour}");
            // tant que le compte est fermé, le reste de l'API est verrouillé, et le jeton reste exigé
            assert_eq!(statut(get("/api/tableau")), 423);
            assert_eq!(statut(ureq::get(&format!("{base}/api/compte/etat")).call()), 401);
            if tour == 0 {
                assert_eq!(statut(post("/api/compte/ouvrir", json!({ "mot_de_passe": mdp }))), 404, "aucun compte à ouvrir");
                assert_eq!(statut(post("/api/compte/creer", json!({ "mot_de_passe": "court", "confirmation": "court" }))), 400);
                assert_eq!(statut(post("/api/compte/creer", json!({ "mot_de_passe": mdp, "confirmation": "un autre mot de passe" }))), 400);
                assert_eq!(statut(post("/api/compte/creer", json!({ "mot_de_passe": mdp, "confirmation": mdp }))), 200);
            } else {
                assert_eq!(statut(post("/api/compte/creer", json!({ "mot_de_passe": mdp, "confirmation": mdp }))), 409, "jamais d'écrasement");
                assert_eq!(statut(post("/api/compte/ouvrir", json!({ "mot_de_passe": "mauvais mot de passe" }))), 403);
                assert_eq!(statut(post("/api/compte/ouvrir", json!({ "mot_de_passe": mdp }))), 200);
            }
            let (owner, agent, _) = fil.join().unwrap().unwrap();
            assert_ne!(owner.x_only_public_key(), agent.publique.x_only_public_key());
            assert_eq!(agent.cle.public_key(), agent.publique, "clé de l'agent principal lisible avec le mot de passe");
            cles.push((owner.x_only_public_key(), agent.publique.x_only_public_key()));
        }
        assert_eq!(cles[0], cles[1], "même compte à la réouverture");
        // mot de passe oublié : la phrase recrée la même clé ; l'ancien fichier est mis de côté, pas effacé
        let phrase = cle::phrase(&cle::ouvrir_tout(&cle::lire(&fichiers.cle).unwrap(), mdp).unwrap().1.unwrap()).unwrap();
        let serveur = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let base = format!("http://127.0.0.1:{}", serveur.server_addr().to_ip().unwrap().port());
        let (s2, f2) = (serveur.clone(), fichiers_compte(&dossier.to_string_lossy()));
        let fil = std::thread::spawn(move || porte(&s2, &Session::fixe("jeton-de-test"), &f2).map_err(|e| e.to_string()));
        let post = |corps: Value| ureq::post(&format!("{base}/api/compte/restaurer")).set("X-Jeton", "jeton-de-test").send_string(&corps.to_string());
        let nouveau = "un tout nouveau mot de passe";
        assert_eq!(statut(post(json!({ "phrase": "abandon ".repeat(24), "mot_de_passe": nouveau, "confirmation": nouveau }))), 403, "phrase invalide");
        assert_eq!(statut(post(json!({ "phrase": phrase.as_str(), "mot_de_passe": nouveau, "confirmation": nouveau }))), 200);
        let (owner, agent, _) = fil.join().unwrap().unwrap();
        assert_eq!((owner.x_only_public_key(), agent.publique.x_only_public_key()), cles[0], "même propriétaire et même agent");
        // la clé de l'agent principal est chiffrée sous l'ANCIEN mot de passe : sa clé privée n'est plus
        // lisible, mais la console garde sa clé publique, donc son coffre (surveiller, alimenter, geler)
        assert_ne!(agent.cle.public_key(), agent.publique, "clé privée de l'agent principal non lisible après restauration");
        assert!(cle::ouvrir_tout(&cle::lire(&fichiers.cle).unwrap(), nouveau).is_ok(), "nouveau mot de passe actif");
        assert!(fs::read_dir(&dossier).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().contains(".ancien-")), "ancien fichier conservé");
        for f in [&fichiers.cle, &fichiers.agent] {
            let f = std::path::Path::new(f);
            assert!(crate::prive::est_prive(f).unwrap(), "{} : {}", f.display(), crate::prive::droits(f));
        }
        let _ = fs::remove_dir_all(&dossier);
    }

    /// Actions sensibles : mot de passe puis double authentification ; verrouillage après 5 échecs ;
    /// le gel, lui, n'exige aucun mot de passe (il ne peut que rapatrier les fonds au propriétaire).
    #[test]
    fn actions_sensibles_mot_de_passe_double_auth_et_verrouillage() {
        let mdp = "le bon mot de passe";
        let mut c = cle::nouveau_coffret().unwrap();
        let owner = cle::cle_du_coffret(&c).unwrap();
        let chemin = std::env::temp_dir().join(format!("cle-console-{}.json", std::process::id()));
        let ch = chemin.to_str().unwrap();
        let _ = std::fs::remove_file(ch);
        cle::ecrire(ch, &cle::chiffrer_coffret(&c, mdp).unwrap()).unwrap();
        let mut g = Garde::neuve();
        assert!(g.ouvrir(None, &owner, &json!({}), true).is_err(), "mode test : rien à exporter");
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp }), true).ok().unwrap().1.is_some());
        let autre = Keypair::from_seckey_slice(secp256k1::SECP256K1, &[9; 32]).unwrap();
        assert!(g.ouvrir(Some(ch), &autre, &json!({ "mot_de_passe": mdp }), true).is_err(), "fichier d'un autre propriétaire");
        // double authentification active : le code est exigé, et ne sert qu'une fois
        let secret = vec![3u8; 20];
        c.totp = Some(zeroize::Zeroizing::new(secret.clone()));
        cle::remplacer(ch, &cle::chiffrer_coffret(&c, mdp).unwrap()).unwrap();
        let mut g = Garde::neuve();
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp }), true).is_err(), "code manquant");
        let code = format!("{:06}", double_auth::code(&secret, double_auth::maintenant() / 30));
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp, "code": code }), true).is_ok());
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp, "code": code }), true).is_err(), "rejeu refusé");
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp }), false).is_ok(), "confirmation de sauvegarde : mot de passe seul");
        let mut g = Garde::neuve();
        for _ in 0..5 {
            assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": "mauvais" }), false).is_err());
        }
        assert!(g.verrou.is_some(), "verrouillé après 5 échecs");
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp }), false).is_err(), "même le bon mot de passe attend une minute");
        for f in [ch.to_string(), format!("{ch}.precedent")] {
            let _ = std::fs::remove_file(f);
        }
    }

    /// Console de test avec un vrai fichier de clé (double authentification active ou non).
    /// Renvoie (base, serveur, fil, phrase, secret de double authentification, chemin du fichier).
    #[cfg(test)]
    fn console_avec_cle(nom: &str, double_auth_active: bool) -> (String, std::sync::Arc<tiny_http::Server>, std::thread::JoinHandle<()>, Vec<String>, Vec<u8>, String) {
        use std::sync::Arc;
        let mdp = "le bon mot de passe";
        let mut c = cle::nouveau_coffret().unwrap();
        let owner = cle::cle_du_coffret(&c).unwrap();
        let secret = vec![5u8; 20];
        if double_auth_active {
            c.totp = Some(zeroize::Zeroizing::new(secret.clone()));
        }
        let phrase: Vec<String> = cle::phrase(&c).unwrap().split(' ').map(String::from).collect();
        let chemin = std::env::temp_dir().join(format!("cle-{nom}-{}.json", std::process::id()));
        let ch = chemin.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&ch);
        cle::ecrire(&ch, &cle::chiffrer_coffret(&c, mdp).unwrap()).unwrap();
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let (s2, ch2) = (serveur.clone(), ch.clone());
        let fil = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            servir(&s2, &Session::fixe("jeton-de-test"), rt.handle().clone(), owner, Keypair::from_seckey_slice(secp256k1::SECP256K1, &[2; 32]).unwrap(), Some(ch2), None);
        });
        (format!("http://127.0.0.1:{port}"), serveur, fil, phrase, secret, ch)
    }

    #[cfg(test)]
    fn poster(base: &str, chemin: &str, corps: Value) -> (u16, Value) {
        match ureq::post(&format!("{base}{chemin}")).set("X-Jeton", "jeton-de-test").send_string(&corps.to_string()) {
            Ok(r) => (r.status(), r.into_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, r.into_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)),
            Err(e) => panic!("{e}"),
        }
    }

    /// R65 : avec la double authentification active, le mot de passe seul ne doit pas suffire à
    /// sortir le fichier de clé chiffré (ce fichier + le mot de passe = la phrase et le secret de
    /// double authentification, hors ligne : la double authentification serait contournée).
    #[test]
    fn r65_fichier_de_cle_chiffre_exige_la_double_authentification() {
        let mdp = "le bon mot de passe";
        let (base, serveur, fil, _, secret, ch) = console_avec_cle("r65", true);
        let (statut, corps) = poster(&base, "/api/cle-chiffree", json!({ "mot_de_passe": mdp }));
        assert_eq!(statut, 403, "mot de passe seul : le fichier chiffré ne sort pas ({corps})");
        assert!(corps["fichier"].is_null());
        let code = format!("{:06}", double_auth::code(&secret, double_auth::maintenant() / 30));
        let (statut, corps) = poster(&base, "/api/cle-chiffree", json!({ "mot_de_passe": mdp, "code": code }));
        assert_eq!(statut, 200, "mot de passe + code : sauvegarde permise ({corps})");
        assert!(corps["fichier"]["chiffre"].is_string());
        // la page demande bien le code pour cette action
        assert!(PAGE.contains("api(\"/api/cle-chiffree\",{mot_de_passe:mdp,code})"), "la page doit envoyer le code");
        serveur.unblock();
        fil.join().unwrap();
        let _ = std::fs::remove_file(ch);
    }

    /// R72 : préparer un kit de connexion, c'est sortir la clé privée d'un agent (kit + code dans la
    /// même réponse). Le lien de session seul ne doit pas y suffire : mot de passe du propriétaire, et
    /// code à 6 chiffres si la double authentification est active, comme pour exporter une clé.
    #[test]
    fn r72_kit_de_connexion_exige_le_mot_de_passe() {
        let mdp = "le bon mot de passe";
        let (base, serveur, fil, _, secret, ch) = console_avec_cle("r72", true);
        for corps in [json!({}), json!({ "mot_de_passe": "un mauvais mot de passe" }), json!({ "mot_de_passe": mdp })] {
            let (statut, rep) = poster(&base, "/api/connecter/preparer", corps);
            assert_eq!(statut, 403, "sans identification complète, pas de kit : {rep}");
            assert!(rep["kit"].is_null() && rep["code"].is_null());
        }
        // identification complète : la garde est passée (l'agent de test n'a simplement rien à remettre)
        let code = format!("{:06}", double_auth::code(&secret, double_auth::maintenant() / 30));
        let (statut, rep) = poster(&base, "/api/connecter/preparer", json!({ "mot_de_passe": mdp, "code": code }));
        assert_eq!(statut, 409, "{rep}");
        assert!(PAGE.contains("api(\"/api/connecter/preparer\",{agent:etat.agent,mot_de_passe:mdp,code})"), "la page doit demander le mot de passe");
        serveur.unblock();
        fil.join().unwrap();
        let _ = std::fs::remove_file(ch);
    }

    /// Chaîne complète côté mandataire, par la console réelle (HTTP) : créer un secret, préparer le
    /// kit, l'installer côté agent, confirmer, transmettre de nouveaux secrets. À chaque étape : ni la
    /// clé privée de l'agent, ni la valeur d'un secret, ni le mot de passe, ni le code de connexion
    /// n'apparaissent dans une réponse où ils n'ont rien à faire, ni dans le journal de la console.
    #[test]
    fn chaine_complete_sans_fuite_de_cle_ni_de_secret() {
        let mdp = "le bon mot de passe";
        let d = std::env::temp_dir().join(format!("console-chaine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let defaut = d.join("etat-coffre.json").to_string_lossy().into_owned();
        let a = agents::nouveau(&defaut, "Recherche", None, None).unwrap();
        let cle_agent = std::fs::read_to_string(&a.cle).unwrap();
        *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(defaut.clone());
        let (base, serveur, fil, _, secret_2fa, ch) = console_avec_cle("chaine", true);
        let code_2fa = |decalage: u64| format!("{:06}", double_auth::code(&secret_2fa, double_auth::maintenant() / 30 + decalage));
        let lire = |chemin: &str| -> (u16, String) {
            match ureq::get(&format!("{base}{chemin}")).set("X-Jeton", "jeton-de-test").call() {
                Ok(r) => (r.status(), r.into_string().unwrap()),
                Err(ureq::Error::Status(c, r)) => (c, r.into_string().unwrap()),
                Err(e) => panic!("{e}"),
            }
        };
        let mut reponses = String::new(); // tout ce que la console a répondu, hors le kit lui-même
        // 1. un secret : écriture seule
        let valeur = "sk-test-VALEUR-SECRETE-0123456789";
        let (statut, r) = poster(&base, "/api/secrets", json!({ "agent": a.id, "nom": "OpenAI", "fournisseur": "openai", "valeur": valeur }));
        assert_eq!(statut, 200, "{r}");
        reponses += &r.to_string();
        let (_, liste) = lire(&format!("/api/secrets?agent={}", a.id));
        assert!(liste.contains("OpenAI") && liste.contains("openai"));
        reponses += &liste;
        // 2. le kit : refusé sans identification, puis remis avec son code
        assert_eq!(poster(&base, "/api/connecter/preparer", json!({ "agent": a.id })).0, 403);
        assert_eq!(poster(&base, "/api/connecter/confirmer", json!({ "agent": a.id, "confirmation": "CONNECTER" })).0, 409, "rien à confirmer sans kit préparé");
        let (statut, r) = poster(&base, "/api/connecter/preparer", json!({ "agent": a.id, "mot_de_passe": mdp, "code": code_2fa(0) }));
        assert_eq!(statut, 200, "{r}");
        let code_connexion = r["code"].as_str().unwrap().to_string();
        let kit: connexion::Scelle = serde_json::from_value(r["kit"].clone()).unwrap();
        assert!(!r["kit"].to_string().contains(cle_agent.trim()) && !r["kit"].to_string().contains(&code_connexion), "kit scellé : ni clé ni code en clair");
        // 3. côté agent : installation avec le code ; un mauvais code ne donne rien
        let dossier = d.join("serveur-agent").to_string_lossy().into_owned();
        assert!(connexion::installer_demo(&kit, "AAAAA-AAAAA-AAAAA-AAAAA", &dossier).is_err());
        connexion::installer_demo(&kit, &code_connexion, &dossier).unwrap();
        assert_eq!(connexion::verifier(&dossier).unwrap(), vec![("OpenAI".to_string(), true)]);
        // 4. confirmation : la console efface sa copie de la clé et ne peut plus préparer de kit
        assert!(std::path::Path::new(&a.cle).exists(), "la console garde la clé tant que la remise n'est pas confirmée");
        // console lancée avec une clé déjà déverrouillée (pas d'enveloppe au départ) : le premier mot de
        // passe vérifié a servi à chiffrer la clé de l'agent, qui était en clair sur le disque
        let garde_par_la_console = std::fs::read_to_string(&a.cle).unwrap();
        assert!(garde_par_la_console.contains("argon2id") && !garde_par_la_console.contains(cle_agent.trim()), "clé de l'agent restée en clair côté console");
        let (statut, r) = poster(&base, "/api/connecter/confirmer", json!({ "agent": a.id, "confirmation": "CONNECTER" }));
        assert_eq!(statut, 200, "{r}");
        reponses += &r.to_string();
        assert!(!std::path::Path::new(&a.cle).exists(), "copie de la console effacée");
        let (statut, r) = poster(&base, "/api/connecter/preparer", json!({ "agent": a.id, "mot_de_passe": mdp, "code": code_2fa(1) }));
        assert_eq!(statut, 409, "agent connecté : plus de kit ({r})");
        reponses += &r.to_string();
        // 5. nouveaux secrets pour l'agent connecté : export signé, accepté par l'agent
        let valeur2 = "sk-test-SECONDE-VALEUR-9876543210";
        assert_eq!(poster(&base, "/api/secrets", json!({ "agent": a.id, "nom": "Stripe", "fournisseur": "stripe", "valeur": valeur2 })).0, 200);
        let (statut, export) = lire(&format!("/api/secrets-chiffres?agent={}", a.id));
        assert_eq!(statut, 200);
        reponses += &export;
        let export: Value = serde_json::from_str(&export).unwrap();
        let fichier = d.join("secrets-export.json");
        std::fs::write(&fichier, export["secrets"].to_string()).unwrap();
        assert_eq!(connexion::maj_secrets(&fichier.to_string_lossy(), &dossier).unwrap(), 2);
        assert_eq!(connexion::verifier(&dossier).unwrap().len(), 2);
        // un agent ne lit pas les secrets d'un autre : même fichier, autre clé
        let autre = Keypair::from_seckey_slice(secp256k1::SECP256K1, &[9; 32]).unwrap();
        assert!(secrets::lire_pour_agent(&format!("{dossier}/agent.key"), &autre, "Stripe").is_err());
        reponses += &lire("/api/evenements").1;
        reponses += &lire("/api/securite").1;
        serveur.unblock();
        fil.join().unwrap();
        *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // aucune fuite : réponses, journal de la console, fichiers restés côté console
        let journal_console = std::fs::read_to_string("console-journal.jsonl").unwrap_or_default();
        let mut cote_console = String::new();
        for f in [d.join("agents.json"), d.join("agents").join(format!("{}.secrets.json", a.id)), d.join("evenements.jsonl")] {
            cote_console += &std::fs::read_to_string(f).unwrap_or_default();
        }
        for (quoi, interdit) in [("clé privée de l'agent", cle_agent.trim()), ("valeur du secret", valeur), ("valeur du second secret", valeur2), ("mot de passe", mdp), ("code de connexion", code_connexion.as_str())] {
            assert!(!reponses.contains(interdit), "{quoi} dans une réponse de la console");
            assert!(!journal_console.contains(interdit), "{quoi} dans le journal de la console");
            assert!(!cote_console.contains(interdit), "{quoi} dans un fichier de la console");
        }
        assert!(journal_console.contains(&a.id), "les actions sont bien journalisées");
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_file(ch);
    }

    /// Page web malveillante ouverte dans le navigateur du propriétaire : elle ne connaît pas le jeton
    /// (jamais envoyé au serveur dans une URL, jamais accepté ailleurs que dans l'en-tête X-Jeton), ne
    /// peut pas se faire passer pour la console (Host, Origin), et la console ne lui ouvre aucun accès
    /// entre origines (aucun en-tête CORS, pas d'affichage en cadre).
    #[test]
    fn page_malveillante_sans_prise_sur_la_console() {
        use std::sync::Arc;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let (s2, h) = (serveur.clone(), rt.handle().clone());
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let fil = std::thread::spawn(move || servir(&s2, &Session::fixe("jeton-de-test"), h, k(1), k(2), None, None));
        let base = format!("http://127.0.0.1:{port}");
        let statut = |r: Result<ureq::Response, ureq::Error>| match r {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        };
        let geler = "{\"confirmation\":\"GELER\"}";
        // jeton ailleurs que dans l'en-tête : paramètre d'URL, cookie, Authorization : refusé
        assert_eq!(statut(ureq::get(&format!("{base}/api/securite?jeton=jeton-de-test&X-Jeton=jeton-de-test")).call()), 401);
        assert_eq!(statut(ureq::get(&format!("{base}/api/securite")).set("Cookie", "jeton=jeton-de-test; X-Jeton=jeton-de-test").call()), 401);
        assert_eq!(statut(ureq::get(&format!("{base}/api/securite")).set("Authorization", "Bearer jeton-de-test").call()), 401);
        // jeton presque juste (préfixe, suffixe, casse) : refusé
        for j in ["jeton-de-tes", "jeton-de-testX", "x jeton-de-test", "JETON-DE-TEST", ""] {
            assert_eq!(statut(ureq::get(&format!("{base}/api/securite")).set("X-Jeton", j).call()), 401, "« {j} »");
        }
        // origines qui ne sont pas la console, même avec le bon jeton : action refusée
        for origine in ["null", "http://attaquant.example", &format!("http://127.0.0.1:{}", port + 1), &format!("https://127.0.0.1:{port}"), &format!("http://127.0.0.1:{port}.attaquant.example"), &format!("http://localhost.attaquant.example:{port}")] {
            assert_eq!(statut(ureq::post(&format!("{base}/api/geler")).set("X-Jeton", "jeton-de-test").set("Origin", origine).send_string(geler)), 403, "origine {origine}");
        }
        // noms d'hôte qui ne sont pas la console (DNS rebinding) : refusés avant tout, page comprise
        for hote in ["attaquant.example", &format!("attaquant.example:{port}"), &format!("127.0.0.1.attaquant.example:{port}"), "127.0.0.1", &format!("[::1]:{port}"), &format!("0.0.0.0:{port}")] {
            assert_eq!(statut(ureq::get(&format!("{base}/")).set("Host", hote).call()), 421, "hôte {hote}");
            assert_eq!(statut(ureq::get(&format!("{base}/api/securite")).set("Host", hote).set("X-Jeton", "jeton-de-test").call()), 421, "hôte {hote}");
        }
        // aucune ouverture entre origines : pas d'en-tête CORS, pré-vérification sans effet, pas de cadre
        let r = ureq::get(&format!("{base}/api/securite")).set("X-Jeton", "jeton-de-test").set("Origin", "http://attaquant.example").call().unwrap();
        assert!(r.headers_names().iter().all(|n| !n.to_ascii_lowercase().starts_with("access-control-")), "aucun en-tête CORS");
        assert_eq!(r.header("X-Frame-Options"), Some("DENY"));
        assert_eq!(r.header("Cache-Control"), Some("no-store"));
        let r = ureq::request("OPTIONS", &format!("{base}/api/geler")).set("Origin", "http://attaquant.example").set("Access-Control-Request-Method", "POST").set("Access-Control-Request-Headers", "x-jeton").call();
        match r {
            Ok(r) => panic!("pré-vérification acceptée : {}", r.status()),
            Err(ureq::Error::Status(c, r)) => {
                assert_eq!(c, 401);
                assert!(r.header("Access-Control-Allow-Origin").is_none() && r.header("Access-Control-Allow-Headers").is_none());
            }
            Err(e) => panic!("{e}"),
        }
        // la page elle-même ne contient pas le jeton et interdit tout chargement extérieur
        let page = ureq::get(&format!("{base}/")).call().unwrap();
        assert!(page.header("Content-Security-Policy").is_some_and(|c| c.contains("default-src 'none'") && c.contains("frame-ancestors 'none'") && c.contains("connect-src 'self'")));
        assert!(!page.into_string().unwrap().contains("jeton-de-test"));
        serveur.unblock();
        fil.join().unwrap();
    }

    /// R73 : le lien remis au navigateur (argument de commande, lisible par les autres utilisateurs
    /// de l'ordinateur : `ps`, /proc) ne porte plus le jeton de session, mais un ticket à usage unique.
    #[test]
    fn r73_lien_remis_au_navigateur_sans_jeton_de_session() {
        let session = Session::nouvelle().unwrap();
        let jeton = session.jeton.lock().unwrap().clone();
        let lien = lien_de_session(PORT, &session).unwrap();
        assert!(!lien.contains(&jeton), "le lien passé en argument de commande contient le jeton de session");
        let ticket = lien.split("#ticket=").nth(1).expect("le lien porte un ticket");
        assert_eq!(ticket.len(), 64, "ticket de 256 bits");
        // le ticket s'échange une fois contre un jeton neuf ; le jeton d'avant l'échange ne vaut plus rien
        let nouveau = session.echanger(ticket).unwrap();
        assert!(nouveau != jeton && !lien.contains(&nouveau));
        assert!(session.jeton_ok(Some(nouveau.clone())) && !session.jeton_ok(Some(jeton)) && !session.jeton_ok(Some(ticket.into())) && !session.jeton_ok(None));
        assert_eq!(session.echanger(ticket), Err(TicketRefuse::DejaServi), "un ticket ne sert qu'une fois");
        assert_eq!(session.echanger(&"0".repeat(64)), Err(TicketRefuse::Inconnu));
        assert_eq!(session.echanger(""), Err(TicketRefuse::Inconnu));
        assert!(session.jeton_ok(Some(nouveau.clone())), "un échange refusé ne ferme pas la session en cours");
        // courte durée : passé deux minutes, le ticket est mort, et le dit
        let t0 = Instant::now();
        let vieux = session.ticket_a(t0).unwrap();
        assert_eq!(session.echanger_a(&vieux, t0 + TICKET_DUREE), Err(TicketRefuse::DejaServi));
        let frais = session.ticket_a(t0).unwrap();
        assert!(session.echanger_a(&frais, t0 + TICKET_DUREE - Duration::from_secs(1)).is_ok());
        // un nouveau lien ferme la session précédente (reprise en main si le lien a été intercepté)
        let suivant = session.echanger(&session.ticket().unwrap()).unwrap();
        assert!(session.jeton_ok(Some(suivant)) && !session.jeton_ok(Some(nouveau)));
        // pas d'accumulation : 8 tickets en attente au plus
        let lot: Vec<String> = (0..10).map(|_| session.ticket().unwrap()).collect();
        assert_eq!(session.echanger(&lot[0]), Err(TicketRefuse::Inconnu));
        assert!(session.echanger(&lot[9]).is_ok());
    }

    /// R73, de bout en bout par HTTP : la page échange le ticket (en-tête, jamais l'URL), une seule fois,
    /// depuis la console seulement ; le ticket n'ouvre rien d'autre ; un second lien ferme la première session.
    #[test]
    fn r73_ticket_a_usage_unique_par_http() {
        use std::sync::Arc;
        let dossier = std::env::temp_dir().join(format!("plafond-r73-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dossier);
        let fichiers = fichiers_compte(&dossier.to_string_lossy());
        let serveur = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let port = serveur.server_addr().to_ip().unwrap().port();
        let session = Arc::new(Session::nouvelle().unwrap());
        let (s2, se2) = (serveur.clone(), session.clone());
        let fil = std::thread::spawn(move || porte(&s2, &se2, &fichiers).map_err(|e| e.to_string()));
        let base = format!("http://127.0.0.1:{port}");
        let lire = |r: Result<ureq::Response, ureq::Error>| match r {
            Ok(r) => (r.status(), serde_json::from_str::<Value>(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
            Err(ureq::Error::Status(c, r)) => (c, serde_json::from_str::<Value>(&r.into_string().unwrap_or_default()).unwrap_or(Value::Null)),
            Err(e) => panic!("{e}"),
        };
        let echange = |ticket: &str| ureq::post(&format!("{base}/api/session")).set("X-Ticket", ticket);
        let etat = |jeton: &str| lire(ureq::get(&format!("{base}/api/compte/etat")).set("X-Jeton", jeton).call()).0;
        let ticket = session.ticket().unwrap();
        // le ticket n'est pas un jeton, et il ne passe ni par l'URL ni depuis une autre page ou un autre hôte
        assert_eq!(etat(&ticket), 401);
        assert_eq!(lire(ureq::post(&format!("{base}/api/session?ticket={ticket}&X-Ticket={ticket}")).call()).0, 401);
        assert_eq!(lire(ureq::get(&format!("{base}/api/session")).set("X-Ticket", &ticket).call()).0, 401);
        assert_eq!(lire(echange(&ticket).set("Origin", "http://attaquant.example").call()).0, 403);
        assert_eq!(lire(echange(&ticket).set("Host", "attaquant.example").call()).0, 421);
        // premier échange : le jeton de session ; il ouvre l'API
        let (c, r) = lire(echange(&ticket).call());
        assert_eq!(c, 200);
        let jeton = r["jeton"].as_str().unwrap().to_string();
        assert_eq!(etat(&jeton), 200);
        // second échange du même lien : refusé, avec un message qui dit quoi faire
        let (c, r) = lire(echange(&ticket).call());
        assert_eq!((c, r["motif"].as_str()), (410, Some("deja_servi")));
        assert!(r["erreur"].as_str().unwrap().contains("Entrée") && r["jeton"].is_null());
        assert_eq!(etat(&jeton), 200);
        let (c, r) = lire(echange(&"f".repeat(64)).call());
        assert_eq!((c, r["motif"].as_str()), (401, Some("inconnu")));
        // nouveau lien : nouvelle session, l'ancienne est fermée
        let (c, r) = lire(echange(&session.ticket().unwrap()).call());
        assert_eq!(c, 200);
        assert_eq!(etat(r["jeton"].as_str().unwrap()), 200);
        assert_eq!(etat(&jeton), 401);
        serveur.unblock();
        assert!(fil.join().unwrap().is_err());
        let _ = fs::remove_dir_all(&dossier);
    }

    /// Clés d'agent côté console : jamais en clair sur le disque quand le compte a un mot de passe.
    /// Agent principal chiffré dès la création du compte ; clés en clair d'une version précédente
    /// (agent principal et mandat) chiffrées à l'ouverture suivante, le clair effacé ; « Connecter
    /// l'agent » remet toujours la bonne clé, avec le mot de passe déjà demandé (R72), sans autre question.
    #[test]
    fn cles_d_agent_chiffrees_sur_le_disque_de_la_console() {
        let dossier = std::env::temp_dir().join(format!("plafond-cles-agent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dossier);
        let fichiers = fichiers_compte(&dossier.to_string_lossy());
        let defaut = dossier.join("etat-coffre.json").to_string_lossy().into_owned();
        let mdp = "un mot de passe assez long";
        let ouvrir = |chemin: &str, corps: Value| {
            let serveur = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
            let base = format!("http://127.0.0.1:{}", serveur.server_addr().to_ip().unwrap().port());
            let (s2, f2) = (serveur.clone(), fichiers_compte(&dossier.to_string_lossy()));
            let fil = std::thread::spawn(move || porte(&s2, &Session::fixe("jeton-de-test"), &f2).map_err(|e| e.to_string()));
            assert_eq!(poster(&base, chemin, corps).0, 200);
            fil.join().unwrap().unwrap()
        };
        let clair = |k: &Keypair| hex::encode(k.secret_bytes());
        // 1. création du compte : la clé de l'agent principal est chiffrée d'emblée
        let (_, principal, enveloppe) = ouvrir("/api/compte/creer", json!({ "mot_de_passe": mdp, "confirmation": mdp }));
        let sur_disque = fs::read_to_string(&fichiers.agent).unwrap();
        assert!(!sur_disque.contains(&clair(&principal.cle)), "clé de l'agent principal en clair dans {}", fichiers.agent);
        assert!(sur_disque.contains("argon2id") && sur_disque.contains(cle::USAGE_AGENT), "même format que la clé du propriétaire");
        // 2. nouveau mandat pendant la session : clé chiffrée sans redemander le mot de passe
        let a = agents::nouveau(&defaut, "Recherche", None, Some(&enveloppe)).unwrap();
        let fichier_a = fs::read_to_string(&a.cle).unwrap();
        assert!(fichier_a.contains("argon2id") && crate::prive::est_prive(std::path::Path::new(&a.cle)).unwrap());
        let p = agents::Principal::from(principal.cle);
        assert_eq!(agents::publique(&a, &p).unwrap().serialize().to_vec(), hex::decode(a.publique.as_ref().unwrap()).unwrap());
        assert_ne!(agents::cle(&a, &p).unwrap().public_key(), agents::publique(&a, &p).unwrap(), "les opérations du propriétaire n'ouvrent pas la clé");
        // 3. migration : fichiers en clair d'une version précédente (agent principal et mandat)
        let (ancien_principal, ancien_mandat) = (cle::nouvelle().unwrap(), cle::nouvelle().unwrap());
        fs::remove_file(&fichiers.agent).unwrap();
        fs::write(&fichiers.agent, clair(&ancien_principal)).unwrap();
        let b = agents::nouveau(&defaut, "Veille", None, None).unwrap();
        fs::remove_file(&b.cle).unwrap();
        fs::write(&b.cle, clair(&ancien_mandat)).unwrap();
        // une migration interrompue juste avant le remplacement se termine à la lecture suivante
        let c = agents::nouveau(&defaut, "Interrompu", None, None).unwrap();
        let cle_c = agents::cle(&c, &p).unwrap();
        agents::ecrire_cle(std::path::Path::new(&format!("{}.chiffre", c.cle)), &cle_c, Some(&enveloppe)).unwrap();
        drop(enveloppe);
        let (_, principal, enveloppe) = ouvrir("/api/compte/ouvrir", json!({ "mot_de_passe": mdp }));
        assert_eq!(clair(&principal.cle), clair(&ancien_principal), "même agent principal après migration");
        assert!(!fs::read_to_string(&fichiers.agent).unwrap().contains(&clair(&ancien_principal)), "clair de l'agent principal effacé");
        // les mandats sont migrés au démarrage de la console (`servir`), avec l'enveloppe de la session
        let serveur = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let base = format!("http://127.0.0.1:{}", serveur.server_addr().to_ip().unwrap().port());
        *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(defaut.clone());
        let (s2, ch, owner) = (serveur.clone(), fichiers.cle.clone(), cle::dechiffrer(&cle::lire(&fichiers.cle).unwrap(), mdp).unwrap());
        let fil = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            servir(&s2, &Session::fixe("jeton-de-test"), rt.handle().clone(), owner, principal, Some(ch), Some(enveloppe));
        });
        assert_eq!(poster(&base, "/api/connecter/preparer", json!({ "agent": b.id })).0, 403, "toujours le mot de passe (R72)");
        let (statut, r) = poster(&base, "/api/connecter/preparer", json!({ "agent": b.id, "mot_de_passe": mdp }));
        assert_eq!(statut, 200, "{r}");
        for (agent, cle_attendue) in [(&b, &ancien_mandat), (&c, &cle_c)] {
            let f = fs::read_to_string(&agent.cle).unwrap();
            assert!(f.contains("argon2id") && !f.contains(&clair(cle_attendue)), "clé du mandat {} encore en clair", agent.nom);
            assert!(!std::path::Path::new(&format!("{}.chiffre", agent.cle)).exists(), "pas de fichier intermédiaire laissé");
            assert!(crate::prive::est_prive(std::path::Path::new(&agent.cle)).unwrap());
        }
        // le kit porte bien la clé d'origine du mandat migré
        let kit: connexion::Scelle = serde_json::from_value(r["kit"].clone()).unwrap();
        let installe = dossier.join("serveur-agent").to_string_lossy().into_owned();
        connexion::installer_demo(&kit, r["code"].as_str().unwrap(), &installe).unwrap();
        assert_eq!(fs::read_to_string(format!("{installe}/agent.key")).unwrap().trim(), clair(&ancien_mandat));
        // aucun fichier de la console ne contient une clé d'agent en clair
        let mut tout = String::new();
        for f in fs::read_dir(&dossier).unwrap().chain(fs::read_dir(dossier.join("agents")).unwrap()).filter_map(|e| e.ok()).filter(|e| e.path().is_file()) {
            tout += &fs::read_to_string(f.path()).unwrap_or_default();
        }
        for k in [&ancien_principal, &ancien_mandat, &cle_c] {
            assert!(!tout.contains(&clair(k)), "clé d'agent en clair restée sur le disque de la console");
        }
        // un autre mot de passe n'ouvre pas la clé d'un mandat : message clair, pas de kit
        let f: cle::Fichier = serde_json::from_str(&fs::read_to_string(&c.cle).unwrap()).unwrap();
        assert!(cle::ouvrir_cle_agent(&f, Some("un tout autre mot de passe"), None).is_err());
        assert_eq!(clair(&cle::ouvrir_cle_agent(&f, Some(mdp), None).unwrap()), clair(&cle_c));
        serveur.unblock();
        fil.join().unwrap();
        *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let _ = fs::remove_dir_all(&dossier);
    }

    /// R66 : la confirmation de sauvegarde (mot de passe seul) ne doit pas servir d'oracle pour
    /// deviner la phrase mot par mot : trois positions DISTINCTES exigées, échecs comptés.
    #[test]
    fn r66_confirmation_de_sauvegarde_sans_oracle() {
        let mdp = "le bon mot de passe";
        let (base, serveur, fil, phrase, _, ch) = console_avec_cle("r66", true);
        // un seul mot juste, répété trois fois à la même position : refusé (sinon 2048 essais par mot)
        let (statut, _) = poster(&base, "/api/recuperation/confirmer", json!({ "mot_de_passe": mdp, "positions": [0, 0, 0], "mots": [phrase[0], phrase[0], phrase[0]] }));
        assert_eq!(statut, 400, "positions répétées : refus");
        assert!(!lire_compte(Some(&ch)).sauvegarde_faite);
        // les mauvais essais sont comptés : verrouillage après 5 échecs
        let mut statuts = Vec::new();
        for _ in 0..6 {
            statuts.push(poster(&base, "/api/recuperation/confirmer", json!({ "mot_de_passe": mdp, "positions": [0, 1, 2], "mots": ["zoo", "zoo", "zoo"] })).0);
        }
        assert_eq!(statuts.last(), Some(&429), "essais illimités sur les mots de la phrase : {statuts:?}");
        serveur.unblock();
        fil.join().unwrap();
        for f in [ch.clone(), chemin_compte(&ch)] {
            let _ = std::fs::remove_file(f);
        }
    }

    /// R66 (suite) : trois positions distinctes et les bons mots : la sauvegarde est confirmée.
    #[test]
    fn r66_confirmation_de_sauvegarde_legitime() {
        let mdp = "le bon mot de passe";
        let (base, serveur, fil, phrase, _, ch) = console_avec_cle("r66b", false);
        let (statut, corps) = poster(&base, "/api/recuperation/confirmer", json!({ "mot_de_passe": mdp, "positions": [3, 11, 23], "mots": [phrase[3], format!(" {} ", phrase[11].to_uppercase()), phrase[23]] }));
        assert_eq!(statut, 200, "{corps}");
        assert!(lire_compte(Some(&ch)).sauvegarde_faite);
        serveur.unblock();
        fil.join().unwrap();
        for f in [ch.clone(), chemin_compte(&ch)] {
            let _ = std::fs::remove_file(f);
        }
    }

    /// R67 : les échecs de code à 6 chiffres ne doivent pas être remis à zéro par une action au mot
    /// de passe seul (sinon : 4 codes faux, 1 action sans code, 4 codes faux… sans jamais de verrou).
    #[test]
    fn r67_essais_de_code_non_remis_a_zero_par_le_mot_de_passe_seul() {
        let mdp = "le bon mot de passe";
        let mut c = cle::nouveau_coffret().unwrap();
        let owner = cle::cle_du_coffret(&c).unwrap();
        let secret = vec![6u8; 20];
        c.totp = Some(zeroize::Zeroizing::new(secret.clone()));
        let chemin = std::env::temp_dir().join(format!("cle-r67-{}.json", std::process::id()));
        let ch = chemin.to_str().unwrap();
        let _ = std::fs::remove_file(ch);
        cle::ecrire(ch, &cle::chiffrer_coffret(&c, mdp).unwrap()).unwrap();
        let p = double_auth::maintenant() / 30;
        let faux = (0..1_000_000u32).find(|n| (p.saturating_sub(2)..=p + 2).all(|q| double_auth::code(&secret, q) != *n)).unwrap();
        let faux = format!("{faux:06}");
        let mut g = Garde::neuve();
        let mut essais_de_code = 0;
        for _ in 0..3 {
            for _ in 0..4 {
                if g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp, "code": faux }), true).is_err() && g.verrou.is_none() {
                    essais_de_code += 1;
                }
            }
            let _ = g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp }), false); // action au mot de passe seul
        }
        assert!(g.verrou.is_some(), "12 codes faux sans verrouillage");
        assert!(essais_de_code <= 5, "au plus 5 essais de code avant le verrou, obtenu {essais_de_code}");
        // les verrous successifs s'allongent (essais de code seulement) : 1 min, puis 2 min…
        let premier = g.verrou.unwrap();
        g.verrou = None;
        for _ in 0..5 {
            let _ = g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp, "code": faux }), true);
        }
        assert!(g.verrou.is_some_and(|v| v > premier && v.duration_since(Instant::now()) >= Duration::from_secs(100)), "le deuxième verrou dure au moins 2 minutes");
        // un bon code remet les compteurs à zéro
        g.verrou = None;
        let bon = format!("{:06}", double_auth::code(&secret, double_auth::maintenant() / 30));
        assert!(g.ouvrir(Some(ch), &owner, &json!({ "mot_de_passe": mdp, "code": bon }), true).is_ok());
        assert_eq!((g.echecs_code, g.verrous_code), (0, 0));
        let _ = std::fs::remove_file(ch);
    }

    #[test]
    fn mandat_finance_par_budget_fois_duree() {
        let v = |j: i64| json!({ "budget_sompi": 2_000_000_000i64, "periode_daa": crate::JOUR_DAA, "plafond_sompi": 200_000_000i64, "duree_jours": j });
        // 20 par jour pendant 30 jours : 600 alloués, perte maximale garantie du mandat = 600
        let (r, d) = regles_mandat(&v(30)).unwrap();
        assert_eq!((r.depot, d), (60_000_000_000, Some(30)));
        assert_eq!(regles_json(&r)["perte_max_mandat_sompi"], 60_000_000_000u64);
        // budget hebdomadaire sur 10 jours : 2 semaines entamées
        let mut w = v(10);
        w["periode_daa"] = json!(7 * crate::JOUR_DAA);
        assert_eq!(regles_mandat(&w).unwrap().0.depot, 4_000_000_000);
        // sans durée : une période, comme avant
        assert_eq!(regles_mandat(&v(0)).unwrap(), (crate::Regles::calculer(2_000_000_000, crate::JOUR_DAA, 200_000_000).unwrap(), None));
        assert!(regles_mandat(&v(400)).is_err());
    }

    #[test]
    fn page_sans_ressource_externe() {
        // aucune ressource tierce : la politique CSP de la console l'interdirait de toute façon
        for motif in ["<script src", "<link ", "http://", "https://fonts", "cdn."] {
            assert!(!PAGE.contains(motif), "ressource externe dans la page : {motif}");
        }
        // choix produit : l'unité du réseau n'apparaît jamais à l'écran (requêtes et devises)
        // seule exception : la liste des cryptos proposées au paiement (Kaspa y figure comme les autres)
        for ligne in PAGE.lines().filter(|l| l.contains("KAS")) {
            assert!(ligne.contains("const CRYPTOS"), "unité du réseau hors de la liste des cryptos : {ligne}");
        }
        assert_eq!(PAGE.matches("KAS").count(), 1);
    }
}

/// Données du tableau de bord, une fois (commande `tableau`, utile en CI et pour le support).
pub async fn tableau_json(owner: &Keypair, agent: &Keypair) -> Res<Value> {
    tableau(owner, agent, None).await
}

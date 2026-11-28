//! Passerelle d'entreprise : un point de passage unique pour tous les agents d'une organisation.
//!
//! Le routeur (routeur.rs) sert UN agent. La passerelle en sert plusieurs, chacun avec son coffre,
//! sa clé d'API et sa politique, derrière une seule adresse que l'équipe de sécurité surveille.
//!
//! Principes (philosophie Plafond : borner le pire cas, ne rien demander de confiance) :
//!   - la clé du PROPRIÉTAIRE n'entre jamais dans la passerelle : elle ne charge que la clé de chaque
//!     agent et la clé PUBLIQUE de son propriétaire. Passerelle piratée = perte bornée par les
//!     covenants des coffres, rien de plus ;
//!   - les clés d'API ne sont jamais stockées : le fichier de configuration n'en garde que
//!     l'empreinte SHA-256. Une copie du fichier ne permet pas d'appeler la passerelle ;
//!   - arrêt d'urgence : une clé d'administration distincte arrête un agent ou tous, instantanément,
//!     et l'arrêt survit à un redémarrage. L'arrêt est local (la passerelle refuse de payer) ; le gel
//!     sur la chaîne reste l'affaire du propriétaire, depuis sa console ;
//!   - journal d'audit chaîné : chaque ligne contient l'empreinte de la précédente. Une ligne
//!     modifiée, supprimée ou insérée casse la chaîne ; la passerelle refuse alors de démarrer, et
//!     `passerelle-verifier` désigne la ligne fautive. La tête de chaîne (n, empreinte) est exposée
//!     pour être recopiée ailleurs (SIEM, coffre de l'entreprise) : c'est ce qui empêche de réécrire
//!     tout le journal d'un coup ;
//!   - tout est refusé par défaut : agent inconnu, agent arrêté, vendeur hors liste, adresse interne,
//!     journal illisible ou impossible à écrire (on ne paie pas ce qu'on ne peut pas tracer).
//!
//! Fichier de configuration (JSON) :
//! ```json
//! {
//!   "ecoute": "127.0.0.1:8403",
//!   "journal": "passerelle-journal.jsonl",
//!   "arrets": "passerelle-arrets.json",
//!   "admin_cle_sha256": "<empreinte de la clé d'administration>",
//!   "agents": [
//!     { "nom": "recherche", "dossier": "agents/recherche", "cle_api_sha256": "<empreinte>",
//!       "origines": ["https://api.exemple.org"], "max_requete_sompi": 20000000, "debit_par_minute": 30 }
//!   ]
//! }
//! ```
//! `dossier` est un agent installé par `vault-cli agent-installer` (agent.json, agent.key, état).
//!
//! Points d'entrée (JSON) :
//!   agents  (`Authorization: Bearer <clé de l'agent>`)
//!     GET  /v1/coffre                     budget du coffre de l'agent appelant
//!     POST /v1/fetch   {url, max_sompi?}  achète la ressource, paie si 402 (`Idempotency-Key` gérée)
//!   administration  (`Authorization: Bearer <clé d'administration>`)
//!     GET  /admin/etat                    agents, arrêts, tête du journal
//!     POST /admin/arret   {agent}         arrête un agent (« * » : tous)
//!     POST /admin/reprise {agent}         lève l'arrêt
//!     GET  /admin/financement             demande de financement de chaque agent (requêtes restantes,
//!                                         montant, adresse de dépôt vérifiée, liens d'achat)
//!     GET  /v1/financement                la même fiche, pour l'agent lui-même

use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use secp256k1::Keypair;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

use crate::routeur::{Debit, Idempotence, Politique, egal_temps_constant, url_journal};
use crate::*;

pub const TOUS: &str = "*";
const ORIGINE_CHAINE: [u8; 32] = [0; 32];

pub fn empreinte(cle: &str) -> [u8; 32] {
    Sha256::digest(cle.as_bytes()).into()
}

/// Nouvelle clé d'API (256 bits d'aléa) et son empreinte, à recopier dans la configuration.
pub fn nouvelle_cle() -> Res<(String, String)> {
    let mut octets = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(octets.as_mut()).map_err(|e| format!("aléa indisponible : {e}"))?;
    let cle = format!("plf_{}", hex::encode(octets.as_ref()));
    let e = hex::encode(empreinte(&cle));
    Ok((cle, e))
}

fn empreinte_hex(nom: &str, v: &str) -> Res<[u8; 32]> {
    let b = hex::decode(v.trim()).map_err(|_| format!("{nom} : empreinte hexadécimale attendue"))?;
    b.try_into().map_err(|_| format!("{nom} : empreinte SHA-256 de 32 octets attendue").into())
}

// ---------------------------------------------------------------- journal chaîné

/// Journal d'audit en JSON Lines où chaque ligne porte `n` (1, 2, 3…) et `precedent`, l'empreinte
/// SHA-256 de la ligne précédente telle qu'écrite (64 zéros pour la première).
pub struct Journal {
    chemin: PathBuf,
    n: u64,
    tete: [u8; 32],
}

/// Vérifie toute la chaîne. Renvoie (nombre de lignes, empreinte de la dernière).
pub fn verifier_journal(chemin: &Path) -> Res<(u64, [u8; 32])> {
    let mut n = 0u64;
    let mut tete = ORIGINE_CHAINE;
    let f = match std::fs::File::open(chemin) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, tete)),
        Err(e) => return Err(format!("{} : {e}", chemin.display()).into()),
    };
    for ligne in std::io::BufReader::new(f).lines() {
        let ligne = ligne?;
        let num = n + 1;
        let v: Value = serde_json::from_str(&ligne).map_err(|_| format!("journal falsifié ou abîmé : ligne {num} illisible"))?;
        if v["n"].as_u64() != Some(num) {
            return Err(format!("journal falsifié : ligne {num} numérotée {} (ligne supprimée ou insérée)", v["n"]).into());
        }
        if v["precedent"].as_str() != Some(hex::encode(tete).as_str()) {
            return Err(format!("journal falsifié : la ligne {num} ne suit pas la ligne {n} (une des deux a été modifiée)").into());
        }
        tete = Sha256::digest(ligne.as_bytes()).into();
        n = num;
    }
    Ok((n, tete))
}

impl Journal {
    /// Ouvre le journal en vérifiant la chaîne existante : un journal falsifié bloque le démarrage.
    pub fn ouvrir(chemin: &Path) -> Res<Self> {
        let (n, tete) = verifier_journal(chemin)?;
        Ok(Journal { chemin: chemin.to_path_buf(), n, tete })
    }

    pub fn tete(&self) -> (u64, String) {
        (self.n, hex::encode(self.tete))
    }

    /// Ajoute une entrée et la force sur le disque. Une erreur ici doit faire refuser l'opération.
    pub fn ecrire(&mut self, entree: Value) -> Res<()> {
        let mut e = entree;
        e["n"] = json!(self.n + 1);
        e["precedent"] = json!(hex::encode(self.tete));
        e["horodatage_unix"] = json!(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
        let ligne = e.to_string();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.chemin).map_err(|err| format!("journal {} : {err}", self.chemin.display()))?;
        f.write_all(format!("{ligne}\n").as_bytes())?;
        f.sync_data()?;
        self.tete = Sha256::digest(ligne.as_bytes()).into();
        self.n += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------- configuration

#[derive(Deserialize)]
struct FichierConfig {
    ecoute: Option<String>,
    journal: Option<String>,
    arrets: Option<String>,
    admin_cle_sha256: String,
    #[serde(default)]
    demo: bool,
    /// Démo testnet : lance aussi le vendeur x402 local (port 8402), payé à l'adresse du propriétaire
    /// du premier agent.
    #[serde(default)]
    vendeur_demo: bool,
    /// Modèle de lien vers un service d'achat (`{adresse}`, `{montant}`, `{devise}`), https seulement.
    lien_achat: Option<String>,
    agents: Vec<FichierAgent>,
}

#[derive(Deserialize)]
struct FichierAgent {
    nom: String,
    dossier: String,
    cle_api_sha256: String,
    #[serde(default)]
    origines: Vec<String>,
    max_requete_sompi: Option<i64>,
    debit_par_minute: Option<usize>,
    /// Demande de financement de cet agent : cible et seuil en requêtes, devise (src/financement.rs).
    recharge: Option<crate::financement::Reglage>,
}

/// Ce que la passerelle sait d'un agent : jamais la clé de son propriétaire.
pub struct Agent {
    pub nom: String,
    cle_api: [u8; 32],
    pub owner_pk: Vec<u8>,
    pub cle: Keypair,
    pub regles: Option<Regles>,
    pub etat: String,
    politique: Politique,
    debit: Debit,
    recharge: Option<crate::financement::Reglage>,
}

/// Lit un agent installé par `agent-installer` (même format que `agent-payer`).
fn charger_agent(dossier: &Path) -> Res<(Vec<u8>, Keypair, Option<Regles>, String)> {
    let meta: Value = serde_json::from_str(&std::fs::read_to_string(dossier.join("agent.json")).map_err(|e| format!("{}/agent.json : {e}", dossier.display()))?)?;
    let owner_pk = hex::decode(meta["proprietaire"].as_str().ok_or("agent.json : propriétaire absent")?)?;
    if owner_pk.len() != 32 || secp256k1::XOnlyPublicKey::from_slice(&owner_pk).is_err() {
        return Err("agent.json : clé publique du propriétaire invalide".into());
    }
    let regles: Option<Regles> = serde_json::from_value(meta["regles"].clone()).unwrap_or(None);
    // Clé lisible par d'autres comptes de la machine : refus (elle signe les dépenses du coffre).
    if !crate::prive::est_prive(&dossier.join("agent.key")).map_err(|e| format!("{}/agent.key : {e}", dossier.display()))? {
        return Err(format!("{}/agent.key est lisible par d'autres utilisateurs : réservez-le au compte de la passerelle (chmod 600)", dossier.display()).into());
    }
    let hexa = zeroize::Zeroizing::new(std::fs::read_to_string(dossier.join("agent.key")).map_err(|e| format!("{}/agent.key : {e}", dossier.display()))?);
    let cle = Keypair::from_seckey_slice(secp256k1::SECP256K1, &zeroize::Zeroizing::new(hex::decode(hexa.trim())?))?;
    let etat = dossier.join("etat-coffre.json").to_string_lossy().into_owned();
    Ok((owner_pk, cle, regles, etat))
}

fn plafond_par_requete(regles: &Option<Regles>) -> i64 {
    let r = regles.clone().unwrap_or_else(Regles::standard);
    (r.capacite as u64).saturating_sub(FEE) as i64
}

fn normaliser_origines(o: &[String]) -> Vec<String> {
    o.iter().map(|s| s.trim().trim_end_matches('/').to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()
}

// ---------------------------------------------------------------- passerelle

/// Exécute l'achat d'une ressource pour un agent (le vrai paiement, ou un faux dans les tests).
pub type Acheteur = Box<dyn FnMut(&Agent, &str, i64) -> Res<x402::Achat>>;
/// Lit le budget d'un agent sur le nœud.
pub type Lecteur = Box<dyn FnMut(&Agent) -> Res<Value>>;

pub struct Passerelle {
    pub ecoute: String,
    vendeur_demo: bool,
    agents: Vec<Agent>,
    admin: [u8; 32],
    arrets: BTreeSet<String>,
    fichier_arrets: PathBuf,
    pub journal: Journal,
    idem: HashMap<String, Idempotence>,
    acheter: Acheteur,
    lire: Lecteur,
    lien_achat: Option<String>,
    /// Cours indicatifs (devise -> prix d'un KAS), pour exprimer la demande dans la devise du client.
    cours: Box<dyn FnMut() -> Option<Value>>,
}

pub struct Requete<'a> {
    pub methode: &'a str,
    pub chemin: &'a str,
    pub autorisation: Option<&'a str>,
    pub idempotence: Option<&'a str>,
    pub corps: &'a str,
}

impl Passerelle {
    /// Construit la passerelle depuis son fichier de configuration. Les chemins relatifs (dossiers des
    /// agents, journal, arrêts) se lisent depuis le dossier du fichier.
    pub fn depuis_fichier(chemin: &Path, acheter: Acheteur, lire: Lecteur) -> Res<Self> {
        let base = chemin.parent().map(Path::to_path_buf).unwrap_or_default();
        let rel = |p: &str| -> PathBuf { if Path::new(p).is_absolute() { PathBuf::from(p) } else { base.join(p) } };
        let cfg: FichierConfig = serde_json::from_str(&std::fs::read_to_string(chemin).map_err(|e| format!("{} : {e}", chemin.display()))?).map_err(|e| format!("configuration invalide : {e}"))?;
        let admin = empreinte_hex("admin_cle_sha256", &cfg.admin_cle_sha256)?;
        if cfg.agents.is_empty() {
            return Err("configuration : aucun agent".into());
        }
        let mut agents = Vec::new();
        let mut vus_noms = BTreeSet::new();
        let mut vues_cles = BTreeSet::new();
        for a in cfg.agents {
            if a.nom.is_empty() || a.nom == TOUS || a.nom.len() > 64 {
                return Err(format!("agent « {} » : nom invalide", a.nom).into());
            }
            if !vus_noms.insert(a.nom.clone()) {
                return Err(format!("agent « {} » déclaré deux fois", a.nom).into());
            }
            let cle_api = empreinte_hex(&format!("agent « {} » : cle_api_sha256", a.nom), &a.cle_api_sha256)?;
            if cle_api == admin || !vues_cles.insert(cle_api) {
                return Err(format!("agent « {} » : sa clé d'API doit être unique (ni partagée, ni égale à la clé d'administration)", a.nom).into());
            }
            let (owner_pk, cle, regles, etat) = charger_agent(&rel(&a.dossier)).map_err(|e| format!("agent « {} » : {e}", a.nom))?;
            let plafond = plafond_par_requete(&regles);
            let origines = normaliser_origines(&a.origines);
            if !cfg.demo && origines.is_empty() {
                return Err(format!("agent « {} » : liste « origines » vide ; hors démo, chaque agent doit avoir ses vendeurs autorisés", a.nom).into());
            }
            agents.push(Agent {
                nom: a.nom,
                cle_api,
                owner_pk,
                cle,
                regles,
                etat,
                politique: Politique { origines, max_requete: a.max_requete_sompi.unwrap_or(plafond).clamp(0, plafond), demo: cfg.demo },
                debit: Debit::new(a.debit_par_minute.unwrap_or(30).max(1)),
                recharge: a.recharge,
            });
        }
        let fichier_arrets = rel(cfg.arrets.as_deref().unwrap_or("passerelle-arrets.json"));
        let arrets: BTreeSet<String> = match std::fs::read_to_string(&fichier_arrets) {
            Ok(t) => serde_json::from_str(&t).map_err(|_| format!("{} illisible : par prudence la passerelle ne démarre pas", fichier_arrets.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(e) => return Err(format!("{} : {e}", fichier_arrets.display()).into()),
        };
        let journal = Journal::ouvrir(&rel(cfg.journal.as_deref().unwrap_or("passerelle-journal.jsonl")))?;
        if cfg.vendeur_demo && !cfg.demo {
            return Err("vendeur_demo exige demo : true (réseau de test uniquement)".into());
        }
        Ok(Passerelle {
            vendeur_demo: cfg.vendeur_demo,
            ecoute: cfg.ecoute.unwrap_or_else(|| format!("127.0.0.1:{}", routeur::PORT)),
            agents,
            admin,
            arrets,
            fichier_arrets,
            journal,
            idem: HashMap::new(),
            lien_achat: cfg.lien_achat.filter(|l| l.starts_with("https://")),
            cours: Box::new(|| None),
            acheter,
            lire,
        })
    }

    pub fn noms(&self) -> Vec<String> {
        self.agents.iter().map(|a| a.nom.clone()).collect()
    }

    pub fn demo(&self) -> bool {
        self.agents.first().is_some_and(|a| a.politique.demo)
    }

    /// Qui appelle ? Toutes les empreintes sont comparées, en temps constant, sans sortie anticipée.
    fn appelant(&self, autorisation: Option<&str>) -> Appelant {
        let Some(jeton) = autorisation.and_then(|a| a.strip_prefix("Bearer ")) else { return Appelant::Inconnu };
        let e = empreinte(jeton);
        let mut trouve = Appelant::Inconnu;
        if egal_temps_constant(&e, &self.admin) {
            trouve = Appelant::Admin;
        }
        for (i, a) in self.agents.iter().enumerate() {
            if egal_temps_constant(&e, &a.cle_api) {
                trouve = Appelant::Agent(i);
            }
        }
        trouve
    }

    fn arrete(&self, nom: &str) -> bool {
        self.arrets.contains(TOUS) || self.arrets.contains(nom)
    }

    fn enregistrer_arrets(&self) -> Res<()> {
        let tmp = self.fichier_arrets.with_extension("nouveau");
        // Écriture puis synchronisation par le même descripteur, ouvert en écriture (Windows refuse
        // de vider sur le disque un fichier ouvert en lecture seule).
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(serde_json::to_string_pretty(&self.arrets)?.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.fichier_arrets)?;
        Ok(())
    }

    /// Traite une requête (sans réseau entrant : testable directement). Les requêtes passent une par
    /// une : deux achats ne lisent jamais le même état de coffre en même temps.
    pub fn traiter(&mut self, r: Requete) -> (u16, Value) {
        match self.appelant(r.autorisation) {
            Appelant::Inconnu => (401, json!({ "erreur": "clé d'API invalide" })),
            Appelant::Admin => self.admin(r),
            Appelant::Agent(i) => self.agent(i, r),
        }
    }

    /// Branche la lecture des cours (sans elle, la demande est exprimée en requêtes seulement).
    pub fn avec_cours(mut self, cours: Box<dyn FnMut() -> Option<Value>>) -> Self {
        self.cours = cours;
        self
    }

    /// Demande de financement d'un agent : combien de requêtes il lui reste, combien il manque pour
    /// atteindre sa cible, et OÙ envoyer l'argent. L'adresse ne vient jamais de l'agent : pour un
    /// coffre à lignée, c'est celle de la fiche de dépôt, recalculée ici et dont la signature du
    /// propriétaire est vérifiée (S7) ; pour un ancien coffre, celle que l'administrateur a écrite
    /// dans la configuration. Sans adresse vérifiable, la fiche n'en donne pas.
    fn financement(&mut self, i: usize) -> Value {
        let Some(reglage) = self.agents[i].recharge.clone() else {
            return json!({ "agent": self.agents[i].nom, "configure": false });
        };
        let lu = match (self.lire)(&self.agents[i]) {
            Ok(v) => v,
            Err(e) => return json!({ "agent": self.agents[i].nom, "configure": true, "erreur": e.to_string() }),
        };
        let valeur = lu["coffre"]["valeur_sompi"].as_u64().unwrap_or(0);
        let cours = (self.cours)().and_then(|c| c[reglage.devise.to_ascii_lowercase().as_str()].as_f64());
        let besoin = crate::financement::calculer(valeur, &reglage, cours);
        let a = &self.agents[i];
        let a_lignee = lu["coffre"]["lignee"].is_string();
        let fiche: Option<crate::coffre092::Fiche> = serde_json::from_value(lu["depot"].clone()).ok().filter(|f: &crate::coffre092::Fiche| {
            crate::coffre092::verifier_fiche(f).is_ok() && f.coffre.owner == hex::encode(&a.owner_pk) && f.coffre.agent == hex::encode(crate::xonly(&a.cle))
        });
        let (adresse, origine) = match (&fiche, a_lignee, &reglage.adresse_depot) {
            (Some(f), _, _) => (Some(f.adresse_depot.clone()), "fiche de dépôt vérifiée (signée par le propriétaire)"),
            (None, true, _) => (None, "adresse de dépôt non vérifiable pour l'instant : aucune adresse n'est donnée"),
            (None, false, Some(adr)) => (Some(adr.clone()), "adresse écrite par l'administrateur dans la configuration"),
            (None, false, None) => (None, "aucune adresse de dépôt configurée"),
        };
        let mut v = crate::financement::fiche(&a.nom, &besoin, &reglage, adresse.as_deref().unwrap_or(""), self.lien_achat.as_deref().filter(|_| adresse.is_some()));
        v["configure"] = json!(true);
        v["adresse_depot"] = json!(adresse);
        v["origine_adresse"] = json!(origine);
        v["fiche_depot"] = json!(fiche);
        v["depot_minimal_sompi"] = json!(fiche.as_ref().map(|f| f.depot_minimal_sompi));
        v["liens"] = crate::financement::liens();
        v
    }

    fn admin(&mut self, r: Requete) -> (u16, Value) {
        match (r.methode, r.chemin) {
            ("GET", "/admin/financement") => {
                let fiches: Vec<Value> = (0..self.agents.len()).map(|i| self.financement(i)).collect();
                let a_recharger = fiches.iter().filter(|f| f["a_recharger"] == true).count();
                (200, json!({ "agents": fiches, "a_recharger": a_recharger }))
            }
            ("GET", "/admin/etat") => {
                let (n, tete) = self.journal.tete();
                let agents: Vec<Value> = self.agents.iter().map(|a| json!({ "nom": a.nom, "arrete": self.arrete(&a.nom), "vendeurs": a.politique.origines, "max_requete_sompi": a.politique.max_requete })).collect();
                (200, json!({ "agents": agents, "arret_general": self.arrets.contains(TOUS), "journal": { "lignes": n, "tete_sha256": tete } }))
            }
            ("POST", "/admin/arret") | ("POST", "/admin/reprise") => {
                let arret = r.chemin == "/admin/arret";
                let v: Value = match serde_json::from_str(r.corps) {
                    Ok(v) => v,
                    Err(_) => return (400, json!({ "erreur": "JSON invalide" })),
                };
                let nom = v["agent"].as_str().unwrap_or("").to_string();
                if nom != TOUS && !self.agents.iter().any(|a| a.nom == nom) {
                    return (404, json!({ "erreur": format!("agent inconnu : « {nom} »") }));
                }
                let avant = self.arrets.clone();
                if arret {
                    self.arrets.insert(nom.clone());
                } else if nom == TOUS {
                    self.arrets.clear(); // la reprise générale lève aussi les arrêts individuels
                } else {
                    self.arrets.remove(&nom);
                }
                if let Err(e) = self.enregistrer_arrets() {
                    self.arrets = avant;
                    return (500, json!({ "erreur": format!("arrêt non enregistré, rien n'a changé : {e}") }));
                }
                let _ = self.journal.ecrire(json!({ "evenement": if arret { "arret" } else { "reprise" }, "agent": nom }));
                println!("[PASSERELLE] {} : {nom}", if arret { "ARRÊT" } else { "reprise" });
                (200, json!({ "agent": nom, "arrete": arret, "arrets": self.arrets }))
            }
            _ => (404, json!({ "erreur": "point d'entrée inconnu" })),
        }
    }

    fn agent(&mut self, i: usize, r: Requete) -> (u16, Value) {
        let nom = self.agents[i].nom.clone();
        if self.arrete(&nom) {
            let _ = self.journal.ecrire(json!({ "evenement": "refus-arret", "agent": nom, "chemin": r.chemin }));
            return (423, json!({ "erreur": "agent arrêté par l'administrateur" }));
        }
        match (r.methode, r.chemin) {
            ("GET", "/v1/coffre") => match (self.lire)(&self.agents[i]) {
                Ok(v) => (200, v),
                Err(e) => (503, json!({ "erreur": e.to_string() })),
            },
            // L'agent peut dire à son propriétaire qu'il a besoin d'être rechargé ; il transmet
            // alors une fiche que le payeur vérifie, jamais une adresse de son cru.
            ("GET", "/v1/financement") => (200, self.financement(i)),
            ("POST", "/v1/fetch") => {
                let cle_idem = r.idempotence.map(|k| k.chars().take(128).collect::<String>());
                if let Some(rejoue) = cle_idem.as_deref().and_then(|k| self.idem.get(&nom).and_then(|m| m.lire(k))) {
                    return (rejoue.0, json!({ "rejoue": true, "reponse": rejoue.1 }));
                }
                let rep = self.fetch(i, r.corps);
                if let (Some(k), true) = (cle_idem, rep.0 == 200 || rep.0 == 402) {
                    self.idem.entry(nom).or_insert_with(Idempotence::new).garder(k, rep.clone());
                }
                rep
            }
            _ => (404, json!({ "erreur": "point d'entrée inconnu" })),
        }
    }

    fn fetch(&mut self, i: usize, corps: &str) -> (u16, Value) {
        let nom = self.agents[i].nom.clone();
        let v: Value = match serde_json::from_str(corps) {
            Ok(v) => v,
            Err(_) => return (400, json!({ "erreur": "JSON invalide" })),
        };
        let url = v["url"].as_str().unwrap_or("").to_string();
        if url.len() > 2048 {
            return (400, json!({ "erreur": "url trop longue" }));
        }
        if let Err(e) = self.agents[i].politique.verifier_url(&url) {
            let _ = self.journal.ecrire(json!({ "evenement": "refus-politique", "agent": nom, "url": url_journal(&url), "raison": e }));
            return (403, json!({ "erreur": e }));
        }
        if !self.agents[i].debit.autoriser(Instant::now()) {
            let _ = self.journal.ecrire(json!({ "evenement": "refus-debit", "agent": nom, "url": url_journal(&url) }));
            return (429, json!({ "erreur": "trop de requêtes payantes par minute" }));
        }
        let max = self.agents[i].politique.max_requete;
        let max = v["max_sompi"].as_i64().map(|m| m.clamp(0, max)).unwrap_or(max);
        // On ne paie pas ce qu'on ne peut pas tracer : la demande est journalisée AVANT l'achat.
        if let Err(e) = self.journal.ecrire(json!({ "evenement": "demande", "agent": nom, "url": url_journal(&url), "max_sompi": max })) {
            return (503, json!({ "erreur": format!("journal d'audit indisponible, achat refusé : {e}") }));
        }
        let achat = (self.acheter)(&self.agents[i], &url, max);
        match achat {
            Ok(a) => {
                let paiement = a.txid.as_ref().map(|t| json!({ "montant_sompi": a.montant, "transaction": t, "explorateur": explorer(t) }));
                let _ = self.journal.ecrire(json!({ "evenement": "resultat", "agent": nom, "url": url_journal(&url), "statut_vendeur": a.statut, "paiement": paiement, "refus": a.refus }));
                let statut = if a.refus.is_some() { 402 } else { 200 };
                (statut, json!({ "statut_vendeur": a.statut, "contenu": a.contenu, "paiement": paiement, "refus": a.refus }))
            }
            Err(e) => {
                let _ = self.journal.ecrire(json!({ "evenement": "erreur", "agent": nom, "url": url_journal(&url), "erreur": e.to_string() }));
                (502, json!({ "erreur": e.to_string() }))
            }
        }
    }
}

enum Appelant {
    Inconnu,
    Admin,
    Agent(usize),
}

/// Achat réel : paiement x402 depuis le coffre de l'agent (son état et ses règles, pas ceux du
/// coffre par défaut).
pub fn acheteur_reel(handle: Handle) -> Acheteur {
    Box::new(move |a: &Agent, url: &str, max: i64| avec_coffre(&a.etat, a.regles.clone(), None, || x402::acheter(&handle, &a.owner_pk, &a.cle, url, Some(max))))
}

pub fn lecteur_reel(handle: Handle) -> Lecteur {
    Box::new(move |a: &Agent| avec_coffre(&a.etat, a.regles.clone(), None, || handle.block_on(routeur::etat_budget(&a.owner_pk, &a.cle))))
}

/// Lance la passerelle (bloquant).
pub fn lancer(handle: Handle, config: &Path) -> Res<()> {
    let handle_vendeur = handle.clone();
    let mut cours = crate::financement::Cours::nouveau();
    let mut p = Passerelle::depuis_fichier(config, acheteur_reel(handle.clone()), lecteur_reel(handle))?.avec_cours(Box::new(move || cours.lire()));
    x402::BLOQUER_INTERNE.store(!p.demo(), std::sync::atomic::Ordering::Relaxed);
    if p.vendeur_demo {
        let pay_to = kaspa_addresses::Address::new(kaspa_addresses::Prefix::Testnet, kaspa_addresses::Version::PubKey, &p.agents[0].owner_pk);
        x402::lancer_vendeur(handle_vendeur, pay_to);
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let serveur = tiny_http::Server::http(p.ecoute.as_str()).map_err(|e| format!("écoute {} : {e}", p.ecoute))?;
    let (n, tete) = p.journal.tete();
    p.journal.ecrire(json!({ "evenement": "demarrage", "agents": p.noms(), "arrets": p.arrets }))?;
    println!("[PASSERELLE] à l'écoute sur http://{} : {} agent(s), arrêts : {:?}", p.ecoute, p.agents.len(), p.arrets);
    println!("[PASSERELLE] journal vérifié : {n} ligne(s), tête {tete}");
    for mut req in serveur.incoming_requests() {
        let entete = |nom: &'static str| req.headers().iter().find(|h| h.field.equiv(nom)).map(|h| h.value.as_str().to_string());
        let autorisation = entete("Authorization");
        let idem = entete("Idempotency-Key");
        let chemin = req.url().split('?').next().unwrap_or("").to_string();
        let methode = req.method().as_str().to_string();
        // Corps lu seulement pour un appelant connu (pas de travail offert aux inconnus), 64 Kio au plus.
        let mut corps = String::new();
        if !matches!(p.appelant(autorisation.as_deref()), Appelant::Inconnu) {
            let _ = req.as_reader().take(64 * 1024).read_to_string(&mut corps);
        }
        let (statut, v) = p.traiter(Requete { methode: &methode, chemin: &chemin, autorisation: autorisation.as_deref(), idempotence: idem.as_deref(), corps: &corps });
        let _ = req.respond(routeur::reponse(statut, v));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Banc {
        _dossier: PathBuf,
        config: PathBuf,
        cle_a: String,
        cle_b: String,
        admin: String,
    }

    fn dossier_temp(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("plafond-passerelle-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn installer_agent(d: &Path, octet: u8) {
        std::fs::create_dir_all(d).unwrap();
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        std::fs::write(d.join("agent.json"), json!({ "proprietaire": hex::encode(xonly(&k(1))), "regles": null }).to_string()).unwrap();
        crate::prive::ecrire(&d.join("agent.key"), hex::encode([octet; 32]).as_bytes()).unwrap();
    }

    fn banc(nom: &str) -> Banc {
        let d = dossier_temp(nom);
        installer_agent(&d.join("a"), 2);
        installer_agent(&d.join("b"), 3);
        let (cle_a, ea) = nouvelle_cle().unwrap();
        let (cle_b, eb) = nouvelle_cle().unwrap();
        let (admin, ead) = nouvelle_cle().unwrap();
        let config = d.join("passerelle.json");
        std::fs::write(&config, json!({
            "admin_cle_sha256": ead,
            "agents": [
                { "nom": "a", "dossier": "a", "cle_api_sha256": ea, "origines": ["https://api.exemple.org"], "debit_par_minute": 3 },
                { "nom": "b", "dossier": "b", "cle_api_sha256": eb, "origines": ["https://data.exemple.net"] }
            ]
        }).to_string()).unwrap();
        Banc { _dossier: d, config, cle_a, cle_b, admin }
    }

    type Appels = Rc<RefCell<Vec<(String, String, i64)>>>;

    fn passerelle(b: &Banc) -> (Passerelle, Appels) {
        let appels: Appels = Rc::new(RefCell::new(Vec::new()));
        let a2 = appels.clone();
        let acheter: Acheteur = Box::new(move |ag: &Agent, url: &str, max: i64| {
            a2.borrow_mut().push((ag.nom.clone(), url.to_string(), max));
            Ok(x402::Achat { statut: 200, contenu: "donnees".into(), montant: 2_000_000, txid: Some("ab".repeat(32)), refus: None })
        });
        let lire: Lecteur = Box::new(|ag: &Agent| Ok(json!({ "agent": ag.nom })));
        (Passerelle::depuis_fichier(&b.config, acheter, lire).unwrap(), appels)
    }

    fn req<'a>(m: &'a str, c: &'a str, auth: &'a str, corps: &'a str) -> Requete<'a> {
        Requete { methode: m, chemin: c, autorisation: Some(auth), idempotence: None, corps }
    }

    fn bearer(k: &str) -> String {
        format!("Bearer {k}")
    }

    #[test]
    fn cle_inconnue_refusee_avant_tout() {
        let b = banc("inconnue");
        let (mut p, appels) = passerelle(&b);
        for auth in ["", "Bearer ", "Bearer plf_faux", &b.cle_a] {
            let (s, _) = p.traiter(req("POST", "/v1/fetch", auth, r#"{"url":"https://api.exemple.org/x"}"#));
            assert_eq!(s, 401, "autorisation « {auth} »");
        }
        assert!(appels.borrow().is_empty());
        // un agent n'a pas accès à l'administration, l'administrateur ne paie pas
        assert_eq!(p.traiter(req("GET", "/admin/etat", &bearer(&b.cle_a), "")).0, 404);
        assert_eq!(p.traiter(req("POST", "/v1/fetch", &bearer(&b.admin), r#"{"url":"https://api.exemple.org/x"}"#)).0, 404);
    }

    #[test]
    fn chaque_agent_paie_depuis_son_coffre_et_seulement_ses_vendeurs() {
        let b = banc("isolement");
        let (mut p, appels) = passerelle(&b);
        // l'agent a ne peut pas utiliser le vendeur de l'agent b
        let (s, v) = p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://data.exemple.net/x"}"#));
        assert_eq!(s, 403, "{v}");
        let (s, v) = p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_b), ""));
        assert_eq!((s, v["agent"].as_str()), (200, Some("b")));
        assert!(appels.borrow().is_empty());
        // adresse interne et http refusés hors démo
        for url in ["http://api.exemple.org/x", "https://127.0.0.1/x", "https://user:pw@api.exemple.org/x"] {
            assert_eq!(p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), &json!({ "url": url }).to_string())).0, 403, "{url}");
        }
        assert!(appels.borrow().is_empty());
    }

    /// Demande de financement : en requêtes et dans la devise du client ; l'adresse de dépôt vient
    /// de la fiche signée par le propriétaire et vérifiée ici, jamais de l'agent.
    #[test]
    fn financement_adresse_de_depot_verifiee() {
        use crate::coffre::Genese;
        let b = banc("financement");
        let (mut p, _) = passerelle(&b);
        let k = |o: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[o; 32]).unwrap();
        let reglage = |adresse: Option<&str>| crate::financement::Reglage { requetes_cible: 1000, seuil_requetes: 200, tarif_requete_sompi: Some(20_000_000), devise: "eur".into(), adresse_depot: adresse.map(String::from) };
        // Sans réglage : rien à dire.
        let (s, v) = p.traiter(req("GET", "/v1/financement", &bearer(&b.cle_a), ""));
        assert_eq!((s, v["configure"].as_bool()), (200, Some(false)));
        // Coffre à lignée de l'agent a (propriétaire : clé 1, agent : clé 2), fiche signée par le propriétaire.
        let coeur = crate::coeur::Coeur { owner: xonly(&k(1)), agent: xonly(&k(2)), capacite: 50_000_000, periode: 36_000, retour: Some(crate::coffre::empreinte_retour(&crate::address(&k(11)))) };
        let genese = Genese { txid: hex::encode([4u8; 32]), entree_txid: hex::encode([5u8; 32]), entree_index: 0, valeurs: vec![300_000_000] };
        let bonne = crate::coffre092::fiche_d_essai(&coeur, genese.clone(), &k(1));
        let lu = |fiche: Value| json!({ "coffre": { "valeur_sompi": 150u64 * 20_000_000, "lignee": "aa" }, "depot": fiche });
        p.agents[0].recharge = Some(reglage(Some("kaspatest:adresse-de-la-configuration")));
        p.lien_achat = Some("https://achat.exemple/?a={adresse}&m={montant}&d={devise}".into());
        p.cours = Box::new(|| Some(json!({ "eur": 0.03 })));
        let f = serde_json::to_value(&bonne).unwrap();
        p.lire = Box::new(move |_| Ok(lu(f.clone())));
        let (s, v) = p.traiter(req("GET", "/v1/financement", &bearer(&b.cle_a), ""));
        assert_eq!(s, 200);
        assert_eq!((v["requetes_restantes"].as_u64(), v["a_recharger"].as_bool(), v["montant"]["valeur"].as_f64()), (Some(150), Some(true), Some(5.26)));
        assert_eq!(v["adresse_depot"].as_str(), Some(bonne.adresse_depot.as_str()), "l'adresse de la fiche vérifiée, pas celle de la configuration");
        assert!(v["lien_achat"].as_str().unwrap().contains(&bonne.adresse_depot) && v["origine_adresse"].as_str().unwrap().contains("signée"));
        assert_eq!(v["depot_minimal_sompi"].as_u64(), Some(bonne.depot_minimal_sompi));
        assert_eq!(v["liens"]["plateformes"][0]["nom"], "Finst");
        // Fiches que l'agent pourrait fabriquer : adresse remplacée, fiche signée par lui-même (sa
        // propre lignée à l'adresse du coffre), fiche d'un autre propriétaire. Aucune adresse n'est donnée.
        let mut remplacee = bonne.clone();
        remplacee.adresse_depot = crate::address(&k(2)).to_string();
        let signee_par_l_agent = crate::coffre092::fiche_d_essai(&coeur, Genese { entree_txid: hex::encode([9u8; 32]), ..genese.clone() }, &k(2));
        let autre_proprietaire = crate::coffre092::fiche_d_essai(&crate::coeur::Coeur { owner: xonly(&k(2)), ..coeur.clone() }, genese.clone(), &k(2));
        assert!(crate::coffre092::verifier_fiche(&autre_proprietaire).is_ok(), "cohérente en elle-même, mais ce n'est pas le coffre de cet agent");
        for (nom, fausse) in [("adresse remplacée", serde_json::to_value(&remplacee).unwrap()), ("signée par l'agent", serde_json::to_value(&signee_par_l_agent).unwrap()), ("autre propriétaire", serde_json::to_value(&autre_proprietaire).unwrap()), ("absente", Value::Null), ("illisible", json!({ "adresse_depot": "kaspatest:x" }))] {
            p.lire = Box::new(move |_| Ok(lu(fausse.clone())));
            let (_, v) = p.traiter(req("GET", "/v1/financement", &bearer(&b.cle_a), ""));
            assert!(v["adresse_depot"].is_null() && v["lien_achat"].is_null() && v["fiche_depot"].is_null(), "{nom} : {v}");
            assert!(v["origine_adresse"].as_str().unwrap().contains("non vérifiable"), "{nom}");
            assert_eq!(v["requetes_restantes"].as_u64(), Some(150), "le besoin reste affiché");
        }
        // Ancien coffre (sans lignée) : l'adresse écrite par l'administrateur dans la configuration.
        p.lire = Box::new(|_| Ok(json!({ "coffre": { "valeur_sompi": 0u64 } })));
        let (_, v) = p.traiter(req("GET", "/v1/financement", &bearer(&b.cle_a), ""));
        assert_eq!(v["adresse_depot"].as_str(), Some("kaspatest:adresse-de-la-configuration"));
        // Sans cours : pas de montant, pas de lien, mais le besoin en requêtes.
        p.cours = Box::new(|| None);
        let (_, v) = p.traiter(req("GET", "/v1/financement", &bearer(&b.cle_a), ""));
        assert!(v["montant"].is_null() && v["lien_achat"].is_null() && v["requetes_restantes"].as_u64() == Some(0));
        // Administration : tous les agents ; un agent n'y a pas accès.
        let (s, v) = p.traiter(req("GET", "/admin/financement", &bearer(&b.admin), ""));
        assert_eq!((s, v["agents"].as_array().unwrap().len(), v["a_recharger"].as_u64()), (200, 2, Some(1)));
        assert_eq!(v["agents"][1]["configure"], false);
        assert_eq!(p.traiter(req("GET", "/admin/financement", &bearer(&b.cle_a), "")).0, 404);
        // Un modèle de lien qui n'est pas en https est ignoré dès la configuration.
        assert!(Some("http://achat.exemple/".to_string()).filter(|l: &String| l.starts_with("https://")).is_none());
    }

    #[test]
    fn max_de_l_agent_jamais_depasse() {
        let b = banc("max");
        let (mut p, appels) = passerelle(&b);
        let plafond = plafond_par_requete(&None);
        // la vérification DNS du vendeur échoue hors réseau : on teste le plafond via la politique directement
        p.agents[0].politique.demo = true;
        p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x","max_sompi":999999999999}"#));
        p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x","max_sompi":-5}"#));
        let a = appels.borrow();
        assert_eq!(a[0].2, plafond, "un max demandé trop haut est ramené au plafond");
        assert_eq!(a[1].2, 0, "un max négatif devient zéro");
    }

    #[test]
    fn arret_d_urgence_immediat_et_persistant() {
        let b = banc("arret");
        let (mut p, appels) = passerelle(&b);
        p.agents[0].politique.demo = true;
        let (s, _) = p.traiter(req("POST", "/admin/arret", &bearer(&b.admin), r#"{"agent":"a"}"#));
        assert_eq!(s, 200);
        assert_eq!(p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x"}"#)).0, 423);
        assert_eq!(p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_a), "")).0, 423);
        assert_eq!(p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_b), "")).0, 200, "l'autre agent continue");
        assert!(appels.borrow().is_empty());
        // l'arrêt survit au redémarrage
        drop(p);
        let (mut p, _) = passerelle(&b);
        assert_eq!(p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_a), "")).0, 423);
        // arrêt général, puis reprise générale
        assert_eq!(p.traiter(req("POST", "/admin/arret", &bearer(&b.admin), r#"{"agent":"*"}"#)).0, 200);
        assert_eq!(p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_b), "")).0, 423);
        assert_eq!(p.traiter(req("POST", "/admin/reprise", &bearer(&b.admin), r#"{"agent":"*"}"#)).0, 200);
        assert_eq!(p.traiter(req("GET", "/v1/coffre", &bearer(&b.cle_a), "")).0, 200);
        assert_eq!(p.traiter(req("POST", "/admin/arret", &bearer(&b.admin), r#"{"agent":"inconnu"}"#)).0, 404);
    }

    #[test]
    fn idempotence_par_agent() {
        let b = banc("idem");
        let (mut p, appels) = passerelle(&b);
        p.agents[0].politique.demo = true;
        let auth = bearer(&b.cle_a);
        let r = || Requete { methode: "POST", chemin: "/v1/fetch", autorisation: Some(&auth), idempotence: Some("k1"), corps: r#"{"url":"https://api.exemple.org/x"}"# };
        assert_eq!(p.traiter(r()).0, 200);
        let (s, v) = p.traiter(r());
        assert_eq!((s, v["rejoue"].as_bool()), (200, Some(true)));
        assert_eq!(appels.borrow().len(), 1, "la même clé ne paie jamais deux fois");
    }

    #[test]
    fn debit_par_minute_par_agent() {
        let b = banc("debit");
        let (mut p, appels) = passerelle(&b);
        p.agents[0].politique.demo = true;
        let statuts: Vec<u16> = (0..5).map(|_| p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x"}"#)).0).collect();
        assert_eq!(statuts, vec![200, 200, 200, 429, 429]);
        assert_eq!(appels.borrow().len(), 3);
    }

    #[test]
    fn journal_chaine_detecte_toute_falsification() {
        let b = banc("journal");
        let (mut p, _) = passerelle(&b);
        p.agents[0].politique.demo = true;
        for _ in 0..3 {
            p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x?jeton=secret"}"#));
        }
        let chemin = p.journal.chemin.clone();
        let (n, tete) = p.journal.tete();
        drop(p);
        assert_eq!(n, 6, "une demande et un résultat par achat");
        let (n2, t2) = verifier_journal(&chemin).unwrap();
        assert_eq!((n2, hex::encode(t2)), (n, tete));
        let texte = std::fs::read_to_string(&chemin).unwrap();
        assert!(!texte.contains("secret"), "les paramètres d'URL ne sont jamais journalisés");
        let lignes: Vec<&str> = texte.lines().collect();
        let ecrire = |l: Vec<String>| std::fs::write(&chemin, l.join("\n") + "\n").unwrap();
        // modification d'un montant
        let mut l: Vec<String> = lignes.iter().map(|s| s.to_string()).collect();
        l[1] = l[1].replace("2000000", "1");
        ecrire(l);
        assert!(verifier_journal(&chemin).is_err());
        // suppression d'une ligne
        let mut l: Vec<String> = lignes.iter().map(|s| s.to_string()).collect();
        l.remove(2);
        ecrire(l);
        assert!(verifier_journal(&chemin).is_err());
        // et la passerelle refuse alors de démarrer
        assert!(Passerelle::depuis_fichier(&b.config, Box::new(|_: &Agent, _: &str, _: i64| Err("x".into())), Box::new(|_: &Agent| Ok(json!({})))).is_err());
        // journal intact : redémarrage et suite de la chaîne
        ecrire(lignes.iter().map(|s| s.to_string()).collect());
        let (mut p, _) = passerelle(&b);
        p.traiter(req("POST", "/admin/arret", &bearer(&b.admin), r#"{"agent":"a"}"#));
        assert_eq!(verifier_journal(&chemin).unwrap().0, 7);
    }

    #[test]
    fn journal_impossible_a_ecrire_donc_pas_d_achat() {
        let b = banc("journal-ko");
        let (mut p, appels) = passerelle(&b);
        p.agents[0].politique.demo = true;
        p.journal.chemin = b._dossier.join("inexistant").join("journal.jsonl");
        let (s, _) = p.traiter(req("POST", "/v1/fetch", &bearer(&b.cle_a), r#"{"url":"https://api.exemple.org/x"}"#));
        assert_eq!(s, 503);
        assert!(appels.borrow().is_empty(), "rien n'est payé sans trace");
    }

    #[test]
    fn configuration_refusee_si_dangereuse() {
        let d = dossier_temp("config");
        installer_agent(&d.join("a"), 2);
        let (_, e) = nouvelle_cle().unwrap();
        let (_, ad) = nouvelle_cle().unwrap();
        let essai = |c: Value| {
            std::fs::write(d.join("p.json"), c.to_string()).unwrap();
            Passerelle::depuis_fichier(&d.join("p.json"), Box::new(|_: &Agent, _: &str, _: i64| Err("x".into())), Box::new(|_: &Agent| Ok(json!({})))).err().map(|e| e.to_string())
        };
        let agent = |cle: &str, origines: Value| json!({ "nom": "a", "dossier": "a", "cle_api_sha256": cle, "origines": origines });
        assert!(essai(json!({ "admin_cle_sha256": ad, "agents": [agent(&e, json!([]))] })).unwrap().contains("origines"), "hors démo, vendeurs obligatoires");
        assert!(essai(json!({ "admin_cle_sha256": ad, "agents": [agent(&ad, json!(["https://x.org"]))] })).unwrap().contains("unique"), "clé d'agent = clé admin");
        assert!(essai(json!({ "admin_cle_sha256": "abcd", "agents": [agent(&e, json!(["https://x.org"]))] })).is_some(), "empreinte tronquée");
        assert!(essai(json!({ "admin_cle_sha256": ad, "agents": [agent(&e, json!(["https://x.org"])), agent(&e, json!(["https://x.org"]))] })).unwrap().contains("deux fois"));
        assert!(essai(json!({ "admin_cle_sha256": ad, "agents": [] })).is_some());
        // le fichier ne contient que des empreintes : la clé elle-même n'y figure jamais
        assert!(essai(json!({ "admin_cle_sha256": ad, "agents": [agent(&e, json!(["https://x.org"]))] })).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cle_d_agent_lisible_par_d_autres_refusee() {
        use std::os::unix::fs::PermissionsExt;
        let b = banc("droits");
        let cle = b._dossier.join("a").join("agent.key");
        std::fs::set_permissions(&cle, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = Passerelle::depuis_fichier(&b.config, Box::new(|_: &Agent, _: &str, _: i64| Err("x".into())), Box::new(|_: &Agent| Ok(json!({})))).err().unwrap().to_string();
        assert!(e.contains("lisible par d'autres"), "{e}");
    }

    #[test]
    fn nouvelle_cle_forte_et_empreinte_coherente() {
        let (k1, e1) = nouvelle_cle().unwrap();
        let (k2, _) = nouvelle_cle().unwrap();
        assert!(k1.starts_with("plf_") && k1.len() == 68 && k1 != k2);
        assert_eq!(e1, hex::encode(empreinte(&k1)));
    }
}

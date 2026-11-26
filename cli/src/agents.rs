//! Registre des agents du propriétaire : un agent = un coffre (même contrat AgentBudget v0.5.1,
//! une instance par agent), avec son propre fichier d'état. Le premier agent (« principal »)
//! reprend le coffre historique et la clé d'agent fournie par l'environnement ; les suivants
//! reçoivent une clé tirée au hasard, écrite à part pour être remise à l'agent : fichier lisible par
//! le seul utilisateur, et chiffré par une clé dérivée de la clé privée du propriétaire dès que le
//! compte en a une protégée par mot de passe (`cle::Enveloppe`, format v2) : restaurer le compte depuis
//! la phrase de 24 mots garde donc ces clés lisibles. Le registre ne contient aucun secret.

use crate::Res;
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const PRINCIPAL: &str = "principal";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Agent {
    pub id: String,
    pub nom: String,
    /// Règles du coffre de cet agent ; absentes pour le principal (règles standard historiques).
    #[serde(default)]
    pub regles: Option<crate::Regles>,
    /// Fichier d'état du coffre de cet agent.
    pub etat: String,
    /// "env" (clé d'agent fournie par l'environnement) ou chemin d'un fichier de clé d'agent ;
    /// après connexion, le fichier est effacé et la console ne garde que la clé publique.
    pub cle: String,
    pub cree_le: u64,
    /// Clé publique de l'agent (33 octets, hexadécimal).
    #[serde(default)]
    pub publique: Option<String>,
    /// Date de connexion : la clé privée a été remise à l'agent et effacée de la console.
    #[serde(default)]
    pub connecte_le: Option<u64>,
    /// Échéance du mandat (secondes Unix) : la console le révoque automatiquement à cette date.
    /// Confort, pas garantie : la garantie est le capital alloué (spec/moteur-de-risque.md).
    #[serde(default)]
    pub echeance: Option<u64>,
    /// Adresse de retour du coffre (gel, retrait) choisie à la création ; absente : la trésorerie.
    #[serde(default)]
    pub retour: Option<String>,
}

/// Agent principal du compte, vu de la console. Elle n'a besoin que de sa clé publique (surveiller,
/// alimenter, geler sont des opérations du propriétaire) : si la clé privée gardée sur le disque n'est
/// pas lisible (ancien format chiffré sous un mot de passe oublié, ou autre propriétaire), la clé
/// publique l'est toujours.
#[derive(Clone, Copy)]
pub struct Principal {
    pub cle: Keypair,
    pub publique: secp256k1::PublicKey,
}

impl From<Keypair> for Principal {
    fn from(cle: Keypair) -> Self {
        Principal { publique: cle.public_key(), cle }
    }
}

impl Principal {
    /// Clé publique seule : la clé privée n'est pas lisible dans cette session.
    pub fn publique_seule(publique: secp256k1::PublicKey) -> Self {
        Principal { cle: cle_muette(), publique }
    }
}

fn dossier(etat_defaut: &str) -> PathBuf {
    Path::new(etat_defaut).parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

/// Événements visibles en direct dans la console (paiement, refus, arrêt), écrits par la console,
/// la démo ou le routeur dans le dossier du registre. Journal borné (sobriété).
pub fn noter(etat_defaut: &str, agent: &str, genre: &str, sompi: Option<i64>) {
    use std::io::Write;
    let chemin = dossier(etat_defaut).join("evenements.jsonl");
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let ligne = serde_json::json!({ "instant_ms": t, "agent": agent, "genre": genre, "sompi": sompi });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&chemin) {
        let _ = writeln!(f, "{ligne}");
    }
    crate::sobriete::borner(&chemin.to_string_lossy(), crate::sobriete::JOURNAL_MAX);
}

/// Fixe l'échéance d'un mandat (révocation automatique par la console).
/// Adresse de retour du mandat, fixée avant l'ouverture de son coffre (elle entre dans son adresse).
pub fn fixer_retour(etat_defaut: &str, id: &str, retour: Option<String>) -> Res<()> {
    let mut agents = charger(etat_defaut);
    let a = agents.iter_mut().find(|a| a.id == id).ok_or("mandat inconnu")?;
    a.retour = retour;
    enregistrer(etat_defaut, &agents)
}

pub fn fixer_echeance(etat_defaut: &str, id: &str, echeance: Option<u64>) -> Res<()> {
    let mut agents = charger(etat_defaut);
    let a = agents.iter_mut().find(|a| a.id == id).ok_or("mandat inconnu")?;
    a.echeance = echeance;
    enregistrer(etat_defaut, &agents)
}

/// Les `n` derniers événements, du plus ancien au plus récent.
pub fn evenements(etat_defaut: &str, n: usize) -> Vec<serde_json::Value> {
    let texte = std::fs::read_to_string(dossier(etat_defaut).join("evenements.jsonl")).unwrap_or_default();
    let lignes: Vec<&str> = texte.lines().collect();
    lignes[lignes.len().saturating_sub(n)..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

fn chemin_registre(etat_defaut: &str) -> PathBuf {
    dossier(etat_defaut).join("agents.json")
}

pub fn charger(etat_defaut: &str) -> Vec<Agent> {
    let lu: Option<Vec<Agent>> = std::fs::read_to_string(chemin_registre(etat_defaut)).ok().and_then(|t| serde_json::from_str(&t).ok());
    match lu {
        Some(v) if !v.is_empty() => v,
        _ => vec![Agent { id: PRINCIPAL.into(), nom: "Agent principal".into(), regles: None, etat: etat_defaut.into(), cle: "env".into(), cree_le: 0, publique: None, connecte_le: None, echeance: None, retour: None }],
    }
}

fn enregistrer(etat_defaut: &str, agents: &[Agent]) -> Res<()> {
    let p = chemin_registre(etat_defaut);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("json.nouveau");
    std::fs::write(&tmp, serde_json::to_string_pretty(agents)?)?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

/// Nom affichable : 1 à 40 caractères, sans caractère de contrôle.
pub fn nom_valide(nom: &str) -> Option<String> {
    let n = nom.trim();
    (!n.is_empty() && n.chars().count() <= 40 && !n.chars().any(char::is_control)).then(|| n.to_string())
}

/// Inscrit un nouvel agent : clé tirée au hasard, écrite sans écrasement possible dans un fichier
/// lisible par le seul utilisateur, chiffrée si une enveloppe est fournie (compte à mot de passe).
pub fn nouveau(etat_defaut: &str, nom: &str, regles: Option<crate::Regles>, enveloppe: Option<&crate::cle::Enveloppe>) -> Res<Agent> {
    let nom = nom_valide(nom).ok_or("nom d'agent invalide (1 à 40 caractères)")?;
    let mut agents = charger(etat_defaut);
    if agents.len() >= 50 {
        return Err("50 agents au plus".into());
    }
    let mut alea = [0u8; 6];
    getrandom::getrandom(&mut alea).map_err(|e| format!("aléa : {e}"))?;
    let id = format!("ag-{}", hex::encode(alea));
    let racine = dossier(etat_defaut).join("agents");
    std::fs::create_dir_all(racine.join(&id))?;
    let cle = crate::cle::nouvelle()?;
    let chemin_cle = racine.join(format!("{id}.key"));
    ecrire_cle(&chemin_cle, &cle, enveloppe)?;
    let a = Agent {
        id: id.clone(),
        nom,
        regles,
        etat: racine.join(&id).join("etat-coffre.json").to_string_lossy().into_owned(),
        cle: chemin_cle.to_string_lossy().into_owned(),
        cree_le: crate::double_auth::maintenant(),
        publique: Some(hex::encode(cle.public_key().serialize())),
        connecte_le: None,
        echeance: None,
        retour: None,
    };
    agents.push(a.clone());
    enregistrer(etat_defaut, &agents)?;
    Ok(a)
}

pub fn renommer(etat_defaut: &str, id: &str, nom: &str) -> Res<()> {
    let nom = nom_valide(nom).ok_or("nom d'agent invalide (1 à 40 caractères)")?;
    let mut agents = charger(etat_defaut);
    let a = agents.iter_mut().find(|a| a.id == id).ok_or("agent inconnu")?;
    a.nom = nom;
    enregistrer(etat_defaut, &agents)
}

/// Clé d'agent telle que la console la garde sur son disque.
pub enum CleStockee {
    /// Ancien format, ou compte sans mot de passe (clés de test) : hexadécimal en clair.
    Claire(Keypair),
    /// Chiffrée : format v2 (clé du propriétaire, `cle::Enveloppe`) ou ancien format v1 (mot de passe).
    Chiffree(crate::cle::Fichier),
}

/// Fichier chiffré VÉRIFIÉ, prêt à prendre la place du fichier de clé (voir `migrer_fichier`).
fn chemin_chiffre(chemin: &str) -> String {
    format!("{chemin}.chiffre")
}

/// Fichier chiffré tout juste écrit, pas encore relu : jamais utilisé pour remplacer une clé.
fn chemin_essai(chemin: &str) -> String {
    format!("{chemin}.essai")
}

/// Termine une migration interrompue : le fichier chiffré était complet et vérifié (écrit,
/// synchronisé et relu avant tout effacement de l'original), il prend la place du fichier de clé.
/// Un fichier chiffré incomplet est jeté.
fn reprendre(chemin: &str) {
    let tmp = chemin_chiffre(chemin);
    if !Path::new(&tmp).exists() {
        return;
    }
    let complet = std::fs::read_to_string(&tmp).ok().and_then(|t| serde_json::from_str::<crate::cle::Fichier>(&t).ok()).is_some();
    if complet {
        if Path::new(chemin).exists() {
            let _ = crate::connexion::effacer_fichier(chemin);
        }
        let _ = std::fs::rename(&tmp, chemin);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Lit le fichier de clé d'un agent : absent, en clair (à chiffrer) ou chiffré.
pub fn lire_cle_stockee(chemin: &str) -> Res<Option<CleStockee>> {
    reprendre(chemin);
    if !Path::new(chemin).exists() {
        return Ok(None);
    }
    let texte = zeroize::Zeroizing::new(std::fs::read_to_string(chemin)?);
    if texte.trim_start().starts_with('{') {
        return Ok(Some(CleStockee::Chiffree(serde_json::from_str(&texte).map_err(|_| "fichier de clé d'agent illisible")?)));
    }
    let octets = zeroize::Zeroizing::new(hex::decode(texte.trim())?);
    Ok(Some(CleStockee::Claire(Keypair::from_seckey_slice(secp256k1::SECP256K1, &octets)?)))
}

/// Écrit la clé d'un agent dans un fichier neuf, lisible par le seul utilisateur : chiffrée si une
/// enveloppe est fournie, sinon en clair (clés de test, sans mot de passe).
pub fn ecrire_cle(chemin: &Path, k: &Keypair, enveloppe: Option<&crate::cle::Enveloppe>) -> Res<()> {
    match enveloppe {
        Some(e) => crate::prive::ecrire(chemin, serde_json::to_string_pretty(&e.chiffrer(k)?)?.as_bytes()),
        None => crate::prive::ecrire(chemin, zeroize::Zeroizing::new(hex::encode(k.secret_bytes())).as_bytes()),
    }
}

/// Migration d'un fichier de clé vers le format v2 (chiffré par la clé du propriétaire) :
///  - clé en clair : toujours migrée ;
///  - ancien format v1 (mot de passe) : migré si le mot de passe est fourni et l'ouvre ;
///  - déjà en v2, ou absent : rien à faire.
/// La clé est chiffrée dans un fichier voisin, relue et déchiffrée pour vérification ; alors seulement
/// l'original est effacé (réécrit puis supprimé) et remplacé. Une interruption ne perd jamais la clé :
/// avant la vérification l'original est intact, après elle `reprendre` termine le remplacement.
/// `v1` garde la dernière dérivation Argon2id (les fichiers d'une même session partagent leur sel).
/// Rend vrai si le fichier a été migré, faux s'il n'y avait rien à faire.
pub fn migrer_fichier(chemin: &str, enveloppe: &crate::cle::Enveloppe, mot_de_passe: Option<&str>, v1: &mut Option<crate::cle::EnveloppeMdp>) -> Res<bool> {
    let k = match lire_cle_stockee(chemin)? {
        Some(CleStockee::Claire(k)) => k,
        Some(CleStockee::Chiffree(f)) if crate::cle::est_cle_agent_v1(&f) => {
            let Some(mdp) = mot_de_passe else { return Ok(false) };
            let ancienne = match v1.take().filter(|e| e.convient(&f)) {
                Some(e) => e,
                None => crate::cle::EnveloppeMdp::du_fichier(&f, mdp)?,
            };
            let k = ancienne.dechiffrer(&f);
            *v1 = Some(ancienne);
            k?
        }
        _ => return Ok(false),
    };
    let (essai, verifie) = (chemin_essai(chemin), chemin_chiffre(chemin));
    let _ = std::fs::remove_file(&essai);
    let _ = std::fs::remove_file(&verifie);
    ecrire_cle(Path::new(&essai), &k, Some(enveloppe))?;
    let relu = std::fs::read_to_string(&essai).ok().and_then(|t| serde_json::from_str::<crate::cle::Fichier>(&t).ok()).and_then(|f| enveloppe.dechiffrer(&f).ok());
    if !relu.is_some_and(|r| r.secret_bytes() == k.secret_bytes()) {
        let _ = std::fs::remove_file(&essai);
        return Err("chiffrement de la clé d'agent non vérifié : fichier d'origine conservé".into());
    }
    std::fs::rename(&essai, &verifie)?;
    crate::connexion::effacer_fichier(chemin)?;
    std::fs::rename(&verifie, chemin)?;
    Ok(true)
}

/// Migre vers le format v2 toutes les clés d'agent du registre encore en clair (agents créés avant le
/// chiffrement) et, si le mot de passe est fourni, celles de l'ancien format v1. Rend le nombre de
/// clés migrées et le nombre de fichiers v1 restants (mot de passe absent, ou chiffrés sous un ancien
/// mot de passe) ; une clé qui résiste n'empêche pas les autres.
pub fn migrer_cles(etat_defaut: &str, enveloppe: &crate::cle::Enveloppe, mot_de_passe: Option<&str>) -> (usize, usize) {
    let (mut migrees, mut restantes, mut v1) = (0, 0, None);
    for a in charger(etat_defaut).iter().filter(|a| a.cle != "env" && !est_connecte(a)) {
        if migrer_fichier(&a.cle, enveloppe, mot_de_passe, &mut v1).unwrap_or(false) {
            migrees += 1;
        } else if matches!(lire_cle_stockee(&a.cle), Ok(Some(CleStockee::Chiffree(f))) if crate::cle::est_cle_agent_v1(&f)) {
            restantes += 1;
        }
    }
    (migrees, restantes)
}

/// Clé privée d'un agent pas encore connecté, pour préparer son kit de connexion. Une clé chiffrée
/// demande l'enveloppe de la session (format v2) ou le mot de passe du propriétaire (ancien format v1).
pub fn cle_privee(a: &Agent, mot_de_passe: Option<&str>, enveloppe: Option<&crate::cle::Enveloppe>) -> Res<Keypair> {
    match lire_cle_stockee(&a.cle)?.ok_or("clé de l'agent introuvable sur cet ordinateur")? {
        CleStockee::Claire(k) => Ok(k),
        CleStockee::Chiffree(f) => crate::cle::ouvrir_cle_agent(&f, mot_de_passe, enveloppe).map_err(|_| {
            if crate::cle::est_cle_agent_v1(&f) {
                "la clé de cet agent est à l'ancien format, chiffrée avec un autre mot de passe que l'actuel (compte restauré depuis la phrase avant la mise à jour ?) : elle ne peut plus être remise. Arrêtez ce mandat (les fonds reviennent en trésorerie) et créez-en un nouveau".into()
            } else {
                "la clé de cet agent ne s'ouvre pas avec la clé de ce compte (fichier d'un autre compte, ou modifié) : elle ne peut pas être remise. Arrêtez ce mandat (les fonds reviennent en trésorerie) et créez-en un nouveau".into()
            }
        }),
    }
}

/// Emplacement de référence des fichiers de l'agent (clé, secrets) ; le principal n'a pas de
/// fichier de clé (clé fournie par l'environnement) mais a son propre coffre de secrets.
pub fn base_fichiers(a: &Agent, etat_defaut: &str) -> String {
    if a.cle != "env" {
        return a.cle.clone();
    }
    let d = dossier(etat_defaut).join("agents");
    let _ = std::fs::create_dir_all(&d);
    d.join(format!("{PRINCIPAL}.key")).to_string_lossy().into_owned()
}

/// Clé publique de l'agent (toujours connue de la console, même après connexion).
pub fn publique(a: &Agent, principal: &Principal) -> Res<secp256k1::PublicKey> {
    if a.cle == "env" {
        return Ok(principal.publique);
    }
    if let Some(h) = &a.publique {
        return Ok(secp256k1::PublicKey::from_slice(&hex::decode(h)?)?);
    }
    // registre ancien, sans clé publique : elle se lit dans le fichier de clé (en clair même s'il est chiffré)
    match lire_cle_stockee(&a.cle)?.ok_or("clé de l'agent introuvable")? {
        CleStockee::Claire(k) => Ok(k.public_key()),
        CleStockee::Chiffree(f) => Ok(secp256k1::PublicKey::from_slice(&hex::decode(&f.publique)?)?),
    }
}

/// Clé publique x-only (celle inscrite dans le contrat du coffre).
pub fn xonly_pub(a: &Agent, principal: &Principal) -> Option<[u8; 32]> {
    publique(a, principal).ok().map(|p| p.x_only_public_key().0.serialize())
}

pub fn est_connecte(a: &Agent) -> bool {
    a.connecte_le.is_some()
}

/// Après connexion, la console n'a plus la clé privée de l'agent. Les opérations du propriétaire
/// (surveiller, alimenter, geler) n'utilisent que la clé publique, transmise au contrat par
/// `avec_coffre` ; cette clé muette ne sert qu'à garder les signatures des fonctions et ne peut rien
/// signer de valide pour ce coffre.
fn cle_muette() -> Keypair {
    Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x42; 32]).expect("clé muette valide")
}

pub fn marquer_connecte(etat_defaut: &str, id: &str) -> Res<()> {
    let mut agents = charger(etat_defaut);
    let a = agents.iter_mut().find(|a| a.id == id).ok_or("agent inconnu")?;
    a.connecte_le = Some(crate::double_auth::maintenant());
    enregistrer(etat_defaut, &agents)
}

/// Clé de l'agent pour les opérations du propriétaire : celle du principal, sinon son fichier s'il
/// est en clair. Une clé chiffrée n'est pas ouverte ici : comme pour un agent connecté, ces opérations
/// n'utilisent que la clé publique (transmise au contrat par `avec_coffre`), et la clé muette suffit.
/// Seule la préparation du kit de connexion ouvre la clé (`cle_privee`, mot de passe exigé par la console).
pub fn cle(a: &Agent, principal: &Principal) -> Res<Keypair> {
    if a.cle == "env" {
        return Ok(principal.cle);
    }
    if est_connecte(a) {
        return Ok(cle_muette());
    }
    match lire_cle_stockee(&a.cle)?.ok_or("clé de l'agent introuvable sur cet ordinateur")? {
        CleStockee::Claire(k) => Ok(k),
        CleStockee::Chiffree(_) => Ok(cle_muette()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JOUR_DAA, Regles};

    #[test]
    fn evenements_du_direct_dans_l_ordre_et_bornes() {
        let d = std::env::temp_dir().join(format!("plafond-direct-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let etat = d.join("etat-coffre.json").to_string_lossy().into_owned();
        noter(&etat, "Agent démo", "paiement", Some(30_000_000));
        noter(&etat, "Agent démo", "bloque", None);
        noter(&etat, "Agent démo", "arret", None);
        let e = evenements(&etat, 2);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0]["genre"].as_str(), e[1]["genre"].as_str()), (Some("bloque"), Some("arret")));
        assert_eq!(evenements(&etat, 10)[0]["sompi"], 30_000_000);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn regles_calculees_depuis_les_trois_reglages() {
        let req = 40_000_000; // une requête de référence
        // Exemple de référence : 100 requêtes par jour, 5 au plus par achat.
        let r = Regles::calculer(100 * req, JOUR_DAA, 5 * req).unwrap();
        assert_eq!(r.capacite, 5 * req, "exposition immédiate = plafond");
        assert!(r.maximum_sur(JOUR_DAA) <= 100 * req, "jamais plus que le budget sur la période");
        assert!(r.maximum_sur(JOUR_DAA) >= 95 * req, "et presque tout le budget est utilisable");
        for periode in [36_000, JOUR_DAA, 7 * JOUR_DAA, 30 * JOUR_DAA] {
            for (n, p) in [(1i64, 1i64), (2, 1), (7, 3), (100, 5), (1_000, 1_000), (1_000_000, 50), (1_000_000, 500_000)] {
                let (b, pl) = (n * req, (p * req).min(n * req / 2));
                match Regles::calculer(b, periode, pl) {
                    Ok(r) => {
                        assert!(r.maximum_sur(periode) <= b, "borne {n}/{p}");
                        assert!(r.capacite >= pl && r.capacite <= i64::MAX / r.recharge_daa && r.plafond <= r.capacite);
                    }
                    // seule limite : la garde arithmétique du contrat (capacité × recharge sans débordement)
                    Err(_) => assert!(pl > i64::MAX / periode, "refus injustifié {n}/{p} sur {periode}"),
                }
            }
        }
        assert!(Regles::calculer(10 * req, JOUR_DAA, 6 * req).is_err(), "plafond > moitié du budget");
        assert!(Regles::calculer(10 * req, 12_345, req).is_err(), "période inconnue");
        assert_eq!(Regles::standard().capacite, Regles::standard().plafond, "cœur v0.6 : la capacité est le plafond par achat");
        assert!(Regles::standard().maximum_sur(Regles::standard().periode_daa) <= Regles::standard().budget);
    }

    #[test]
    fn registre_principal_puis_nouveaux_agents() {
        let d = std::env::temp_dir().join(format!("agents-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let defaut = d.join("etat-coffre.json").to_string_lossy().into_owned();
        let v = charger(&defaut);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, PRINCIPAL);
        assert_eq!(v[0].etat, defaut, "le principal reprend le coffre historique");
        let a = nouveau(&defaut, "  Achats API  ", None, None).unwrap();
        let b = nouveau(&defaut, "Veille", Some(crate::Regles::calculer(4_000_000_000, crate::JOUR_DAA, 200_000_000).unwrap()), None).unwrap();
        let v = charger(&defaut);
        assert_eq!(v.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>(), ["Agent principal", "Achats API", "Veille"]);
        assert_ne!(a.etat, b.etat, "un fichier d'état par coffre");
        let p = Principal::from(Keypair::from_seckey_slice(secp256k1::SECP256K1, &[1; 32]).unwrap());
        assert_ne!(cle(&a, &p).unwrap().secret_bytes(), cle(&b, &p).unwrap().secret_bytes());
        assert_eq!(cle(&v[0], &p).unwrap().secret_bytes(), p.cle.secret_bytes());
        assert!(crate::prive::est_prive(Path::new(&a.cle)).unwrap(), "{}", crate::prive::droits(Path::new(&a.cle)));
        assert!(!std::fs::read_to_string(chemin_registre(&defaut)).unwrap().contains(&hex::encode(cle(&a, &p).unwrap().secret_bytes())), "aucun secret dans le registre");
        assert!(nouveau(&defaut, "", None, None).is_err());
        assert!(nouveau(&defaut, &"x".repeat(41), None, None).is_err());
        assert_eq!(charger(&defaut)[2].regles, b.regles, "règles conservées dans le registre");
        assert_eq!(publique(&a, &p).unwrap(), cle(&a, &p).unwrap().public_key());
        marquer_connecte(&defaut, &a.id).unwrap();
        let a2 = charger(&defaut).into_iter().find(|x| x.id == a.id).unwrap();
        assert!(est_connecte(&a2));
        assert_ne!(cle(&a2, &p).unwrap().public_key(), publique(&a2, &p).unwrap(), "plus de clé privée réelle après connexion");
        assert_eq!(xonly_pub(&a2, &p), xonly_pub(&a, &p), "la clé publique reste connue");
        // le contrat du coffre reste identique : la console travaille avec la clé publique seule
        let avant = crate::VaultParams::pour(&[7; 32], &cle(&a, &p).unwrap(), 0, 0).agent;
        let apres = crate::avec_coffre("/tmp/inexistant.json", None, xonly_pub(&a2, &p), || crate::VaultParams::pour(&[7; 32], &cle(&a2, &p).unwrap(), 0, 0).agent);
        assert_eq!(avant, apres);
        renommer(&defaut, &a.id, "Achats").unwrap();
        assert_eq!(charger(&defaut)[1].nom, "Achats");
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn dossier_test(nom: &str) -> (PathBuf, String) {
        let d = std::env::temp_dir().join(format!("agents-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let defaut = d.join("etat-coffre.json").to_string_lossy().into_owned();
        (d, defaut)
    }

    fn sur_disque(a: &Agent) -> crate::cle::Fichier {
        match lire_cle_stockee(&a.cle).unwrap().unwrap() {
            CleStockee::Chiffree(f) => f,
            CleStockee::Claire(_) => panic!("clé de {} en clair", a.nom),
        }
    }

    /// Migration vers le format v2 : une clé en clair et une clé v1 (mot de passe) gardent la même
    /// clé privée, l'original disparaît, rien d'intermédiaire ne reste, le fichier reste privé.
    #[test]
    fn migration_clair_et_v1_vers_v2_conserve_la_cle() {
        let (d, defaut) = dossier_test("migration");
        let mdp = "un mot de passe long";
        let proprio = crate::cle::nouvelle().unwrap();
        let env = crate::cle::Enveloppe::du_proprietaire(&proprio);
        let ancienne = crate::cle::EnveloppeMdp::avec_cout(mdp, 19 * 1024, 2, 1).unwrap();
        // trois mandats d'une version précédente : en clair, v1 (deux fichiers de la même session)
        let clair = nouveau(&defaut, "En clair", None, None).unwrap();
        let (v1a, v1b) = (nouveau(&defaut, "Ancien A", None, None).unwrap(), nouveau(&defaut, "Ancien B", None, None).unwrap());
        let p = Principal::from(proprio);
        let attendues: Vec<[u8; 32]> = [&clair, &v1a, &v1b].iter().map(|a| cle(a, &p).unwrap().secret_bytes()).collect();
        for a in [&v1a, &v1b] {
            let k = cle(a, &p).unwrap();
            std::fs::remove_file(&a.cle).unwrap();
            crate::prive::ecrire(Path::new(&a.cle), serde_json::to_string_pretty(&ancienne.chiffrer(&k).unwrap()).unwrap().as_bytes()).unwrap();
        }
        // un mandat déjà en v2 : intact
        let neuf = nouveau(&defaut, "Neuf", None, Some(&env)).unwrap();
        let avant = std::fs::read_to_string(&neuf.cle).unwrap();
        // sans mot de passe : le clair est migré, les v1 attendent
        assert_eq!(migrer_cles(&defaut, &env, None), (1, 2));
        assert_eq!(cle_privee(&v1a, Some(mdp), Some(&env)).unwrap().secret_bytes(), attendues[1], "v1 toujours lisible avec le mot de passe");
        assert!(cle_privee(&v1a, None, Some(&env)).is_err());
        // mauvais mot de passe : rien ne bouge, rien n'est perdu
        assert_eq!(migrer_cles(&defaut, &env, Some("un autre mot de passe")), (0, 2));
        assert!(crate::cle::est_cle_agent_v1(&sur_disque(&v1a)));
        // bon mot de passe : tout est en v2, mêmes clés, ouvertes par la seule clé du propriétaire
        assert_eq!(migrer_cles(&defaut, &env, Some(mdp)), (2, 0));
        assert_eq!(migrer_cles(&defaut, &env, Some(mdp)), (0, 0), "migration idempotente");
        for (a, attendue) in [&clair, &v1a, &v1b].iter().zip(&attendues) {
            let f = sur_disque(a);
            assert!(f.version == 2 && f.kdf == crate::cle::KDF_PROPRIETAIRE, "{} pas en v2", a.nom);
            assert_eq!(&cle_privee(a, None, Some(&env)).unwrap().secret_bytes(), attendue, "clé de {} changée par la migration", a.nom);
            assert!(!std::fs::read_to_string(&a.cle).unwrap().contains(&hex::encode(attendue)));
            assert!(!Path::new(&chemin_chiffre(&a.cle)).exists() && !Path::new(&chemin_essai(&a.cle)).exists(), "fichier intermédiaire laissé");
            assert!(crate::prive::est_prive(Path::new(&a.cle)).unwrap());
        }
        assert_eq!(std::fs::read_to_string(&neuf.cle).unwrap(), avant, "fichier v2 réécrit sans raison");
        // un autre propriétaire n'ouvre rien : message clair
        let autre = crate::cle::Enveloppe::du_proprietaire(&crate::cle::nouvelle().unwrap());
        assert!(cle_privee(&clair, Some(mdp), Some(&autre)).unwrap_err().to_string().contains("autre compte"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Migration interrompue : à aucun moment la clé n'est perdue. Avant la vérification, l'original
    /// fait foi (un fichier d'essai, même abîmé, est ignoré) ; après, le fichier vérifié le remplace.
    #[test]
    fn migration_interrompue_ne_perd_pas_la_cle() {
        let (d, defaut) = dossier_test("interrompue");
        let mdp = "un mot de passe long";
        let env = crate::cle::Enveloppe::du_proprietaire(&crate::cle::nouvelle().unwrap());
        let ancienne = crate::cle::EnveloppeMdp::avec_cout(mdp, 19 * 1024, 2, 1).unwrap();
        let a = nouveau(&defaut, "Ancien", None, None).unwrap();
        let k = cle_privee(&a, None, None).unwrap();
        let v1 = serde_json::to_string_pretty(&ancienne.chiffrer(&k).unwrap()).unwrap();
        std::fs::remove_file(&a.cle).unwrap();
        crate::prive::ecrire(Path::new(&a.cle), v1.as_bytes()).unwrap();
        // 1. arrêt pendant l'écriture du fichier d'essai (tronqué) : l'original v1 reste, puis migre
        std::fs::write(chemin_essai(&a.cle), "{ \"version\": 2, \"kdf\": \"cle-propr").unwrap();
        assert_eq!(cle_privee(&a, Some(mdp), Some(&env)).unwrap().secret_bytes(), k.secret_bytes());
        assert_eq!(std::fs::read_to_string(&a.cle).unwrap(), v1, "original touché par un essai non vérifié");
        assert!(migrer_fichier(&a.cle, &env, Some(mdp), &mut None).unwrap());
        assert_eq!(cle_privee(&a, None, Some(&env)).unwrap().secret_bytes(), k.secret_bytes());
        // 2. arrêt après la vérification, avant l'effacement de l'original : la lecture suivante termine
        std::fs::rename(&a.cle, chemin_chiffre(&a.cle)).unwrap();
        crate::prive::ecrire(Path::new(&a.cle), v1.as_bytes()).unwrap();
        assert_eq!(sur_disque(&a).version, 2);
        assert!(!Path::new(&chemin_chiffre(&a.cle)).exists());
        // 3. arrêt après l'effacement de l'original, avant le renommage : idem
        std::fs::rename(&a.cle, chemin_chiffre(&a.cle)).unwrap();
        assert_eq!(cle_privee(&a, None, Some(&env)).unwrap().secret_bytes(), k.secret_bytes());
        assert!(Path::new(&a.cle).exists() && !Path::new(&chemin_chiffre(&a.cle)).exists());
        // 4. fichier « vérifié » abîmé (ne devrait pas arriver) : jeté, l'original reste
        std::fs::write(chemin_chiffre(&a.cle), "{ tronqué").unwrap();
        assert_eq!(cle_privee(&a, None, Some(&env)).unwrap().secret_bytes(), k.secret_bytes());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Mot de passe oublié : compte restauré depuis les 24 mots avec un nouveau mot de passe. Les
    /// clés d'agent v2 s'ouvrent (même clé de propriétaire) ; une clé v1 de l'ancien mot de passe
    /// reste illisible, avec un message clair, et son fichier n'est ni migré ni abîmé.
    #[test]
    fn restauration_nouveau_mot_de_passe_les_cles_v2_restent_lisibles() {
        let (d, defaut) = dossier_test("restauration");
        let (ancien_mdp, nouveau_mdp) = ("l'ancien mot de passe", "le nouveau mot de passe");
        let coffret = crate::cle::nouveau_coffret().unwrap();
        let env = crate::cle::Enveloppe::du_proprietaire(&crate::cle::cle_du_coffret(&coffret).unwrap());
        let a = nouveau(&defaut, "Recherche", None, Some(&env)).unwrap();
        let attendue = cle_privee(&a, None, Some(&env)).unwrap().secret_bytes();
        let b = nouveau(&defaut, "Ancien", None, None).unwrap();
        let v1 = serde_json::to_string_pretty(&crate::cle::EnveloppeMdp::avec_cout(ancien_mdp, 19 * 1024, 2, 1).unwrap().chiffrer(&cle_privee(&b, None, None).unwrap()).unwrap()).unwrap();
        std::fs::remove_file(&b.cle).unwrap();
        crate::prive::ecrire(Path::new(&b.cle), v1.as_bytes()).unwrap();
        drop(env);
        // restauration : seuls les 24 mots et le nouveau mot de passe sont connus
        let phrase = crate::cle::phrase(&coffret).unwrap();
        let restaure = crate::cle::Enveloppe::du_proprietaire(&crate::cle::cle_du_coffret(&crate::cle::depuis_phrase(&phrase).unwrap()).unwrap());
        assert_eq!(migrer_cles(&defaut, &restaure, Some(nouveau_mdp)), (0, 1));
        assert_eq!(cle_privee(&a, Some(nouveau_mdp), Some(&restaure)).unwrap().secret_bytes(), attendue, "clé v2 illisible après restauration");
        let e = cle_privee(&b, Some(nouveau_mdp), Some(&restaure)).unwrap_err().to_string();
        assert!(e.contains("ancien format") && e.contains("Arrêtez ce mandat"), "{e}");
        assert_eq!(std::fs::read_to_string(&b.cle).unwrap(), v1, "fichier v1 illisible : laissé tel quel");
        std::fs::remove_dir_all(&d).unwrap();
    }
}

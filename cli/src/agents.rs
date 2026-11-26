//! Registre des agents du propriétaire : un agent = un coffre (même contrat AgentBudget v0.5.1,
//! une instance par agent), avec son propre fichier d'état. Le premier agent (« principal »)
//! reprend le coffre historique et la clé d'agent fournie par l'environnement ; les suivants
//! reçoivent une clé tirée au hasard, écrite à part pour être remise à l'agent : fichier lisible par
//! le seul utilisateur, et chiffré par le mot de passe du propriétaire dès que le compte en a un
//! (`cle::Enveloppe`). Le registre ne contient aucun secret.

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
/// alimenter, geler sont des opérations du propriétaire) : après un changement de mot de passe par la
/// phrase de récupération, la clé privée gardée sur le disque n'est plus lisible, la clé publique si.
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
    /// Clé publique seule : la clé privée n'est pas lisible avec le mot de passe actuel.
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
    /// Chiffrée par le mot de passe du propriétaire (`cle::Enveloppe`).
    Chiffree(crate::cle::Fichier),
}

fn chemin_chiffre(chemin: &str) -> String {
    format!("{chemin}.chiffre")
}

/// Termine un chiffrement interrompu : le fichier chiffré était complet (écrit et synchronisé avant
/// tout effacement du clair), il prend la place du fichier de clé. Un fichier chiffré incomplet est jeté.
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

/// Migration d'un fichier de clé en clair : la clé est chiffrée dans un fichier voisin, relue pour
/// vérification, puis le fichier en clair est effacé (réécrit puis supprimé) et remplacé. Rend vrai
/// si une clé en clair a été chiffrée, faux s'il n'y avait rien à faire.
pub fn chiffrer_fichier(chemin: &str, enveloppe: &crate::cle::Enveloppe) -> Res<bool> {
    let Some(CleStockee::Claire(k)) = lire_cle_stockee(chemin)? else { return Ok(false) };
    let tmp = chemin_chiffre(chemin);
    let _ = std::fs::remove_file(&tmp);
    ecrire_cle(Path::new(&tmp), &k, Some(enveloppe))?;
    let relu: crate::cle::Fichier = serde_json::from_str(&std::fs::read_to_string(&tmp)?)?;
    if enveloppe.dechiffrer(&relu)?.secret_bytes() != k.secret_bytes() {
        let _ = std::fs::remove_file(&tmp);
        return Err("chiffrement de la clé d'agent non vérifié : fichier en clair conservé".into());
    }
    crate::connexion::effacer_fichier(chemin)?;
    std::fs::rename(&tmp, chemin)?;
    Ok(true)
}

/// Chiffre toutes les clés d'agent encore en clair du registre (agents créés avant le chiffrement, ou
/// avant que le mot de passe ait été saisi). Rend le nombre de clés chiffrées ; une clé qui résiste
/// (fichier abîmé) n'empêche pas les autres.
pub fn chiffrer_cles_en_clair(etat_defaut: &str, enveloppe: &crate::cle::Enveloppe) -> usize {
    charger(etat_defaut).iter().filter(|a| a.cle != "env" && !est_connecte(a)).filter(|a| chiffrer_fichier(&a.cle, enveloppe).unwrap_or(false)).count()
}

/// Clé privée d'un agent pas encore connecté, pour préparer son kit de connexion. Une clé chiffrée
/// demande l'enveloppe de la session ou le mot de passe du propriétaire.
pub fn cle_privee(a: &Agent, mot_de_passe: Option<&str>, enveloppe: Option<&crate::cle::Enveloppe>) -> Res<Keypair> {
    match lire_cle_stockee(&a.cle)?.ok_or("clé de l'agent introuvable sur cet ordinateur")? {
        CleStockee::Claire(k) => Ok(k),
        CleStockee::Chiffree(f) => crate::cle::ouvrir_cle_agent(&f, mot_de_passe, enveloppe).map_err(|_| {
            "la clé de cet agent a été chiffrée avec un autre mot de passe (compte restauré depuis la phrase ?) : elle ne peut plus être remise. Arrêtez ce mandat (les fonds reviennent en trésorerie) et créez-en un nouveau".into()
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
/// Seule la préparation du kit de connexion ouvre la clé (`cle_privee`, mot de passe exigé).
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
}

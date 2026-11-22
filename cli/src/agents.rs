//! Registre des agents du propriétaire : un agent = un coffre (même contrat AgentBudget v0.5.1,
//! une instance par agent), avec son propre fichier d'état. Le premier agent (« principal »)
//! reprend le coffre historique et la clé d'agent fournie par l'environnement ; les suivants
//! reçoivent une clé tirée au hasard, écrite à part (0600) pour être remise à l'agent.
//! Le registre ne contient aucun secret.

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
}

fn dossier(etat_defaut: &str) -> PathBuf {
    Path::new(etat_defaut).parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."))
}

fn chemin_registre(etat_defaut: &str) -> PathBuf {
    dossier(etat_defaut).join("agents.json")
}

pub fn charger(etat_defaut: &str) -> Vec<Agent> {
    let lu: Option<Vec<Agent>> = std::fs::read_to_string(chemin_registre(etat_defaut)).ok().and_then(|t| serde_json::from_str(&t).ok());
    match lu {
        Some(v) if !v.is_empty() => v,
        _ => vec![Agent { id: PRINCIPAL.into(), nom: "Agent principal".into(), regles: None, etat: etat_defaut.into(), cle: "env".into(), cree_le: 0, publique: None, connecte_le: None }],
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

/// Inscrit un nouvel agent : clé tirée au hasard, écrite sans écrasement possible (0600).
pub fn nouveau(etat_defaut: &str, nom: &str, regles: Option<crate::Regles>) -> Res<Agent> {
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
    ecrire_secret(&chemin_cle, &hex::encode(cle.secret_bytes()))?;
    let a = Agent {
        id: id.clone(),
        nom,
        regles,
        etat: racine.join(&id).join("etat-coffre.json").to_string_lossy().into_owned(),
        cle: chemin_cle.to_string_lossy().into_owned(),
        cree_le: crate::double_auth::maintenant(),
        publique: Some(hex::encode(cle.public_key().serialize())),
        connecte_le: None,
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

fn ecrire_secret(chemin: &Path, contenu: &str) -> Res<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(chemin)?;
        o.write_all(contenu.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(chemin, contenu)?;
    Ok(())
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
pub fn publique(a: &Agent, principal: &Keypair) -> Res<secp256k1::PublicKey> {
    if a.cle == "env" {
        return Ok(principal.public_key());
    }
    match &a.publique {
        Some(h) => Ok(secp256k1::PublicKey::from_slice(&hex::decode(h)?)?),
        None => Ok(cle(a, principal)?.public_key()),
    }
}

/// Clé publique x-only (celle inscrite dans le contrat du coffre).
pub fn xonly_pub(a: &Agent, principal: &Keypair) -> Option<[u8; 32]> {
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

/// Clé de l'agent : celle de l'environnement pour le principal, sinon son fichier.
pub fn cle(a: &Agent, principal: &Keypair) -> Res<Keypair> {
    if a.cle == "env" {
        return Ok(*principal);
    }
    if est_connecte(a) {
        return Ok(cle_muette());
    }
    let hexa = zeroize::Zeroizing::new(std::fs::read_to_string(&a.cle)?);
    let octets = zeroize::Zeroizing::new(hex::decode(hexa.trim())?);
    Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &octets)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JOUR_DAA, Regles};

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
        assert_eq!(Regles::standard().budget, 2 * Regles::standard().capacite);
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
        let a = nouveau(&defaut, "  Achats API  ", None).unwrap();
        let b = nouveau(&defaut, "Veille", Some(crate::Regles::calculer(4_000_000_000, crate::JOUR_DAA, 200_000_000).unwrap())).unwrap();
        let v = charger(&defaut);
        assert_eq!(v.iter().map(|x| x.nom.as_str()).collect::<Vec<_>>(), ["Agent principal", "Achats API", "Veille"]);
        assert_ne!(a.etat, b.etat, "un fichier d'état par coffre");
        let p = Keypair::from_seckey_slice(secp256k1::SECP256K1, &[1; 32]).unwrap();
        assert_ne!(cle(&a, &p).unwrap().secret_bytes(), cle(&b, &p).unwrap().secret_bytes());
        assert_eq!(cle(&v[0], &p).unwrap().secret_bytes(), p.secret_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a.cle).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(!std::fs::read_to_string(chemin_registre(&defaut)).unwrap().contains(&hex::encode(cle(&a, &p).unwrap().secret_bytes())), "aucun secret dans le registre");
        assert!(nouveau(&defaut, "", None).is_err());
        assert!(nouveau(&defaut, &"x".repeat(41), None).is_err());
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

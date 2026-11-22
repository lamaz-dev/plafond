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
    /// Fichier d'état du coffre de cet agent.
    pub etat: String,
    /// "env" (clé d'agent fournie par l'environnement) ou chemin d'un fichier de clé d'agent.
    pub cle: String,
    pub cree_le: u64,
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
        _ => vec![Agent { id: PRINCIPAL.into(), nom: "Agent principal".into(), etat: etat_defaut.into(), cle: "env".into(), cree_le: 0 }],
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
pub fn nouveau(etat_defaut: &str, nom: &str) -> Res<Agent> {
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
        etat: racine.join(&id).join("etat-coffre.json").to_string_lossy().into_owned(),
        cle: chemin_cle.to_string_lossy().into_owned(),
        cree_le: crate::double_auth::maintenant(),
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

/// Clé de l'agent : celle de l'environnement pour le principal, sinon son fichier.
pub fn cle(a: &Agent, principal: &Keypair) -> Res<Keypair> {
    if a.cle == "env" {
        return Ok(*principal);
    }
    let hexa = zeroize::Zeroizing::new(std::fs::read_to_string(&a.cle)?);
    let octets = zeroize::Zeroizing::new(hex::decode(hexa.trim())?);
    Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &octets)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registre_principal_puis_nouveaux_agents() {
        let d = std::env::temp_dir().join(format!("agents-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let defaut = d.join("etat-coffre.json").to_string_lossy().into_owned();
        let v = charger(&defaut);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, PRINCIPAL);
        assert_eq!(v[0].etat, defaut, "le principal reprend le coffre historique");
        let a = nouveau(&defaut, "  Achats API  ").unwrap();
        let b = nouveau(&defaut, "Veille").unwrap();
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
        assert!(nouveau(&defaut, "").is_err());
        assert!(nouveau(&defaut, &"x".repeat(41)).is_err());
        renommer(&defaut, &a.id, "Achats").unwrap();
        assert_eq!(charger(&defaut)[1].nom, "Achats");
        std::fs::remove_dir_all(&d).unwrap();
    }
}

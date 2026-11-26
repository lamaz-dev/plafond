//! Coffre de secrets par agent (clés API : OpenAI, Anthropic, Stripe, Salesforce, SAP, AWS…).
//!
//! Principe : écriture seule. Chaque secret est chiffré pour la clé publique de l'agent
//! (ECDH secp256k1 avec une clé éphémère, puis XChaCha20-Poly1305 ; l'agent, le nom du secret et la
//! version sont liés au chiffré). La console ne garde jamais la valeur : elle la chiffre, l'efface
//! de la mémoire et n'offre aucune voie pour la relire ou l'exporter. Seul l'agent, avec sa propre
//! clé, peut la déchiffrer au moment de l'utiliser (`dechiffrer`, appelée côté agent).
//! Le fichier ne contient que des chiffrés et des métadonnées (fournisseur, date de modification).

use crate::Res;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use secp256k1::{Keypair, PublicKey, SecretKey, ecdh::SharedSecret};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const FOURNISSEURS: [&str; 10] = ["openai", "anthropic", "stripe", "salesforce", "sap", "aws", "slack", "tavily", "google", "autre"];

#[derive(Serialize, Deserialize, Clone)]
pub struct Secret {
    pub fournisseur: String,
    pub modifie_le: u64,
    /// Clé publique éphémère (33 octets, hexadécimal).
    eph: String,
    nonce: String,
    chiffre: String,
}

/// Ce que la console peut montrer : jamais la valeur, ni un extrait.
#[derive(Serialize)]
pub struct Apercu {
    pub nom: String,
    pub fournisseur: String,
    pub modifie_le: u64,
}

fn chemin(chemin_cle_agent: &str) -> String {
    match chemin_cle_agent.strip_suffix(".key") {
        Some(b) => format!("{b}.secrets.json"),
        None => format!("{chemin_cle_agent}.secrets.json"),
    }
}

fn aad(agent: &PublicKey, nom: &str) -> Vec<u8> {
    format!("kaspa-agent-vault/secret-agent/v1/{}/{nom}", hex::encode(agent.serialize())).into_bytes()
}

pub fn nom_valide(nom: &str) -> Option<String> {
    let n = nom.trim();
    (!n.is_empty() && n.chars().count() <= 40 && n.chars().all(|c| c.is_alphanumeric() || " -_.".contains(c))).then(|| n.to_string())
}

fn lire(fichier: &str) -> BTreeMap<String, Secret> {
    std::fs::read_to_string(fichier).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn ecrire(fichier: &str, s: &BTreeMap<String, Secret>) -> Res<()> {
    let tmp = format!("{fichier}.nouveau");
    let _ = std::fs::remove_file(&tmp);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(s)?.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(&tmp, serde_json::to_string_pretty(s)?)?;
    std::fs::rename(tmp, fichier)?;
    Ok(())
}

/// Chiffre `valeur` pour l'agent `agent_pub` ; la valeur est effacée de la mémoire après usage.
pub fn chiffrer(agent_pub: &PublicKey, nom: &str, fournisseur: &str, valeur: Zeroizing<String>, maintenant: u64) -> Res<Secret> {
    if valeur.trim().is_empty() || valeur.len() > 8192 {
        return Err("secret vide ou trop long".into());
    }
    let eph = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let partage = Zeroizing::new(SharedSecret::new(agent_pub, &eph).secret_bytes());
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("aléa : {e}"))?;
    let ch = XChaCha20Poly1305::new((&*partage).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: valeur.trim().as_bytes(), aad: &aad(agent_pub, nom) })
        .map_err(|_| "chiffrement impossible")?;
    Ok(Secret {
        fournisseur: fournisseur.into(),
        modifie_le: maintenant,
        eph: hex::encode(PublicKey::from_secret_key(secp256k1::SECP256K1, &eph).serialize()),
        nonce: hex::encode(nonce),
        chiffre: hex::encode(ch),
    })
}

/// Côté agent uniquement : déchiffre un secret avec la clé de l'agent.
#[cfg_attr(not(test), allow(dead_code))]
pub fn dechiffrer(agent: &Keypair, nom: &str, s: &Secret) -> Res<Zeroizing<String>> {
    let eph = PublicKey::from_slice(&hex::decode(&s.eph)?)?;
    let partage = Zeroizing::new(SharedSecret::new(&eph, &agent.secret_key()).secret_bytes());
    let nonce = hex::decode(&s.nonce)?;
    if nonce.len() != 24 {
        return Err("nonce invalide".into());
    }
    let clair = XChaCha20Poly1305::new((&*partage).into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &hex::decode(&s.chiffre)?, aad: &aad(&agent.public_key(), nom) })
        .map_err(|_| "secret illisible : mauvaise clé d'agent ou fichier modifié")?;
    Ok(Zeroizing::new(String::from_utf8(clair).map_err(|_| "secret invalide")?))
}

/// Enregistre (ou remplace) un secret d'agent. Rien n'est renvoyé de la valeur.
pub fn enregistrer(chemin_cle_agent: &str, agent_pub: &PublicKey, nom: &str, fournisseur: &str, valeur: Zeroizing<String>) -> Res<()> {
    let nom = nom_valide(nom).ok_or("nom de secret invalide (1 à 40 caractères : lettres, chiffres, espace, - _ .)")?;
    let fournisseur = FOURNISSEURS.iter().find(|f| **f == fournisseur).ok_or("fournisseur inconnu")?;
    let fichier = chemin(chemin_cle_agent);
    let mut tous = lire(&fichier);
    if tous.len() >= 50 && !tous.contains_key(&nom) {
        return Err("50 secrets au plus par agent".into());
    }
    let s = chiffrer(agent_pub, &nom, fournisseur, valeur, crate::double_auth::maintenant())?;
    tous.insert(nom, s);
    ecrire(&fichier, &tous)
}

pub fn supprimer(chemin_cle_agent: &str, nom: &str) -> Res<()> {
    let fichier = chemin(chemin_cle_agent);
    let mut tous = lire(&fichier);
    tous.remove(nom).ok_or("secret inconnu")?;
    ecrire(&fichier, &tous)
}

pub const FORMAT_EXPORT: &str = "kaspa-agent-vault/secrets-agent/v1";

/// Fichier de secrets à transmettre à un agent déjà connecté (R71). Les secrets y sont chiffrés
/// pour l'agent (confidentialité), et l'ensemble est signé par le propriétaire (authenticité) :
/// l'agent n'installe que ce que son propriétaire a signé, pour lui, et jamais une version plus
/// ancienne que celle qu'il a déjà.
#[derive(Serialize, Deserialize)]
pub struct Export {
    pub format: String,
    /// JSON de la charge (`agent`, `cree_le`, `secrets`), signé tel quel.
    pub charge: String,
    /// Signature Schnorr du propriétaire (hexadécimal).
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
struct Charge {
    agent: String,
    cree_le: u64,
    secrets: BTreeMap<String, Secret>,
}

fn condense_export(charge: &str) -> secp256k1::Message {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(FORMAT_EXPORT.as_bytes());
    h.update([0u8]);
    h.update(charge.as_bytes());
    secp256k1::Message::from_digest(h.finalize().into())
}

/// Côté console : exporte les secrets (déjà chiffrés) de l'agent, signés par le propriétaire.
pub fn exporter(proprietaire: &Keypair, agent_pub: &PublicKey, chemin_cle_agent: &str, maintenant: u64) -> Res<Export> {
    let charge = serde_json::to_string(&Charge { agent: hex::encode(agent_pub.serialize()), cree_le: maintenant, secrets: lire(&chemin(chemin_cle_agent)) })?;
    let signature = hex::encode(proprietaire.sign_schnorr(condense_export(&charge)).as_ref());
    Ok(Export { format: FORMAT_EXPORT.into(), charge, signature })
}

/// Côté agent : contrôle la signature du propriétaire, le destinataire et la fraîcheur (`depuis` =
/// date du dernier jeu de secrets installé). Renvoie les secrets (toujours chiffrés) et leur date.
pub fn verifier_export(texte: &str, proprietaire_xonly: &str, agent_pub: &str, depuis: u64) -> Res<(serde_json::Value, usize, u64)> {
    let refus = "fichier de secrets refusé : il n'est pas signé par le propriétaire de cet agent (exportez-le de nouveau depuis la console)";
    let e: Export = serde_json::from_str(texte).map_err(|_| refus)?;
    if e.format != FORMAT_EXPORT {
        return Err(refus.into());
    }
    let cle = secp256k1::XOnlyPublicKey::from_slice(&hex::decode(proprietaire_xonly).map_err(|_| refus)?).map_err(|_| refus)?;
    let signature = secp256k1::schnorr::Signature::from_slice(&hex::decode(&e.signature).map_err(|_| refus)?).map_err(|_| refus)?;
    secp256k1::SECP256K1.verify_schnorr(&signature, &condense_export(&e.charge), &cle).map_err(|_| refus)?;
    let c: Charge = serde_json::from_str(&e.charge).map_err(|_| refus)?;
    if c.agent != agent_pub {
        return Err("fichier de secrets refusé : il est destiné à un autre agent".into());
    }
    if c.cree_le < depuis {
        return Err("fichier de secrets refusé : il est plus ancien que les secrets déjà installés".into());
    }
    Ok((serde_json::to_value(&c.secrets)?, c.secrets.len(), c.cree_le))
}

pub fn lister(chemin_cle_agent: &str) -> Vec<Apercu> {
    lire(&chemin(chemin_cle_agent)).into_iter().map(|(nom, s)| Apercu { nom, fournisseur: s.fournisseur, modifie_le: s.modifie_le }).collect()
}

/// Côté agent : lecture d'un secret par son nom.
#[cfg_attr(not(test), allow(dead_code))]
pub fn lire_pour_agent(chemin_cle_agent: &str, agent: &Keypair, nom: &str) -> Res<Zeroizing<String>> {
    let tous = lire(&chemin(chemin_cle_agent));
    dechiffrer(agent, nom, tous.get(nom).ok_or("secret inconnu")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecriture_seule_et_lecture_par_l_agent() {
        let d = std::env::temp_dir().join(format!("secrets-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let cle = d.join("ag-test.key").to_string_lossy().into_owned();
        let agent = Keypair::from_seckey_slice(secp256k1::SECP256K1, &[5; 32]).unwrap();
        let autre = Keypair::from_seckey_slice(secp256k1::SECP256K1, &[6; 32]).unwrap();
        let valeur = "sk-proj-CECI-EST-UN-SECRET-DE-TEST-0123456789";
        enregistrer(&cle, &agent.public_key(), "OpenAI", "openai", Zeroizing::new(format!("  {valeur}\n"))).unwrap();
        // le fichier ne contient ni la valeur ni un extrait
        let brut = std::fs::read_to_string(chemin(&cle)).unwrap();
        assert!(!brut.contains("sk-proj") && !brut.contains("0123456789"));
        // la liste ne montre que nom, fournisseur, date
        let l = lister(&cle);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].nom.as_str(), l[0].fournisseur.as_str()), ("OpenAI", "openai"));
        assert!(!serde_json::to_string(&l).unwrap().contains("sk-proj"));
        // seul l'agent lit ; une autre clé, un autre nom ou un chiffré modifié échouent
        assert_eq!(lire_pour_agent(&cle, &agent, "OpenAI").unwrap().as_str(), valeur);
        assert!(lire_pour_agent(&cle, &autre, "OpenAI").is_err());
        let mut tous = lire(&chemin(&cle));
        let s = tous.remove("OpenAI").unwrap();
        assert!(dechiffrer(&agent, "Stripe", &s).is_err(), "nom lié au chiffré");
        // deux enregistrements de la même valeur donnent des chiffrés différents (clé éphémère)
        let s2 = chiffrer(&agent.public_key(), "OpenAI", "openai", Zeroizing::new(valeur.into()), 0).unwrap();
        assert_ne!(s.chiffre, s2.chiffre);
        // remplacement puis suppression
        enregistrer(&cle, &agent.public_key(), "OpenAI", "openai", Zeroizing::new("nouvelle-valeur".into())).unwrap();
        assert_eq!(lire_pour_agent(&cle, &agent, "OpenAI").unwrap().as_str(), "nouvelle-valeur");
        assert!(enregistrer(&cle, &agent.public_key(), "x", "inconnu", Zeroizing::new("v".into())).is_err());
        assert!(enregistrer(&cle, &agent.public_key(), "a/b", "aws", Zeroizing::new("v".into())).is_err());
        assert!(enregistrer(&cle, &agent.public_key(), "vide", "aws", Zeroizing::new("   ".into())).is_err());
        supprimer(&cle, "OpenAI").unwrap();
        assert!(lister(&cle).is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(chemin(&cle)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}

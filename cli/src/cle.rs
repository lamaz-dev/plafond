//! Clé du propriétaire, chiffrée sur son appareil (option A : non-custodial).
//!
//! La clé secrète est tirée au hasard par le système, chiffrée par XChaCha20-Poly1305 avec une
//! clé dérivée du mot de passe par Argon2id, et écrite dans un fichier JSON. Elle ne quitte jamais
//! l'appareil : ni le routeur, ni le serveur ne la voient. Perdre le fichier ET le mot de passe,
//! c'est perdre le contrôle du coffre : le propriétaire doit en garder une sauvegarde.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};

use crate::Res;
use zeroize::Zeroizing;

/// Paramètres Argon2id (recommandation OWASP 2025 : 19 Mio, 2 passes, 1 voie ; ici 64 Mio, 3 passes).
const M_KIO: u32 = 64 * 1024;
const T: u32 = 3;
const P: u32 = 1;
const MOT_DE_PASSE_MIN: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct Fichier {
    pub version: u32,
    pub kdf: String,
    pub m_kio: u32,
    pub t: u32,
    pub p: u32,
    pub sel: String,
    pub nonce: String,
    pub chiffre: String,
    /// Clé publique x-only (en clair : sert à identifier le coffre, ne permet pas de signer).
    pub publique: String,
}

/// Clé dérivée du mot de passe : effacée de la mémoire à la sortie de portée (y compris en cas
/// d'erreur ou de panique), grâce à `Zeroizing`.
fn deriver(mot_de_passe: &str, sel: &[u8], m: u32, t: u32, p: u32) -> Res<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| format!("Argon2 : {e}"))?;
    let mut k = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(mot_de_passe.as_bytes(), sel, &mut *k).map_err(|e| format!("Argon2 : {e}"))?;
    Ok(k)
}

/// Données associées : lient le chiffré à la version et à la clé publique (aucun échange possible).
fn aad(publique: &str) -> Vec<u8> {
    format!("kaspa-agent-vault/cle-proprietaire/v1/{publique}").into_bytes()
}

pub fn chiffrer(k: &Keypair, mot_de_passe: &str) -> Res<Fichier> {
    if mot_de_passe.chars().count() < MOT_DE_PASSE_MIN {
        return Err(format!("mot de passe trop court ({MOT_DE_PASSE_MIN} caractères minimum)").into());
    }
    let mut sel = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut sel).map_err(|e| format!("aléa : {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("aléa : {e}"))?;
    let publique = hex::encode(k.x_only_public_key().0.serialize());
    let cle = deriver(mot_de_passe, &sel, M_KIO, T, P)?;
    let c = XChaCha20Poly1305::new((&*cle).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &*Zeroizing::new(k.secret_bytes()), aad: &aad(&publique) })
        .map_err(|_| "chiffrement impossible")?;
    Ok(Fichier { version: 1, kdf: "argon2id".into(), m_kio: M_KIO, t: T, p: P, sel: hex::encode(sel), nonce: hex::encode(nonce), chiffre: hex::encode(c), publique })
}

pub fn dechiffrer(f: &Fichier, mot_de_passe: &str) -> Res<Keypair> {
    if f.version != 1 || f.kdf != "argon2id" {
        return Err("format de clé inconnu".into());
    }
    if f.m_kio < 19 * 1024 || f.t < 2 {
        return Err("paramètres de dérivation trop faibles : fichier refusé".into());
    }
    let cle = deriver(mot_de_passe, &hex::decode(&f.sel)?, f.m_kio, f.t, f.p)?;
    let nonce = hex::decode(&f.nonce)?;
    if nonce.len() != 24 {
        return Err("nonce invalide".into());
    }
    let secret: Zeroizing<Vec<u8>> = XChaCha20Poly1305::new((&*cle).into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &hex::decode(&f.chiffre)?, aad: &aad(&f.publique) })
        .map_err(|_| "mot de passe incorrect ou fichier modifié")?
        .into();
    let k = Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret)?;
    if hex::encode(k.x_only_public_key().0.serialize()) != f.publique {
        return Err("clé publique incohérente : fichier modifié".into());
    }
    Ok(k)
}

/// Nouvelle clé tirée par le système d'exploitation.
pub fn nouvelle() -> Res<Keypair> {
    loop {
        let mut s = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *s).map_err(|e| format!("aléa : {e}"))?;
        if let Ok(k) = Keypair::from_seckey_slice(secp256k1::SECP256K1, &*s) {
            return Ok(k);
        }
    }
}

pub fn ecrire(chemin: &str, f: &Fichier) -> Res<()> {
    if std::path::Path::new(chemin).exists() {
        return Err(format!("{chemin} existe déjà : refus d'écraser une clé").into());
    }
    let json = serde_json::to_string_pretty(f)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(chemin)?;
        o.write_all(json.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(chemin, json)?;
    Ok(())
}

pub fn lire(chemin: &str) -> Res<Fichier> {
    Ok(serde_json::from_str(&std::fs::read_to_string(chemin)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rapide(k: &Keypair, mdp: &str) -> Fichier {
        // Mêmes primitives, coût minimal accepté, pour garder les tests rapides.
        let mut f = chiffrer(k, mdp).unwrap();
        let sel = hex::decode(&f.sel).unwrap();
        let cle = deriver(mdp, &sel, 19 * 1024, 2, 1).unwrap();
        let c = XChaCha20Poly1305::new((&*cle).into())
            .encrypt(XNonce::from_slice(&hex::decode(&f.nonce).unwrap()), Payload { msg: &k.secret_bytes(), aad: &aad(&f.publique) })
            .unwrap();
        f.m_kio = 19 * 1024;
        f.t = 2;
        f.chiffre = hex::encode(c);
        f
    }

    #[test]
    fn aller_retour_et_mauvais_mot_de_passe() {
        let k = nouvelle().unwrap();
        let f = rapide(&k, "correct horse battery");
        assert_eq!(dechiffrer(&f, "correct horse battery").unwrap().secret_bytes(), k.secret_bytes());
        assert!(dechiffrer(&f, "correct horse batterz").is_err());
        assert!(!serde_json::to_string(&f).unwrap().contains(&hex::encode(k.secret_bytes())));
    }

    #[test]
    fn falsifications_detectees() {
        let k = nouvelle().unwrap();
        let mdp = "un mot de passe long";
        let mut f = rapide(&k, mdp);
        let autre = nouvelle().unwrap();
        f.publique = hex::encode(autre.x_only_public_key().0.serialize()); // échange de clé publique
        assert!(dechiffrer(&f, mdp).is_err());
        let mut f = rapide(&k, mdp);
        let mut c = hex::decode(&f.chiffre).unwrap();
        c[0] ^= 1;
        f.chiffre = hex::encode(c);
        assert!(dechiffrer(&f, mdp).is_err());
        let mut f = rapide(&k, mdp);
        f.m_kio = 1024; // affaiblissement des paramètres refusé
        assert!(dechiffrer(&f, mdp).is_err());
    }

    #[test]
    fn mot_de_passe_court_refuse_et_pas_d_ecrasement() {
        assert!(chiffrer(&nouvelle().unwrap(), "court").is_err());
        let dir = std::env::temp_dir().join(format!("cle-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = dir.join("cle.json");
        let chemin = chemin.to_str().unwrap();
        let _ = std::fs::remove_file(chemin);
        let f = rapide(&nouvelle().unwrap(), "un mot de passe long");
        ecrire(chemin, &f).unwrap();
        assert!(ecrire(chemin, &f).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(chemin).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_file(chemin).unwrap();
    }
}

/// Mot de passe du propriétaire : saisi au clavier (jamais affiché), ou PROPRIETAIRE_MDP pour un
/// usage automatisé (testnet uniquement). Effacé de la mémoire après usage.
pub fn mot_de_passe(invite: &str) -> Res<Zeroizing<String>> {
    if let Ok(m) = std::env::var("PROPRIETAIRE_MDP") {
        return Ok(Zeroizing::new(m));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(invite)?))
}

/// Ouvre le fichier de clé du propriétaire.
pub fn ouvrir(chemin: &str) -> Res<Keypair> {
    let f = lire(chemin)?;
    dechiffrer(&f, &mot_de_passe("Mot de passe du coffre propriétaire : ")?)
}

/// Crée un fichier de clé neuf (mot de passe demandé deux fois).
pub fn creer(chemin: &str) -> Res<Keypair> {
    let m1 = mot_de_passe("Nouveau mot de passe (12 caractères minimum) : ")?;
    if std::env::var("PROPRIETAIRE_MDP").is_err() {
        let m2 = mot_de_passe("Confirmer le mot de passe : ")?;
        if *m1 != *m2 {
            return Err("les deux mots de passe diffèrent".into());
        }
    }
    let k = nouvelle()?;
    ecrire(chemin, &chiffrer(&k, &m1)?)?;
    Ok(k)
}

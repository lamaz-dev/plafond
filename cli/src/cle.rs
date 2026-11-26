//! Clé du propriétaire, chiffrée sur son appareil (option A : non-custodial).
//!
//! Format v2 : une phrase de récupération de 24 mots (BIP39) est tirée au hasard par le système ;
//! la clé du propriétaire en est dérivée (chemin Kaspa standard m/44'/111111'/0'/0/0). La phrase
//! (et l'éventuel secret de double authentification) est chiffrée par XChaCha20-Poly1305 avec une
//! clé dérivée du mot de passe par Argon2id, et écrite dans un fichier JSON. Format v1 (clé brute)
//! toujours lu. Elle ne quitte jamais
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
pub(crate) const M_KIO: u32 = 64 * 1024;
pub(crate) const T: u32 = 3;
pub(crate) const P: u32 = 1;
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
pub(crate) fn deriver(mot_de_passe: &str, sel: &[u8], m: u32, t: u32, p: u32) -> Res<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| format!("Argon2 : {e}"))?;
    let mut k = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(mot_de_passe.as_bytes(), sel, &mut *k).map_err(|e| format!("Argon2 : {e}"))?;
    Ok(k)
}

/// Données associées : lient le chiffré à la version et à la clé publique (aucun échange possible).
fn aad(publique: &str) -> Vec<u8> {
    format!("kaspa-agent-vault/cle-proprietaire/v1/{publique}").into_bytes()
}

#[cfg_attr(not(test), allow(dead_code))] // format v1, conservé pour la lecture et les tests
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

/// Contenu chiffré d'un fichier v2 : la source de la clé (phrase de récupération) et, si la double
/// authentification est activée, son secret. Tout est effacé de la mémoire à la sortie de portée.
pub struct Coffret {
    pub entropie: Zeroizing<Vec<u8>>,
    pub totp: Option<Zeroizing<Vec<u8>>>,
}

pub const CHEMIN_DERIVATION: &str = "m/44'/111111'/0'/0/0";

/// Phrase de récupération (24 mots anglais BIP39) correspondant à l'entropie.
pub fn phrase(c: &Coffret) -> Res<Zeroizing<String>> {
    let m = kaspa_bip32::Mnemonic::from_entropy(c.entropie.to_vec(), kaspa_bip32::Language::English).map_err(|e| format!("phrase : {e}"))?;
    Ok(Zeroizing::new(m.phrase().to_string()))
}

/// Coffret retrouvé depuis une phrase saisie (somme de contrôle BIP39 vérifiée).
pub fn depuis_phrase(texte: &str) -> Res<Coffret> {
    let mots: Vec<&str> = texte.split_whitespace().collect();
    if mots.len() != 24 {
        return Err("la phrase de récupération compte 24 mots".into());
    }
    let normalisee = Zeroizing::new(mots.iter().map(|m| m.to_lowercase()).collect::<Vec<_>>().join(" "));
    let m = kaspa_bip32::Mnemonic::new(normalisee.as_str(), kaspa_bip32::Language::English).map_err(|_| "phrase de récupération invalide (mot inconnu ou somme de contrôle fausse)")?;
    Ok(Coffret { entropie: Zeroizing::new(m.entropy().to_vec()), totp: None })
}

/// Clé du propriétaire dérivée de la phrase (même dérivation que les portefeuilles Kaspa standards).
pub fn cle_du_coffret(c: &Coffret) -> Res<Keypair> {
    let m = kaspa_bip32::Mnemonic::from_entropy(c.entropie.to_vec(), kaspa_bip32::Language::English).map_err(|e| format!("phrase : {e}"))?;
    let graine = m.to_seed("");
    let racine = kaspa_bip32::ExtendedPrivateKey::<kaspa_bip32::SecretKey>::new(graine.as_bytes()).map_err(|e| format!("dérivation : {e}"))?;
    let chemin: kaspa_bip32::DerivationPath = CHEMIN_DERIVATION.parse().map_err(|e| format!("chemin : {e:?}"))?;
    let enfant = racine.derive_path(&chemin).map_err(|e| format!("dérivation : {e}"))?;
    let octets = Zeroizing::new(kaspa_bip32::PrivateKey::to_bytes(enfant.private_key()));
    Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &octets[..])?)
}

pub fn nouveau_coffret() -> Res<Coffret> {
    let mut e = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(&mut e).map_err(|e| format!("aléa : {e}"))?;
    Ok(Coffret { entropie: e, totp: None })
}

#[derive(Serialize, Deserialize)]
struct Contenu {
    entropie: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp: Option<String>,
}

fn aad_v2(publique: &str) -> Vec<u8> {
    format!("kaspa-agent-vault/cle-proprietaire/v2/{publique}").into_bytes()
}

pub fn chiffrer_coffret(c: &Coffret, mot_de_passe: &str) -> Res<Fichier> {
    if mot_de_passe.chars().count() < MOT_DE_PASSE_MIN {
        return Err(format!("mot de passe trop court ({MOT_DE_PASSE_MIN} caractères minimum)").into());
    }
    let k = cle_du_coffret(c)?;
    let mut sel = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut sel).map_err(|e| format!("aléa : {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("aléa : {e}"))?;
    let publique = hex::encode(k.x_only_public_key().0.serialize());
    let contenu = Zeroizing::new(serde_json::to_string(&Contenu { entropie: hex::encode(&*c.entropie), totp: c.totp.as_ref().map(|t| hex::encode(&**t)) })?);
    let cle = deriver(mot_de_passe, &sel, M_KIO, T, P)?;
    let ch = XChaCha20Poly1305::new((&*cle).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: contenu.as_bytes(), aad: &aad_v2(&publique) })
        .map_err(|_| "chiffrement impossible")?;
    Ok(Fichier { version: 2, kdf: "argon2id".into(), m_kio: M_KIO, t: T, p: P, sel: hex::encode(sel), nonce: hex::encode(nonce), chiffre: hex::encode(ch), publique })
}

fn controler(f: &Fichier) -> Res<()> {
    if !(f.version == 1 || f.version == 2) || f.kdf != "argon2id" {
        return Err("format de clé inconnu".into());
    }
    if f.m_kio < 19 * 1024 || f.t < 2 {
        return Err("paramètres de dérivation trop faibles : fichier refusé".into());
    }
    if f.m_kio > 1024 * 1024 || f.t > 10 || f.p == 0 || f.p > 8 {
        return Err("paramètres de dérivation démesurés : fichier refusé (protection mémoire)".into());
    }
    Ok(())
}

/// Ouvre un fichier v1 ou v2 : la clé, et pour v2 le coffret (phrase, double authentification).
pub fn ouvrir_tout(f: &Fichier, mot_de_passe: &str) -> Res<(Keypair, Option<Coffret>)> {
    controler(f)?;
    let cle = deriver(mot_de_passe, &hex::decode(&f.sel)?, f.m_kio, f.t, f.p)?;
    let nonce = hex::decode(&f.nonce)?;
    if nonce.len() != 24 {
        return Err("nonce invalide".into());
    }
    let aad = if f.version == 1 { aad(&f.publique) } else { aad_v2(&f.publique) };
    let clair: Zeroizing<Vec<u8>> = XChaCha20Poly1305::new((&*cle).into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &hex::decode(&f.chiffre)?, aad: &aad })
        .map_err(|_| "mot de passe incorrect ou fichier modifié")?
        .into();
    let (k, coffret) = if f.version == 1 {
        (Keypair::from_seckey_slice(secp256k1::SECP256K1, &clair)?, None)
    } else {
        let c: Contenu = serde_json::from_slice(&clair)?;
        let coffret = Coffret {
            entropie: Zeroizing::new(hex::decode(&c.entropie)?),
            totp: c.totp.map(|t| hex::decode(t).map(Zeroizing::new)).transpose()?,
        };
        (cle_du_coffret(&coffret)?, Some(coffret))
    };
    if hex::encode(k.x_only_public_key().0.serialize()) != f.publique {
        return Err("clé publique incohérente : fichier modifié".into());
    }
    Ok((k, coffret))
}

pub fn dechiffrer(f: &Fichier, mot_de_passe: &str) -> Res<Keypair> {
    Ok(ouvrir_tout(f, mot_de_passe)?.0)
}

/// Remplace un fichier de clé existant (même clé publique exigée), de façon atomique ; l'ancienne
/// version est conservée à côté (`.precedent`).
pub fn remplacer(chemin: &str, f: &Fichier) -> Res<()> {
    let ancien = lire(chemin)?;
    if ancien.publique != f.publique {
        return Err("refus : le nouveau fichier ne correspond pas à la même clé".into());
    }
    let tmp = format!("{chemin}.nouveau");
    let _ = std::fs::remove_file(&tmp);
    ecrire(&tmp, f)?;
    let precedent = format!("{chemin}.precedent");
    std::fs::copy(chemin, &precedent)?;
    crate::prive::proteger(std::path::Path::new(&precedent))?;
    std::fs::rename(&tmp, chemin)?;
    Ok(())
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
    crate::prive::ecrire(std::path::Path::new(chemin), serde_json::to_string_pretty(f)?.as_bytes())
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
        f.m_kio = 64 * 1024 * 1024; // 64 Gio : refusé avant toute allocation
        assert!(dechiffrer(&f, mdp).is_err());
    }

    #[test]
    fn phrase_vecteur_bip39_et_aller_retour_v2() {
        // Vecteur officiel BIP39 (entropie nulle de 32 octets).
        let c = Coffret { entropie: Zeroizing::new(vec![0u8; 32]), totp: None };
        let p = phrase(&c).unwrap();
        assert!(p.starts_with("abandon abandon") && p.ends_with("art"));
        let k = cle_du_coffret(&c).unwrap();
        assert_eq!(cle_du_coffret(&depuis_phrase(&p.to_uppercase()).unwrap()).unwrap().secret_bytes(), k.secret_bytes());
        assert!(depuis_phrase(&p.replace("art", "abandon")).is_err()); // somme de contrôle
        assert!(depuis_phrase("abandon abandon").is_err());
        // Chiffrement v2 (coût réduit pour le test) puis ouverture.
        let mut c2 = nouveau_coffret().unwrap();
        c2.totp = Some(Zeroizing::new(vec![7u8; 20]));
        let mdp = "un mot de passe long";
        let mut f = chiffrer_coffret(&c2, mdp).unwrap();
        let sel = hex::decode(&f.sel).unwrap();
        let cle = deriver(mdp, &sel, 19 * 1024, 2, 1).unwrap();
        let contenu = serde_json::to_string(&Contenu { entropie: hex::encode(&*c2.entropie), totp: Some(hex::encode([7u8; 20])) }).unwrap();
        f.chiffre = hex::encode(XChaCha20Poly1305::new((&*cle).into()).encrypt(XNonce::from_slice(&hex::decode(&f.nonce).unwrap()), Payload { msg: contenu.as_bytes(), aad: &aad_v2(&f.publique) }).unwrap());
        f.m_kio = 19 * 1024;
        f.t = 2;
        let (k2, cof) = ouvrir_tout(&f, mdp).unwrap();
        assert_eq!(k2.secret_bytes(), cle_du_coffret(&c2).unwrap().secret_bytes());
        assert_eq!(cof.unwrap().totp.unwrap().to_vec(), vec![7u8; 20]);
        assert!(ouvrir_tout(&f, "mauvais mot de passe").is_err());
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains(&hex::encode(&*c2.entropie)) && !json.contains("abandon"));
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
        assert!(crate::prive::est_prive(std::path::Path::new(chemin)).unwrap(), "{}", crate::prive::droits(std::path::Path::new(chemin)));
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
    let c = nouveau_coffret()?;
    ecrire(chemin, &chiffrer_coffret(&c, &m1)?)?;
    cle_du_coffret(&c)
}

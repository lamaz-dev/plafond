//! Connecter un agent. La console remet à l'agent tout ce dont il a besoin (sa clé, les règles et
//! l'état de son coffre, ses secrets chiffrés) dans un kit scellé par un code de connexion à usage
//! unique (Argon2id + XChaCha20-Poly1305), puis, une fois la remise confirmée, efface sa propre copie
//! de la clé. Ensuite la console ne connaît plus que la clé publique de l'agent : elle peut toujours
//! alimenter, surveiller et geler le coffre (opérations du propriétaire), mais ne peut plus ni payer à
//! la place de l'agent, ni déchiffrer ses secrets.
//!
//! Côté agent : `vault-cli agent-installer <kit>` (code saisi au clavier, jamais affiché), puis
//! `vault-cli agent-verifier` contrôle que la clé et chaque secret sont lisibles, sans rien afficher.

use crate::Res;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use zeroize::Zeroizing;

pub const FORMAT: &str = "kaspa-agent-vault/kit-connexion/v1";

/// Contenu du kit (en clair seulement en mémoire, effacé après usage).
#[derive(Serialize, Deserialize)]
pub struct Kit {
    pub agent_id: String,
    pub nom: String,
    pub cle_agent: String,
    pub publique: String,
    pub proprietaire: String,
    pub regles: Option<crate::Regles>,
    pub origine: Option<Value>,
    pub etat: Option<Value>,
    pub secrets: Value,
    pub reseau: String,
    pub cree_le: u64,
}

impl Drop for Kit {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.cle_agent);
    }
}

/// Kit scellé, prêt à voyager : seul le code de connexion l'ouvre.
#[derive(Serialize, Deserialize, Clone)]
pub struct Scelle {
    pub format: String,
    pub agent_id: String,
    pub nom: String,
    pub publique: String,
    kdf: String,
    m_kio: u32,
    t: u32,
    p: u32,
    sel: String,
    nonce: String,
    chiffre: String,
}

const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // sans 0/O, 1/I/L

/// Code de connexion : 4 groupes de 5 caractères (≈ 99 bits), à transmettre séparément du kit.
pub fn nouveau_code() -> Res<Zeroizing<String>> {
    let mut code = Zeroizing::new(String::new());
    let mut alea = Zeroizing::new([0u8; 40]);
    getrandom::getrandom(&mut alea[..]).map_err(|e| format!("aléa : {e}"))?;
    let mut n = 0;
    for &o in alea.iter() {
        // rejet pour une distribution uniforme sur 31 symboles
        if o >= 248 {
            continue;
        }
        if n > 0 && n % 5 == 0 {
            code.push('-');
        }
        code.push(ALPHABET[(o % 31) as usize] as char);
        n += 1;
        if n == 20 {
            return Ok(code);
        }
    }
    Err("aléa insuffisant".into())
}

fn normaliser(code: &str) -> Zeroizing<String> {
    Zeroizing::new(code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect())
}

fn aad(agent_id: &str, publique: &str) -> Vec<u8> {
    format!("{FORMAT}/{agent_id}/{publique}").into_bytes()
}

pub fn sceller(kit: &Kit, code: &str) -> Res<Scelle> {
    let mut sel = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut sel).map_err(|e| format!("aléa : {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| format!("aléa : {e}"))?;
    let (m, t, p) = (crate::cle::M_KIO, crate::cle::T, crate::cle::P);
    let cle = crate::cle::deriver(&normaliser(code), &sel, m, t, p)?;
    let clair = Zeroizing::new(serde_json::to_vec(kit)?);
    let ch = XChaCha20Poly1305::new((&*cle).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &clair, aad: &aad(&kit.agent_id, &kit.publique) })
        .map_err(|_| "scellement impossible")?;
    Ok(Scelle {
        format: FORMAT.into(),
        agent_id: kit.agent_id.clone(),
        nom: kit.nom.clone(),
        publique: kit.publique.clone(),
        kdf: "argon2id".into(),
        m_kio: m,
        t,
        p,
        sel: hex::encode(sel),
        nonce: hex::encode(nonce),
        chiffre: hex::encode(ch),
    })
}

pub fn ouvrir(s: &Scelle, code: &str) -> Res<Kit> {
    if s.format != FORMAT || s.kdf != "argon2id" || s.m_kio < 19 * 1024 || s.m_kio > 1024 * 1024 || s.t < 2 || s.t > 10 || s.p == 0 || s.p > 8 {
        return Err("kit de connexion inconnu ou paramètres refusés".into());
    }
    let cle = crate::cle::deriver(&normaliser(code), &hex::decode(&s.sel)?, s.m_kio, s.t, s.p)?;
    let nonce = hex::decode(&s.nonce)?;
    if nonce.len() != 24 {
        return Err("nonce invalide".into());
    }
    let clair: Zeroizing<Vec<u8>> = XChaCha20Poly1305::new((&*cle).into())
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &hex::decode(&s.chiffre)?, aad: &aad(&s.agent_id, &s.publique) })
        .map_err(|_| "code de connexion incorrect ou kit modifié")?
        .into();
    let kit: Kit = serde_json::from_slice(&clair)?;
    // cohérence : la clé contenue correspond bien à la clé publique annoncée
    let k = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &Zeroizing::new(hex::decode(&kit.cle_agent)?))?;
    if hex::encode(k.public_key().serialize()) != kit.publique || kit.publique != s.publique || kit.agent_id != s.agent_id {
        return Err("kit incohérent : clé d'agent et clé publique ne correspondent pas".into());
    }
    Ok(kit)
}

/// Efface un fichier secret : réécriture par des zéros, synchronisation, suppression.
pub fn effacer_fichier(chemin: &str) -> Res<()> {
    use std::io::Write;
    let taille = std::fs::metadata(chemin)?.len() as usize;
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(chemin)?;
        f.write_all(&vec![0u8; taille.max(1)])?;
        f.sync_all()?;
    }
    std::fs::remove_file(chemin)?;
    Ok(())
}

fn ecrire_prive(chemin: &Path, contenu: &[u8]) -> Res<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(chemin)?;
        f.write_all(contenu)?;
    }
    #[cfg(not(unix))]
    std::fs::write(chemin, contenu)?;
    Ok(())
}

/// Registre des mandats installés sur cet ordinateur (une ligne par mandat : propriétaire, clé
/// publique, dossier). Rien de secret.
fn registre_machine() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PLAFOND_REGISTRE_AGENTS") {
        return p.into();
    }
    let maison = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    Path::new(&maison).join(".plafond").join("mandats-installes.json")
}

/// Un programme d'agent = un mandat. Deux mandats du même propriétaire sur la même machine
/// permettraient de transférer de l'un à l'autre et de dépasser la fenêtre de 24 h (R52 ; la courbe
/// promise, elle, tiendrait). Garde-fou contre l'erreur de configuration : refus, sauf si le premier
/// dossier n'existe plus (agent désinstallé).
fn verifier_un_mandat_par_machine(registre: &Path, proprietaire: &str, publique: &str, dossier: &Path) -> Res<()> {
    let lu: Vec<Value> = std::fs::read_to_string(registre).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    for m in &lu {
        let autre = Path::new(m["dossier"].as_str().unwrap_or(""));
        if m["proprietaire"] == proprietaire && m["publique"] != publique && autre.join("agent.key").exists() && autre != dossier {
            return Err(format!(
                "un autre mandat du même propriétaire est déjà installé sur cet ordinateur ({}). Un agent = un mandat : pour lui donner plus de budget, agrandissez son mandat dans la console",
                autre.display()
            )
            .into());
        }
    }
    Ok(())
}

fn inscrire_machine(registre: &Path, proprietaire: &str, publique: &str, dossier: &Path) -> Res<()> {
    let mut lu: Vec<Value> = std::fs::read_to_string(registre).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    lu.retain(|m| Path::new(m["dossier"].as_str().unwrap_or("")).join("agent.key").exists());
    lu.push(serde_json::json!({ "proprietaire": proprietaire, "publique": publique, "dossier": dossier.canonicalize().unwrap_or(dossier.to_path_buf()) }));
    if let Some(dir) = registre.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(registre, serde_json::to_string_pretty(&lu)?)?;
    Ok(())
}

/// Installation côté agent : écrit la clé (0600, jamais d'écrasement), l'état du coffre et les secrets.
pub fn installer(s: &Scelle, code: &str, dossier: &str) -> Res<String> {
    installer_avec(s, code, dossier, true)
}

/// Agent de démonstration : temporaire et révoqué à la fin de la démo, il ne compte pas comme mandat
/// installé (sinon la démo suivante serait refusée).
pub fn installer_demo(s: &Scelle, code: &str, dossier: &str) -> Res<String> {
    installer_avec(s, code, dossier, false)
}

fn installer_avec(s: &Scelle, code: &str, dossier: &str, registre_actif: bool) -> Res<String> {
    let kit = ouvrir(s, code)?;
    let d = Path::new(dossier);
    if d.join("agent.key").exists() {
        return Err(format!("un agent est déjà installé dans {dossier} : choisissez un autre dossier").into());
    }
    let registre = registre_machine();
    let d_abs = d.canonicalize().unwrap_or(d.to_path_buf());
    if registre_actif {
        verifier_un_mandat_par_machine(&registre, &kit.proprietaire, &kit.publique, &d_abs)?;
    }
    std::fs::create_dir_all(d)?;
    ecrire_prive(&d.join("agent.key"), kit.cle_agent.as_bytes())?;
    if let Some(o) = &kit.origine {
        std::fs::write(d.join("etat-coffre-origine.json"), serde_json::to_string_pretty(o)?)?;
    }
    if let Some(e) = &kit.etat {
        std::fs::write(d.join("etat-coffre.json"), serde_json::to_string_pretty(e)?)?;
    }
    std::fs::write(d.join("agent.secrets.json"), serde_json::to_string_pretty(&kit.secrets)?)?;
    let meta = serde_json::json!({ "agent_id": kit.agent_id, "nom": kit.nom, "publique": kit.publique, "proprietaire": kit.proprietaire, "regles": kit.regles, "reseau": kit.reseau, "installe_le": crate::double_auth::maintenant() });
    std::fs::write(d.join("agent.json"), serde_json::to_string_pretty(&meta)?)?;
    if registre_actif {
        inscrire_machine(&registre, &kit.proprietaire, &kit.publique, d)?;
    }
    Ok(kit.nom.clone())
}

/// Mise à jour des secrets côté agent (fichier de secrets chiffrés exporté par la console : il peut
/// voyager librement, seul l'agent sait le lire).
pub fn maj_secrets(fichier: &str, dossier: &str) -> Res<usize> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(fichier)?)?;
    let n = v.as_object().map(|o| o.len()).ok_or("fichier de secrets invalide")?;
    let tmp = Path::new(dossier).join("agent.secrets.json.nouveau");
    std::fs::write(&tmp, serde_json::to_string_pretty(&v)?)?;
    std::fs::rename(tmp, Path::new(dossier).join("agent.secrets.json"))?;
    Ok(n)
}

/// Contrôle côté agent : la clé est lisible et chaque secret se déchiffre (rien n'est affiché).
pub fn verifier(dossier: &str) -> Res<Vec<(String, bool)>> {
    let d = Path::new(dossier);
    let hexa = Zeroizing::new(std::fs::read_to_string(d.join("agent.key"))?);
    let k = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &Zeroizing::new(hex::decode(hexa.trim())?))?;
    let base = d.join("agent.key").to_string_lossy().into_owned();
    Ok(crate::secrets::lister(&base).into_iter().map(|a| { let ok = crate::secrets::lire_pour_agent(&base, &k, &a.nom).is_ok(); (a.nom, ok) }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_mandat_par_machine() {
        let t = std::env::temp_dir().join(format!("plafond-registre-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let registre = t.join("mandats.json");
        let (a, b) = (t.join("agent-a"), t.join("agent-b"));
        std::fs::create_dir_all(&a).unwrap();
        assert!(verifier_un_mandat_par_machine(&registre, "proprio", "pkA", &a).is_ok(), "premier mandat");
        std::fs::write(a.join("agent.key"), "x").unwrap();
        inscrire_machine(&registre, "proprio", "pkA", &a).unwrap();
        let e = verifier_un_mandat_par_machine(&registre, "proprio", "pkB", &b).unwrap_err().to_string();
        assert!(e.contains("agrandissez son mandat"), "{e}");
        assert!(verifier_un_mandat_par_machine(&registre, "autre-proprio", "pkC", &b).is_ok(), "autre propriétaire : permis");
        std::fs::remove_file(a.join("agent.key")).unwrap();
        assert!(verifier_un_mandat_par_machine(&registre, "proprio", "pkB", &b).is_ok(), "premier agent désinstallé : permis");
        let _ = std::fs::remove_dir_all(&t);
    }

    #[test]
    fn kit_scelle_installe_et_verifie() {
        let code = nouveau_code().unwrap();
        assert_eq!(code.len(), 23);
        assert!(code.chars().all(|c| c == '-' || ALPHABET.contains(&(c as u8))));
        assert_ne!(*code, *nouveau_code().unwrap());
        let d = std::env::temp_dir().join(format!("connexion-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // côté console : un agent avec un secret
        let agent = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[8; 32]).unwrap();
        let console_cle = d.join("console-ag.key").to_string_lossy().into_owned();
        std::fs::write(&console_cle, hex::encode(agent.secret_bytes())).unwrap();
        crate::secrets::enregistrer(&console_cle, &agent.public_key(), "OpenAI", "openai", Zeroizing::new("sk-test-123".into())).unwrap();
        let secrets_chiffres: Value = serde_json::from_str(&std::fs::read_to_string(d.join("console-ag.secrets.json")).unwrap()).unwrap();
        let kit = Kit {
            agent_id: "ag-1".into(), nom: "Recherche".into(), cle_agent: hex::encode(agent.secret_bytes()), publique: hex::encode(agent.public_key().serialize()),
            proprietaire: "00".into(), regles: None, origine: None, etat: None, secrets: secrets_chiffres, reseau: "testnet-10".into(), cree_le: 0,
        };
        let s = sceller(&kit, &code).unwrap();
        let brut = serde_json::to_string(&s).unwrap();
        assert!(!brut.contains(&hex::encode(agent.secret_bytes())), "clé jamais en clair dans le kit");
        // mauvais code, kit modifié : refus
        assert!(ouvrir(&s, "AAAAA-BBBBB-CCCCC-DDDDD").is_err());
        let mut s2 = s.clone();
        s2.agent_id = "ag-2".into();
        assert!(ouvrir(&s2, &code).is_err());
        // code saisi en minuscules, sans tirets : accepté
        let saisi = code.replace('-', " ").to_lowercase();
        let agent_dossier = d.join("serveur-agent").to_string_lossy().into_owned();
        assert_eq!(installer_demo(&s, &saisi, &agent_dossier).unwrap(), "Recherche");
        assert!(installer_demo(&s, &code, &agent_dossier).is_err(), "jamais d'écrasement");
        assert_eq!(verifier(&agent_dossier).unwrap(), vec![("OpenAI".to_string(), true)]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(Path::new(&agent_dossier).join("agent.key")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // côté console : effacement de la copie de la clé
        effacer_fichier(&console_cle).unwrap();
        assert!(!Path::new(&console_cle).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

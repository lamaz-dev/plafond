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

/// Écrit un fichier de secrets de l'agent (chiffrés pour lui) : neuf, sans suivre un lien laissé à sa
/// place (R69), et lisible par le seul utilisateur.
fn ecrire_neuf_prive(chemin: &Path, contenu: &[u8]) -> Res<()> {
    let _ = std::fs::remove_file(chemin);
    crate::prive::ecrire(chemin, contenu)
}

/// Écrit un fichier non secret de l'agent sans jamais suivre un lien symbolique laissé à sa place
/// (R69) : l'ancien nom est retiré, puis le fichier est créé neuf.
fn ecrire_neuf(chemin: &Path, contenu: &[u8]) -> Res<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(chemin);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(chemin)?;
    f.write_all(contenu)?;
    Ok(())
}

/// Registre lu : absent = aucun mandat ; présent mais illisible = erreur (R70), pour que la règle
/// « un mandat par machine » ne saute pas en silence.
fn lire_registre(registre: &Path) -> Res<Vec<Value>> {
    if !registre.exists() {
        return Ok(Vec::new());
    }
    std::fs::read_to_string(registre).ok().and_then(|t| serde_json::from_str(&t).ok()).ok_or_else(|| {
        format!(
            "registre des mandats illisible ({}) : vérifiez qu'aucun autre mandat du même propriétaire n'est installé sur cet ordinateur, puis supprimez ce fichier",
            registre.display()
        )
        .into()
    })
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
    let lu = lire_registre(registre)?;
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
    let mut lu = lire_registre(registre)?;
    lu.retain(|m| Path::new(m["dossier"].as_str().unwrap_or("")).join("agent.key").exists());
    lu.push(serde_json::json!({ "proprietaire": proprietaire, "publique": publique, "dossier": dossier.canonicalize().unwrap_or(dossier.to_path_buf()) }));
    if let Some(dir) = registre.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // écriture atomique : une interruption ne laisse pas un registre tronqué
    let tmp = registre.with_extension("json.nouveau");
    ecrire_neuf(&tmp, serde_json::to_string_pretty(&lu)?.as_bytes())?;
    std::fs::rename(tmp, registre)?;
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
    crate::prive::ecrire(&d.join("agent.key"), kit.cle_agent.as_bytes())?;
    if let Some(o) = &kit.origine {
        ecrire_neuf(&d.join("etat-coffre-origine.json"), serde_json::to_string_pretty(o)?.as_bytes())?;
    }
    if let Some(e) = &kit.etat {
        ecrire_neuf(&d.join("etat-coffre.json"), serde_json::to_string_pretty(e)?.as_bytes())?;
    }
    ecrire_neuf_prive(&d.join("agent.secrets.json"), serde_json::to_string_pretty(&kit.secrets)?.as_bytes())?;
    let meta = serde_json::json!({ "agent_id": kit.agent_id, "nom": kit.nom, "publique": kit.publique, "proprietaire": kit.proprietaire, "regles": kit.regles, "reseau": kit.reseau, "installe_le": crate::double_auth::maintenant(), "secrets_du": kit.cree_le });
    ecrire_neuf(&d.join("agent.json"), serde_json::to_string_pretty(&meta)?.as_bytes())?;
    if registre_actif {
        inscrire_machine(&registre, &kit.proprietaire, &kit.publique, d)?;
    }
    Ok(kit.nom.clone())
}

/// Mise à jour des secrets côté agent. Le fichier exporté par la console peut voyager librement :
/// seul l'agent sait lire les secrets, et l'agent n'accepte que ce que SON propriétaire a signé pour
/// lui, jamais une version plus ancienne que celle déjà installée (R71).
pub fn maj_secrets(fichier: &str, dossier: &str) -> Res<usize> {
    let d = Path::new(dossier);
    let mut meta: Value = serde_json::from_str(&std::fs::read_to_string(d.join("agent.json"))?)?;
    let (secrets, n, date) = crate::secrets::verifier_export(
        &std::fs::read_to_string(fichier)?,
        meta["proprietaire"].as_str().unwrap_or(""),
        meta["publique"].as_str().unwrap_or(""),
        meta["secrets_du"].as_u64().unwrap_or(0),
    )?;
    let tmp = d.join("agent.secrets.json.nouveau");
    ecrire_neuf_prive(&tmp, serde_json::to_string_pretty(&secrets)?.as_bytes())?;
    std::fs::rename(tmp, d.join("agent.secrets.json"))?;
    meta["secrets_du"] = date.into();
    let tmp = d.join("agent.json.nouveau");
    ecrire_neuf(&tmp, serde_json::to_string_pretty(&meta)?.as_bytes())?;
    std::fs::rename(tmp, d.join("agent.json"))?;
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

    /// Kit de test (coût Argon2 minimal accepté) : agent de clé `[octet; 32]`.
    fn kit_de_test(octet: u8, id: &str) -> (Kit, secp256k1::Keypair) {
        let agent = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[octet; 32]).unwrap();
        let kit = Kit {
            agent_id: id.into(), nom: "Recherche".into(), cle_agent: hex::encode(agent.secret_bytes()), publique: hex::encode(agent.public_key().serialize()),
            proprietaire: hex::encode(proprietaire_de_test().x_only_public_key().0.serialize()), regles: None, origine: None, etat: Some(serde_json::json!({ "x": 1 })), secrets: serde_json::json!({}), reseau: "testnet-10".into(), cree_le: 1_000,
        };
        (kit, agent)
    }

    fn proprietaire_de_test() -> secp256k1::Keypair {
        secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x77; 32]).unwrap()
    }

    fn dossier_de_test(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("connexion-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Attaque : affaiblir le code de connexion. 20 symboles tirés uniformément parmi 31 = 99 bits ;
    /// aucun symbole ambigu, aucun biais visible sur 40 000 symboles.
    #[test]
    fn code_de_connexion_99_bits_sans_biais() {
        let mut vus = std::collections::BTreeSet::new();
        assert!(ALPHABET.iter().all(|c| vus.insert(*c)), "alphabet sans doublon");
        assert_eq!(ALPHABET.len(), 31);
        assert!(!ALPHABET.iter().any(|c| b"0O1IL".contains(c)));
        assert!((20.0 * (31f64).log2()) > 99.0);
        let mut compte = [0u32; 256];
        let mut codes = std::collections::BTreeSet::new();
        for _ in 0..2000 {
            let c = nouveau_code().unwrap();
            assert_eq!(c.split('-').map(str::len).collect::<Vec<_>>(), [5, 5, 5, 5]);
            for o in c.bytes().filter(|o| *o != b'-') {
                compte[o as usize] += 1;
            }
            assert!(codes.insert(c.to_string()), "code répété");
        }
        let attendu = 2000.0 * 20.0 / 31.0; // ≈ 1290 par symbole
        for c in ALPHABET {
            let n = compte[*c as usize] as f64;
            assert!((n - attendu).abs() < 6.0 * attendu.sqrt(), "symbole {} biaisé : {n} pour {attendu}", *c as char);
        }
    }

    /// Attaques sur le kit : paramètres de dérivation imposés par un kit forgé, substitution de
    /// l'en-tête (autre agent, autre clé publique), kit d'un autre agent, messages d'erreur.
    #[test]
    fn kit_forge_substitue_ou_affaibli_refuse() {
        let code = "ABCDE-FGHJK-MNPQR-STUVW";
        let (kit, agent) = kit_de_test(11, "ag-aaaaaaaaaaaa");
        let s = sceller(&kit, code).unwrap();
        assert_eq!((s.m_kio, s.t, s.p), (64 * 1024, 3, 1), "paramètres de scellement");
        // paramètres faibles ou démesurés annoncés par le kit : refusés avant toute dérivation
        for (m, t, p) in [(8, 1, 1), (19 * 1024 - 1, 3, 1), (64 * 1024, 1, 1), (64 * 1024, 3, 0), (2 * 1024 * 1024, 3, 1), (64 * 1024, 11, 1), (64 * 1024, 3, 9)] {
            let mut f = s.clone();
            (f.m_kio, f.t, f.p) = (m, t, p);
            let debut = std::time::Instant::now();
            assert!(ouvrir(&f, code).err().unwrap().to_string().contains("paramètres refusés"), "{m}/{t}/{p}");
            assert!(debut.elapsed() < std::time::Duration::from_millis(50), "refus sans calcul");
        }
        // paramètres valides mais différents de ceux du scellement : la clé dérivée change, refus
        let mut f = s.clone();
        f.m_kio = 19 * 1024;
        assert!(ouvrir(&f, code).is_err());
        for (champ, valeur) in [("kdf", "argon2i"), ("format", "kaspa-agent-vault/kit-connexion/v0")] {
            let mut j = serde_json::to_value(&s).unwrap();
            j[champ] = valeur.into();
            assert!(ouvrir(&serde_json::from_value(j).unwrap(), code).is_err(), "{champ}");
        }
        // substitution de l'en-tête : autre agent, autre clé publique, limite agent/clé déplacée
        let (kit_b, agent_b) = kit_de_test(12, "ag-bbbbbbbbbbbb");
        let sb = sceller(&kit_b, code).unwrap();
        for (id, publique) in [(sb.agent_id.clone(), s.publique.clone()), (s.agent_id.clone(), sb.publique.clone()), (format!("{}/{}", s.agent_id, &s.publique[..4]), s.publique[5..].to_string())] {
            let mut f = s.clone();
            (f.agent_id, f.publique) = (id, publique);
            assert!(ouvrir(&f, code).is_err(), "en-tête substitué");
        }
        // chiffré de B sous l'en-tête de A (même code) : refusé
        let mut f = s.clone();
        (f.sel, f.nonce, f.chiffre) = (sb.sel.clone(), sb.nonce.clone(), sb.chiffre.clone());
        assert!(ouvrir(&f, code).is_err(), "kit d'un autre agent");
        // kit scellé par un attaquant : clé privée qui ne correspond pas à la clé publique annoncée
        let mut menteur = kit_de_test(11, "ag-aaaaaaaaaaaa").0;
        menteur.cle_agent = hex::encode(agent_b.secret_bytes());
        let e = ouvrir(&sceller(&menteur, code).unwrap(), code).err().unwrap().to_string();
        assert!(e.contains("incohérent") && !e.contains(&menteur.cle_agent), "{e}");
        // le nom de l'en-tête n'est pas authentifié : il ne sert à rien, le nom installé vient du chiffré
        let mut f = s.clone();
        f.nom = "Autre nom\u{1b}[2J".into();
        assert_eq!(ouvrir(&f, code).unwrap().nom, "Recherche");
        // aucun message d'erreur ne cite le code, la clé ou le chiffré
        let cle_hex = hex::encode(agent.secret_bytes());
        for e in [ouvrir(&s, "AAAAA-AAAAA-AAAAA-AAAAZ").err().unwrap().to_string(), ouvrir(&f, "").err().unwrap().to_string()] {
            assert!(!e.contains("AAAAZ") && !e.contains(code) && !e.contains(&cle_hex) && !e.contains(&s.chiffre), "{e}");
        }
        // ni le kit scellé ni son affichage ne contiennent la clé ou le code
        let brut = serde_json::to_string(&s).unwrap();
        assert!(!brut.contains(&cle_hex) && !brut.contains(code) && !brut.contains(&code.replace('-', "")));
    }

    /// Attaques sur l'installation : lien symbolique à la place de la clé, fichiers lisibles par
    /// d'autres, écrasement, effacement réel de la copie de la console (même par un lien physique).
    // Unix seulement : le test fabrique des liens symboliques et physiques, ce qui demande un droit
    // particulier sous Windows (mode développeur ou administrateur). Les droits des fichiers installés
    // sont contrôlés sur tous les systèmes par `kit_scelle_installe_et_verifie` et par `prive`.
    #[cfg(unix)]
    #[test]
    fn installation_cle_privee_jamais_exposee() {
        use std::os::unix::fs::PermissionsExt;
        let code = "ABCDE-FGHJK-MNPQR-STUVW";
        let d = dossier_de_test("installation");
        let (kit, agent) = kit_de_test(13, "ag-cccccccccccc");
        let s = sceller(&kit, code).unwrap();
        let cle_hex = hex::encode(agent.secret_bytes());
        // lien symbolique pendant « agent.key » vers un fichier lisible par l'attaquant : refus, rien n'est écrit
        let piege = d.join("piege");
        std::fs::create_dir_all(&piege).unwrap();
        std::os::unix::fs::symlink(d.join("vole.txt"), piege.join("agent.key")).unwrap();
        assert!(installer_demo(&s, code, &piege.to_string_lossy()).is_err());
        assert!(!d.join("vole.txt").exists(), "la clé ne suit pas un lien symbolique");
        // installation normale : la clé en 0600, et la clé privée dans aucun autre fichier
        let dossier = d.join("agent");
        installer_demo(&s, code, &dossier.to_string_lossy()).unwrap();
        for f in std::fs::read_dir(&dossier).unwrap().map(|f| f.unwrap()) {
            let nom = f.file_name().to_string_lossy().into_owned();
            let contenu = std::fs::read_to_string(f.path()).unwrap();
            if nom == "agent.key" {
                assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            } else {
                assert!(!contenu.contains(&cle_hex), "clé privée dans {nom}");
                assert_eq!(f.metadata().unwrap().permissions().mode() & 0o022, 0, "{nom} modifiable par d'autres");
            }
        }
        // une seconde installation n'écrase rien, même avec un autre kit
        let (kit2, _) = kit_de_test(14, "ag-dddddddddddd");
        assert!(installer_demo(&sceller(&kit2, code).unwrap(), code, &dossier.to_string_lossy()).is_err());
        assert_eq!(std::fs::read_to_string(dossier.join("agent.key")).unwrap(), cle_hex);
        // effacement côté console : le contenu est réécrit sur place (un lien physique ne garde rien)
        let copie = d.join("console.key");
        std::fs::write(&copie, &cle_hex).unwrap();
        std::fs::hard_link(&copie, d.join("lien-physique")).unwrap();
        effacer_fichier(&copie.to_string_lossy()).unwrap();
        assert!(!copie.exists());
        assert!(std::fs::read(d.join("lien-physique")).unwrap().iter().all(|o| *o == 0), "contenu réellement effacé");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// R69 : dans un dossier préparé par quelqu'un d'autre, un lien symbolique à la place d'un
    /// fichier de l'agent (agent.json, état, secrets) ne doit pas faire écrire l'installation ailleurs.
    // Unix seulement : créer un lien symbolique demande un droit particulier sous Windows (mode
    // développeur ou administrateur), absent d'un poste ordinaire.
    #[cfg(unix)]
    #[test]
    fn r69_installation_ne_suit_pas_les_liens_symboliques() {
        let code = "ABCDE-FGHJK-MNPQR-STUVW";
        let d = dossier_de_test("r69");
        let (kit, _) = kit_de_test(15, "ag-eeeeeeeeeeee");
        let s = sceller(&kit, code).unwrap();
        let dossier = d.join("agent");
        std::fs::create_dir_all(&dossier).unwrap();
        for (f, cible) in [("agent.json", "cible-1"), ("etat-coffre.json", "cible-2"), ("agent.secrets.json", "cible-3")] {
            std::fs::write(d.join(cible), "fichier de la victime").unwrap();
            std::os::unix::fs::symlink(d.join(cible), dossier.join(f)).unwrap();
        }
        installer_demo(&s, code, &dossier.to_string_lossy()).unwrap();
        for cible in ["cible-1", "cible-2", "cible-3"] {
            assert_eq!(std::fs::read_to_string(d.join(cible)).unwrap(), "fichier de la victime", "{cible} écrasé à travers un lien symbolique");
        }
        for f in ["agent.json", "etat-coffre.json", "agent.secrets.json"] {
            assert!(!std::fs::symlink_metadata(dossier.join(f)).unwrap().file_type().is_symlink(), "{f} est un vrai fichier");
        }
        // même règle pour la mise à jour des secrets
        std::fs::remove_file(dossier.join("agent.secrets.json")).unwrap();
        std::os::unix::fs::symlink(d.join("cible-3"), dossier.join("agent.secrets.json.nouveau")).unwrap();
        let cle_console = d.join("console-ag.key").to_string_lossy().into_owned();
        let agent_pub = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[15; 32]).unwrap().public_key();
        std::fs::write(d.join("export.json"), serde_json::to_string(&crate::secrets::exporter(&proprietaire_de_test(), &agent_pub, &cle_console, 2_000).unwrap()).unwrap()).unwrap();
        maj_secrets(&d.join("export.json").to_string_lossy(), &dossier.to_string_lossy()).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("cible-3")).unwrap(), "fichier de la victime");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// R71 : le fichier de secrets « peut voyager librement » : il est donc à la merci de qui le
    /// transporte. Quiconque connaît la clé publique de l'agent (elle est publique) peut fabriquer des
    /// secrets que l'agent sait déchiffrer : sans signature du propriétaire, l'agent les installerait
    /// (clé d'API de l'attaquant à la place de la bonne, ou retour à une ancienne clé révoquée).
    #[test]
    fn r71_secrets_forges_par_un_tiers_refuses() {
        let code = "ABCDE-FGHJK-MNPQR-STUVW";
        let d = dossier_de_test("r71");
        let (kit, agent) = kit_de_test(16, "ag-ffffffffffff");
        let dossier = d.join("agent").to_string_lossy().into_owned();
        installer_demo(&sceller(&kit, code).unwrap(), code, &dossier).unwrap();
        // l'attaquant ne connaît que la clé publique de l'agent
        let forge = crate::secrets::chiffrer(&agent.public_key(), "OpenAI", "openai", Zeroizing::new("sk-cle-de-l-attaquant".into()), 1).unwrap();
        let fichier = d.join("secrets-forges.json");
        std::fs::write(&fichier, serde_json::json!({ "OpenAI": forge }).to_string()).unwrap();
        assert!(maj_secrets(&fichier.to_string_lossy(), &dossier).is_err(), "secrets non signés par le propriétaire : refus");
        assert!(verifier(&dossier).unwrap().is_empty(), "rien n'a été installé");
        // le vrai export de la console, signé par le propriétaire : accepté
        let cle_console = d.join("console-ag.key").to_string_lossy().into_owned();
        crate::secrets::enregistrer(&cle_console, &agent.public_key(), "OpenAI", "openai", Zeroizing::new("sk-test-la-bonne".into())).unwrap();
        let ecrire = |nom: &str, e: &crate::secrets::Export| {
            let f = d.join(nom);
            std::fs::write(&f, serde_json::to_string(e).unwrap()).unwrap();
            f.to_string_lossy().into_owned()
        };
        let bon = crate::secrets::exporter(&proprietaire_de_test(), &agent.public_key(), &cle_console, 2_000).unwrap();
        // … mais pas s'il est signé par un autre que le propriétaire, modifié en route, ou destiné à un autre agent
        let intrus = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[0x78; 32]).unwrap();
        assert!(maj_secrets(&ecrire("intrus.json", &crate::secrets::exporter(&intrus, &agent.public_key(), &cle_console, 2_000).unwrap()), &dossier).is_err(), "signé par un autre");
        let mut modifie = crate::secrets::exporter(&proprietaire_de_test(), &agent.public_key(), &cle_console, 2_000).unwrap();
        modifie.charge = modifie.charge.replace("2000", "9000");
        assert!(maj_secrets(&ecrire("modifie.json", &modifie), &dossier).is_err(), "modifié en route");
        let (_, autre_agent) = kit_de_test(17, "ag-000000000000");
        assert!(maj_secrets(&ecrire("autre.json", &crate::secrets::exporter(&proprietaire_de_test(), &autre_agent.public_key(), &cle_console, 2_000).unwrap()), &dossier).unwrap_err().to_string().contains("autre agent"));
        assert!(verifier(&dossier).unwrap().is_empty(), "toujours rien d'installé");
        assert_eq!(maj_secrets(&ecrire("bon.json", &bon), &dossier).unwrap(), 1);
        assert_eq!(verifier(&dossier).unwrap(), vec![("OpenAI".to_string(), true)]);
        assert_eq!(crate::secrets::lire_pour_agent(&format!("{dossier}/agent.key"), &agent, "OpenAI").unwrap().as_str(), "sk-test-la-bonne");
        // retour en arrière : un ancien export (clé révoquée depuis) n'est plus accepté
        crate::secrets::enregistrer(&cle_console, &agent.public_key(), "OpenAI", "openai", Zeroizing::new("sk-test-la-nouvelle".into())).unwrap();
        let recent = crate::secrets::exporter(&proprietaire_de_test(), &agent.public_key(), &cle_console, 3_000).unwrap();
        assert_eq!(maj_secrets(&ecrire("recent.json", &recent), &dossier).unwrap(), 1);
        assert!(maj_secrets(&ecrire("bon.json", &bon), &dossier).unwrap_err().to_string().contains("plus ancien"));
        assert_eq!(crate::secrets::lire_pour_agent(&format!("{dossier}/agent.key"), &agent, "OpenAI").unwrap().as_str(), "sk-test-la-nouvelle");
        // un export antérieur à l'installation du kit est refusé lui aussi
        let vieux = crate::secrets::exporter(&proprietaire_de_test(), &agent.public_key(), &cle_console, 999).unwrap();
        assert!(maj_secrets(&ecrire("vieux.json", &vieux), &dossier).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// R70 : un registre des mandats illisible (fichier tronqué ou abîmé) ne doit pas désactiver en
    /// silence la règle « un mandat par machine » (R52).
    #[test]
    fn r70_registre_illisible_refuse_au_lieu_de_tout_permettre() {
        let d = dossier_de_test("r70");
        let registre = d.join("mandats.json");
        let a = d.join("agent-a");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("agent.key"), "x").unwrap();
        inscrire_machine(&registre, "proprio", "pkA", &a).unwrap();
        let bon = std::fs::read_to_string(&registre).unwrap();
        std::fs::write(&registre, &bon[..bon.len() / 2]).unwrap(); // écriture interrompue
        let r = verifier_un_mandat_par_machine(&registre, "proprio", "pkB", &d.join("agent-b"));
        assert!(r.is_err(), "registre illisible : la règle ne doit pas sauter");
        assert!(r.unwrap_err().to_string().contains("illisible"));
        assert!(inscrire_machine(&registre, "proprio", "pkB", &d.join("agent-b")).is_err(), "et il n'est pas écrasé");
        // registre absent : première installation, permise
        std::fs::remove_file(&registre).unwrap();
        assert!(verifier_un_mandat_par_machine(&registre, "proprio", "pkB", &d.join("agent-b")).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
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
        for f in ["agent.key", "agent.secrets.json"] {
            let f = Path::new(&agent_dossier).join(f);
            assert!(crate::prive::est_prive(&f).unwrap(), "{} : {}", f.display(), crate::prive::droits(&f));
        }
        // côté console : effacement de la copie de la clé
        effacer_fichier(&console_cle).unwrap();
        assert!(!Path::new(&console_cle).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

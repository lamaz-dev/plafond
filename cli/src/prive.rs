//! Fichiers sensibles (clés, secrets) : un seul endroit pour les écrire, lisibles par le seul
//! utilisateur courant sur tous les systèmes.
//!
//!  - Unix : fichier créé avec les droits 0600.
//!  - Windows : il n'y a pas de droits 0600. Le fichier est créé avec une liste d'accès (ACL) protégée
//!    qui ne contient qu'une entrée, « contrôle total pour l'utilisateur courant » : rien n'est hérité
//!    du dossier. La liste est posée à la création même (`CreateFileW` avec un descripteur de
//!    sécurité), jamais après coup : le fichier n'existe à aucun moment avec des droits plus larges.
//!
//! Dans tous les cas le fichier est créé neuf (création exclusive) : jamais d'écrasement, et un lien
//! symbolique laissé à sa place n'est pas suivi.

use crate::Res;
use std::path::Path;

/// Crée un fichier sensible neuf, lisible et modifiable par le seul utilisateur courant.
pub fn creer(chemin: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(chemin)
    }
    #[cfg(windows)]
    {
        windows::creer(chemin)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::OpenOptions::new().write(true).create_new(true).open(chemin)
    }
}

/// Écrit `contenu` dans un fichier sensible neuf (voir `creer`) ; échoue si le fichier existe.
pub fn ecrire(chemin: &Path, contenu: &[u8]) -> Res<()> {
    use std::io::Write;
    let mut f = creer(chemin).map_err(|e| format!("{} : {e}", chemin.display()))?;
    f.write_all(contenu)?;
    f.sync_all()?;
    Ok(())
}

/// Restreint un fichier existant à l'utilisateur courant (copie de sauvegarde, par exemple).
pub fn proteger(chemin: &Path) -> Res<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    windows::proteger(chemin)?;
    #[cfg(not(any(unix, windows)))]
    let _ = chemin;
    Ok(())
}

/// Vrai si le fichier n'est accessible qu'à l'utilisateur courant (0600 sous Unix ; sous Windows,
/// liste d'accès protégée dont la seule entrée est l'utilisateur courant).
#[cfg_attr(not(test), allow(dead_code))]
pub fn est_prive(chemin: &Path) -> Res<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(std::fs::metadata(chemin)?.permissions().mode() & 0o777 == 0o600)
    }
    #[cfg(windows)]
    {
        Ok(windows::liste_privee(&windows::liste(chemin)?, &windows::liste_attendue()?))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(std::fs::metadata(chemin)?.is_file())
    }
}

/// Description lisible des droits du fichier, pour les messages des tests.
#[cfg(test)]
pub fn droits(chemin: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(chemin).map(|m| format!("{:o}", m.permissions().mode() & 0o777)).unwrap_or_else(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        windows::liste(chemin).unwrap_or_else(|e| e.to_string())
    }
    #[cfg(not(any(unix, windows)))]
    {
        chemin.display().to_string()
    }
}

#[cfg(windows)]
mod windows {
    use std::io::{Error, Result};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn large(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// Chaîne UTF-16 terminée par zéro, rendue par le système.
    unsafe fn texte(p: *const u16) -> String {
        let mut n = 0;
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
    }

    /// Identifiant de sécurité (SID) de l'utilisateur qui exécute le programme, sous forme de texte.
    fn sid_courant() -> Result<String> {
        unsafe {
            let mut jeton: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) == 0 {
                return Err(Error::last_os_error());
            }
            let mut tampon = [0u64; 64]; // 512 octets, alignés pour TOKEN_USER
            let mut lu = 0u32;
            let ok = GetTokenInformation(jeton, TokenUser, tampon.as_mut_ptr().cast(), std::mem::size_of_val(&tampon) as u32, &mut lu);
            let erreur = Error::last_os_error();
            CloseHandle(jeton);
            if ok == 0 {
                return Err(erreur);
            }
            let utilisateur = &*(tampon.as_ptr() as *const TOKEN_USER);
            let mut p: *mut u16 = null_mut();
            if ConvertSidToStringSidW(utilisateur.User.Sid, &mut p) == 0 {
                return Err(Error::last_os_error());
            }
            let sid = texte(p);
            LocalFree(p.cast());
            Ok(sid)
        }
    }

    /// Descripteur de sécurité « utilisateur courant seul, rien d'hérité », libéré à la sortie de portée.
    struct Descripteur(PSECURITY_DESCRIPTOR);

    impl Drop for Descripteur {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    fn descripteur() -> Result<Descripteur> {
        // D:P = liste d'accès protégée (aucun héritage) ; une entrée : accès complet (FA) à l'utilisateur.
        let sddl = large(std::ffi::OsStr::new(&format!("D:P(A;;FA;;;{})", sid_courant()?)));
        let mut d: PSECURITY_DESCRIPTOR = null_mut();
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut d, null_mut()) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(Descripteur(d))
    }

    pub fn creer(chemin: &Path) -> Result<std::fs::File> {
        let d = descripteur()?;
        let attributs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: d.0, bInheritHandle: 0 };
        let nom = large(chemin.as_os_str());
        let h = unsafe { CreateFileW(nom.as_ptr(), GENERIC_WRITE, 0, &attributs, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, null_mut()) };
        if h == INVALID_HANDLE_VALUE {
            return Err(Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h as _) })
    }

    pub fn proteger(chemin: &Path) -> Result<()> {
        let d = descripteur()?;
        let (mut presente, mut par_defaut) = (0, 0);
        let mut acl: *mut ACL = null_mut();
        if unsafe { GetSecurityDescriptorDacl(d.0, &mut presente, &mut acl, &mut par_defaut) } == 0 || presente == 0 || acl.is_null() {
            return Err(Error::other("liste d'accès introuvable"));
        }
        let nom = large(chemin.as_os_str());
        let e = unsafe { SetNamedSecurityInfoW(nom.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null_mut(), null_mut(), acl, null_mut()) };
        if e != 0 {
            return Err(Error::from_raw_os_error(e as i32));
        }
        Ok(())
    }

    /// Liste d'accès du fichier au format texte du système (SDDL), par exemple `D:P(A;;FA;;;S-1-5-21-…)`.
    pub fn liste(chemin: &Path) -> Result<String> {
        let nom = large(chemin.as_os_str());
        let mut d: PSECURITY_DESCRIPTOR = null_mut();
        let e = unsafe { GetNamedSecurityInfoW(nom.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null_mut(), null_mut(), null_mut(), null_mut(), &mut d) };
        if e != 0 {
            return Err(Error::from_raw_os_error(e as i32));
        }
        en_texte(&Descripteur(d))
    }

    /// La liste « utilisateur courant seul », telle que le système l'écrit lui-même : il remplace
    /// certains identifiants par un alias (`LA` pour le compte administrateur intégré, par exemple),
    /// si bien qu'on ne peut pas comparer avec l'identifiant écrit en toutes lettres.
    pub fn liste_attendue() -> Result<String> {
        en_texte(&descripteur()?)
    }

    fn en_texte(d: &Descripteur) -> Result<String> {
        let mut p: *mut u16 = null_mut();
        if unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(d.0, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut p, null_mut()) } == 0 {
            return Err(Error::last_os_error());
        }
        let s = unsafe { texte(p) };
        unsafe {
            LocalFree(p.cast());
        }
        Ok(s)
    }

    /// Vrai si la liste est protégée (pas d'héritage) et ne contient qu'une entrée, celle attendue :
    /// « accès complet pour l'utilisateur courant ». Les deux textes viennent du système lui-même.
    pub fn liste_privee(sddl: &str, attendue: &str) -> bool {
        let decouper = |s: &str| -> Option<(String, String)> {
            let reste = s.strip_prefix("D:")?;
            let debut = reste.find('(')?;
            Some((reste[..debut].to_string(), reste[debut..].to_string()))
        };
        let (Some((drapeaux, entrees)), Some((_, voulues))) = (decouper(sddl), decouper(attendue)) else { return false };
        drapeaux.contains('P') && entrees == voulues && entrees.matches('(').count() == 1 && entrees.starts_with("(A;;FA;;;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows (et Unix) : un fichier sensible n'est accessible qu'à l'utilisateur courant, dès sa
    /// création ; un fichier ordinaire, lui, hérite des droits du dossier, et `proteger` le restreint.
    #[test]
    fn fichier_sensible_lisible_par_le_seul_utilisateur() {
        let d = std::env::temp_dir().join(format!("plafond-prive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let secret = d.join("secret.key");
        ecrire(&secret, b"contenu secret").unwrap();
        assert!(est_prive(&secret).unwrap(), "droits du fichier sensible : {}", droits(&secret));
        assert_eq!(std::fs::read(&secret).unwrap(), b"contenu secret", "toujours lisible par son propriétaire");
        assert!(ecrire(&secret, b"autre").is_err(), "jamais d'écrasement");
        assert_eq!(std::fs::read(&secret).unwrap(), b"contenu secret");
        // un fichier écrit sans précaution n'est pas privé : c'est ce que `ecrire` et `proteger` évitent
        let ordinaire = d.join("ordinaire.txt");
        std::fs::write(&ordinaire, "x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ordinaire, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(!est_prive(&ordinaire).unwrap(), "droits du fichier ordinaire : {}", droits(&ordinaire));
        proteger(&ordinaire).unwrap();
        assert!(est_prive(&ordinaire).unwrap(), "droits après protection : {}", droits(&ordinaire));
        assert_eq!(std::fs::read_to_string(&ordinaire).unwrap(), "x");
        // un fichier privé se remplace et s'efface normalement
        std::fs::rename(&ordinaire, d.join("renomme.txt")).unwrap();
        assert!(est_prive(&d.join("renomme.txt")).unwrap());
        crate::connexion::effacer_fichier(&secret.to_string_lossy()).unwrap();
        assert!(!secret.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

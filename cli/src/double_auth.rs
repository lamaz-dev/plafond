//! Double authentification (TOTP, RFC 6238) : codes à 6 chiffres renouvelés toutes les 30 s,
//! compatibles avec les applications d'authentification usuelles. Le secret est stocké chiffré
//! dans le fichier de clé du propriétaire (format v2), jamais en clair sur le disque.

use hmac::{Hmac, Mac};
use sha1::Sha1;

const PAS: u64 = 30;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32(octets: &[u8]) -> String {
    let (mut sortie, mut tampon, mut bits) = (String::new(), 0u32, 0u32);
    for &o in octets {
        tampon = (tampon << 8) | o as u32;
        bits += 8;
        while bits >= 5 {
            sortie.push(ALPHABET[((tampon >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        sortie.push(ALPHABET[((tampon << (5 - bits)) & 31) as usize] as char);
    }
    sortie
}

/// Code à 6 chiffres pour le pas de temps `pas` (= secondes Unix / 30).
pub fn code(secret: &[u8], pas: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepte toute longueur");
    mac.update(&pas.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let d = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[d] & 0x7f, h[d + 1], h[d + 2], h[d + 3]]);
    n % 1_000_000
}

pub fn maintenant() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Vérifie un code saisi (tolérance d'un pas de part et d'autre pour le décalage d'horloge).
/// Renvoie le pas accepté, pour refuser qu'un même code serve deux fois (`dernier_pas`).
pub fn verifier(secret: &[u8], saisi: &str, instant: u64, dernier_pas: u64) -> Option<u64> {
    let saisi = saisi.trim().replace(' ', "");
    if saisi.len() != 6 || !saisi.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let valeur: u32 = saisi.parse().ok()?;
    let p = instant / PAS;
    [p.saturating_sub(1), p, p + 1].into_iter().find(|&q| q > dernier_pas && code(secret, q) == valeur)
}

pub fn nouveau_secret() -> crate::Res<Vec<u8>> {
    let mut s = vec![0u8; 20];
    getrandom::getrandom(&mut s).map_err(|e| format!("aléa : {e}"))?;
    Ok(s)
}

/// Lien à scanner par l'application d'authentification.
pub fn lien(secret: &[u8], compte: &str) -> String {
    let emetteur = "Tresorerie%20des%20agents";
    format!("otpauth://totp/{emetteur}:{compte}?secret={}&issuer={emetteur}&algorithm=SHA1&digits=6&period=30", base32(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vecteurs_rfc6238_et_base32() {
        let s = b"12345678901234567890";
        // RFC 6238, annexe B (SHA-1) : 94287082 à T=59, 07081804 à T=1111111109 (6 derniers chiffres).
        assert_eq!(code(s, 59 / 30), 287082);
        assert_eq!(code(s, 1111111109 / 30), 81804);
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn verification_fenetre_et_rejeu() {
        let s = b"12345678901234567890";
        let t = 1111111109;
        let c = format!("{:06}", code(s, t / 30));
        let pas = verifier(s, &c, t, 0).expect("code valide");
        assert!(verifier(s, &c, t, pas).is_none(), "un code ne sert qu'une fois");
        assert!(verifier(s, &c, t + 30, 0).is_some(), "tolérance d'un pas");
        assert!(verifier(s, &c, t + 120, 0).is_none(), "code expiré");
        assert!(verifier(s, "12a456", t, 0).is_none());
    }
}

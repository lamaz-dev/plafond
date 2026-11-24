//! Sobriété : Plafond ne doit jamais encombrer la machine qui l'héberge.
//! - mémoire plafonnée (PLAFOND_MEMOIRE_MO, défaut 512 Mo) : au-delà, arrêt net plutôt que de
//!   prendre la mémoire des autres programmes (les fichiers sont écrits par renommage atomique) ;
//! - deux fils d'exécution au plus (voir `main`) et priorité basse pour la console et la démo ;
//! - journaux bornés (1 Mo, on garde la moitié la plus récente) ;
//! - nettoyage au démarrage : écritures interrompues (`*.nouveau`) et vieux rapports de démo.
//!   Jamais les clés, le compte ni les sauvegardes `.ancien-*`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const JOURNAL_MAX: u64 = 1 << 20;
const RAPPORTS_GARDES: usize = 5;

pub struct Plafonne;
static UTILISE: AtomicUsize = AtomicUsize::new(0);
static LIMITE: AtomicUsize = AtomicUsize::new(512 << 20);

unsafe impl GlobalAlloc for Plafonne {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if UTILISE.fetch_add(l.size(), Ordering::Relaxed) + l.size() > LIMITE.load(Ordering::Relaxed) {
            UTILISE.fetch_sub(l.size(), Ordering::Relaxed);
            return std::ptr::null_mut();
        }
        let p = unsafe { System.alloc(l) };
        if p.is_null() {
            UTILISE.fetch_sub(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        UTILISE.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

/// Lit PLAFOND_MEMOIRE_MO (64 Mo au minimum).
pub fn regler_memoire() {
    if let Some(mo) = std::env::var("PLAFOND_MEMOIRE_MO").ok().and_then(|v| v.parse::<usize>().ok()) {
        LIMITE.store(mo.max(64) << 20, Ordering::Relaxed);
    }
}

/// Priorité basse pour ce processus (PLAFOND_PRIORITE=normale pour s'en passer). Sans dépendance :
/// un outil du système, lancé en arrière-plan ; un échec est sans conséquence.
pub fn priorite_basse() {
    if std::env::var("PLAFOND_PRIORITE").is_ok_and(|v| v == "normale") {
        return;
    }
    let pid = std::process::id().to_string();
    let mut c = if cfg!(windows) {
        let mut c = std::process::Command::new("powershell");
        c.args(["-NoProfile", "-NonInteractive", "-Command", &format!("(Get-Process -Id {pid}).PriorityClass='BelowNormal'")]);
        c
    } else {
        let mut c = std::process::Command::new("renice");
        c.args(["-n", "10", "-p", &pid]);
        c
    };
    let _ = c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

/// Garde un journal sous `max` octets : au-delà, on ne conserve que la moitié la plus récente.
pub fn borner(chemin: &str, max: u64) {
    if std::fs::metadata(chemin).map(|m| m.len() <= max).unwrap_or(true) {
        return;
    }
    let Ok(texte) = std::fs::read_to_string(chemin) else { return };
    let debut = texte.len() - (max / 2) as usize;
    let reste = texte[debut..].split_once('\n').map(|(_, r)| r).unwrap_or("");
    let tmp = format!("{chemin}.nouveau");
    if std::fs::write(&tmp, reste).is_ok() {
        let _ = std::fs::rename(&tmp, chemin);
    }
}

/// Nettoyage au démarrage, dans les dossiers donnés (non récursif).
pub fn nettoyer(dossiers: &[&Path]) {
    let heure = std::time::Duration::from_secs(3600);
    for d in dossiers {
        let Ok(lecture) = std::fs::read_dir(d) else { continue };
        let mut rapports = vec![];
        for e in lecture.flatten() {
            let nom = e.file_name().to_string_lossy().into_owned();
            let age = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
            if nom.ends_with(".nouveau") && age.is_some_and(|a| a > heure) {
                let _ = std::fs::remove_file(e.path());
            } else if nom.starts_with("demo-rapport-") && nom.ends_with(".json") {
                rapports.push(nom);
            }
        }
        rapports.sort(); // horodatage dans le nom : ordre chronologique
        for vieux in rapports.iter().rev().skip(RAPPORTS_GARDES) {
            let _ = std::fs::remove_file(d.join(vieux));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_borne_et_nettoyage_prudent() {
        let d = std::env::temp_dir().join(format!("plafond-sobriete-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let j = d.join("j.jsonl");
        let lignes: String = (0..5000).map(|i| format!("{{\"n\":{i}}}\n")).collect();
        std::fs::write(&j, &lignes).unwrap();
        borner(j.to_str().unwrap(), 10_000);
        let reste = std::fs::read_to_string(&j).unwrap();
        assert!(reste.len() <= 5_000 && reste.ends_with("{\"n\":4999}\n") && reste.starts_with("{\"n\":"));
        for i in 0..8 {
            std::fs::write(d.join(format!("demo-rapport-17000000{i}.json")), "{}").unwrap();
        }
        for garde in ["proprietaire.json", "agent-principal.key", "proprietaire.json.ancien-1", "frais.nouveau"] {
            std::fs::write(d.join(garde), "x").unwrap();
        }
        nettoyer(&[&d]);
        let noms: Vec<String> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(noms.iter().filter(|n| n.starts_with("demo-rapport-")).count(), 5);
        assert!(noms.contains(&"demo-rapport-170000007.json".to_string()) && !noms.contains(&"demo-rapport-170000000.json".to_string()));
        // clés, compte et sauvegardes intacts ; un fichier .nouveau récent (écriture en cours) aussi
        for garde in ["proprietaire.json", "agent-principal.key", "proprietaire.json.ancien-1", "frais.nouveau"] {
            assert!(noms.contains(&garde.to_string()), "{garde} supprimé");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}

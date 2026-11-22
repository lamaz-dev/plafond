//! Démonstration de bout en bout, reproductible, sur le réseau de test : les 7 étapes qu'un DSI veut
//! voir, chacune contrôlée. `vault-cli demo` (clés du propriétaire comme pour la console). Pendant la
//! démo, la console ouverte à côté montre les changements en direct (même registre d'agents).
//!
//! 1. créer un agent · 2. lui attribuer un budget (ouverture de son coffre) · 3. lui donner un secret ·
//! 4. le connecter (sa clé passe sur « son serveur », la console l'efface) · 5. il paie un service ·
//! 6. il tente de dépasser son budget : le réseau refuse · 7. arrêt d'urgence : les fonds reviennent.

use crate::*;
use std::time::{Duration, Instant};

fn bloquant<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

fn unites(s: i64) -> String {
    format!("{:.4}", s as f64 / 1e8)
}

async fn solde(c: &KaspaRpcClient, k: &Keypair) -> Res<u64> {
    Ok(c.get_utxos_by_addresses(vec![address(k)]).await?.iter().map(|u| u.utxo_entry.amount).sum())
}

/// Attend que la dernière sortie du coffre soit inscrite (un paiement enchaîné non confirmé est refusé
/// par le contrat : c'est voulu).
async fn attendre_inscription(owner_pk: &[u8], agent: &Keypair, quoi: &str) -> Res<()> {
    let debut = Instant::now();
    let c = connect_silencieux().await?;
    loop {
        if let Ok(e) = load_state() {
            if creation_coffre(&c, owner_pk, agent, &e).await.is_ok() {
                c.disconnect().await?;
                return Ok(());
            }
        }
        if debut.elapsed() > Duration::from_secs(120) {
            c.disconnect().await?;
            return Err(format!("{quoi} : pas inscrit après 120 s").into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

struct Etape {
    numero: u8,
    titre: &'static str,
    ok: bool,
    detail: String,
}

pub async fn lancer(owner: Keypair, principal: Keypair) -> Res<()> {
    let defaut = etat_par_defaut();
    let mut etapes: Vec<Etape> = Vec::new();
    let mut note = |numero, titre, ok, detail: String| {
        println!("\n[{numero}/7] {titre} : {}\n      {detail}", if ok { "OK" } else { "ÉCHEC" });
        etapes.push(Etape { numero, titre, ok, detail });
        ok
    };
    // Paramètres : 2 unités par jour, 0,5 au plus par achat → exposition immédiate 0,5.
    let regles = Regles::calculer(200_000_000, JOUR_DAA, 50_000_000)?;
    // Aucune dépendance à un indexeur : seule la chaîne du nœud sert à retrouver le coffre.
    NOEUD_SEUL.store(true, std::sync::atomic::Ordering::Relaxed);
    let c = connect().await?;
    let tresorerie_avant = solde(&c, &owner).await?;
    let besoin = regles.depot + 10_000_000;
    println!("Trésorerie du propriétaire : {} unités (il en faut {} pour la démo)", unites(tresorerie_avant as i64), unites(besoin as i64));
    if tresorerie_avant < besoin {
        return Err(format!("trésorerie insuffisante : approvisionnez {} sur le réseau de test (distributeur : https://faucet-tn10.kaspanet.io/)", address(&owner)).into());
    }
    let service = address(&payee(&owner));
    c.disconnect().await?;

    // 1. Créer un agent
    let nom = format!("Démo DSI {}", double_auth::maintenant() % 100_000);
    let a = agents::nouveau(&defaut, &nom, Some(regles))?;
    let pub_agent = agents::xonly_pub(&a, &principal);
    note(1, "Créer un agent", true, format!("« {nom} » ({})", a.id));

    // 2. Lui attribuer un budget : ouverture de son coffre
    let k = agents::cle(&a, &principal)?;
    let r = avec_coffre(&a.etat, a.regles, pub_agent, || bloquant(deployer(&owner, &k)));
    let ok = match &r {
        Ok(tx) => note(2, "Lui attribuer un budget", true, format!("2 unités par jour, 0,5 au plus par achat ; perte maximale immédiate {} ; coffre ouvert : {}", unites(regles.capacite), explorer(tx))),
        Err(e) => note(2, "Lui attribuer un budget", false, e.to_string()),
    };
    if !ok {
        return bilan(&etapes);
    }

    // 3. Lui donner un secret
    let mut alea = [0u8; 16];
    getrandom::getrandom(&mut alea).map_err(|e| format!("aléa : {e}"))?;
    let valeur = zeroize::Zeroizing::new(format!("demo-{}", hex::encode(alea)));
    let base = agents::base_fichiers(&a, &defaut);
    secrets::enregistrer(&base, &agents::publique(&a, &principal)?, "Service démo", "autre", valeur)?;
    let fichier_secrets = std::fs::read_to_string(base.replace(".key", ".secrets.json")).unwrap_or_default();
    note(3, "Lui donner un secret", !fichier_secrets.contains("demo-"), "clé d'API enregistrée, chiffrée pour cet agent seul ; valeur absente du fichier et des journaux".into());

    // 4. Le connecter : sa clé passe sur « son serveur », la console l'efface
    let (kit, code) = console::preparer_kit(&a, &owner, &defaut)?;
    let serveur = std::path::Path::new(&defaut).parent().map(|p| p.to_path_buf()).unwrap_or_default().join("serveur-agent-demo").join(&a.id);
    let serveur = serveur.to_string_lossy().into_owned();
    connexion::installer(&kit, &code, &serveur)?;
    connexion::effacer_fichier(&a.cle)?;
    agents::marquer_connecte(&defaut, &a.id)?;
    let lisibles = connexion::verifier(&serveur)?;
    note(4, "Le connecter", lisibles.iter().all(|(_, ok)| *ok) && !std::path::Path::new(&a.cle).exists(),
        format!("clé installée côté agent ({serveur}), effacée de la console ; secrets lisibles par l'agent : {}", lisibles.len()));

    // L'agent travaille désormais depuis son dossier, avec sa propre clé.
    let cle_agent = Keypair::from_seckey_slice(secp256k1::SECP256K1, &zeroize::Zeroizing::new(hex::decode(std::fs::read_to_string(format!("{serveur}/agent.key"))?.trim())?))?;
    let etat_agent = format!("{serveur}/etat-coffre.json");
    let owner_pk = xonly(&owner);
    avec_coffre(&etat_agent, a.regles, None, || bloquant(attendre_inscription(&owner_pk, &cle_agent, "coffre")))?;

    // 5. Il paie un service (service de démonstration que nous opérons)
    let r = avec_coffre(&etat_agent, a.regles, None, || bloquant(crate::payer_agent(&owner_pk, &cle_agent, 30_000_000, &service, false)));
    let ok = match &r {
        Ok(tx) => note(5, "Payer un service", true, format!("0,3 unité payée au service de démonstration {service} : {}", explorer(tx))),
        Err(e) => note(5, "Payer un service", false, e.to_string()),
    };
    if !ok {
        return bilan(&etapes);
    }
    avec_coffre(&etat_agent, a.regles, None, || bloquant(attendre_inscription(&owner_pk, &cle_agent, "paiement")))?;

    // 6. Il tente de dépasser son budget : c'est le réseau qui refuse
    let r = avec_coffre(&etat_agent, a.regles, None, || bloquant(crate::payer_agent(&owner_pk, &cle_agent, 45_000_000, &service, true)));
    match &r {
        Err(e) if e.to_string().starts_with("REFUSÉ") => note(6, "Bloqué au-delà du budget", true, format!("0,45 unité demandée (sous le plafond par achat, au-delà du budget restant) : {e}")),
        Ok(tx) => note(6, "Bloqué au-delà du budget", false, format!("paiement accepté alors qu'il devait être refusé : {}", explorer(tx))),
        Err(e) => note(6, "Bloqué au-delà du budget", false, format!("erreur inattendue : {e}")),
    };

    // 7. Arrêt d'urgence depuis la console (état périmé côté console : le coffre est retrouvé sur le registre)
    let c = connect_silencieux().await?;
    let avant = solde(&c, &owner).await?;
    c.disconnect().await?;
    let k_console = agents::cle(&agents::charger(&defaut).into_iter().find(|x| x.id == a.id).ok_or("agent disparu du registre")?, &principal)?;
    let r = avec_coffre(&a.etat, a.regles, pub_agent, || bloquant(geler(&owner, &k_console, false, 0)));
    match &r {
        Ok(tx) => {
            // le gel peut mettre quelques secondes à être inscrit : on interroge jusqu'à 60 s
            let c = connect_silencieux().await?;
            let mut apres = solde(&c, &owner).await?;
            let debut = Instant::now();
            while apres <= avant && debut.elapsed() < Duration::from_secs(60) {
                tokio::time::sleep(Duration::from_secs(2)).await;
                apres = solde(&c, &owner).await?;
            }
            c.disconnect().await?;
            note(7, "Arrêt d'urgence", apres > avant, format!("fonds rapatriés dans la trésorerie : +{} unités ({})", unites(apres as i64 - avant as i64), explorer(tx)))
        }
        Err(e) => note(7, "Arrêt d'urgence", false, e.to_string()),
    };
    bilan(&etapes)
}

fn bilan(etapes: &[Etape]) -> Res<()> {
    println!("\n=== Bilan de la démonstration ===");
    for e in etapes {
        println!("{} {}. {}", if e.ok { "✓" } else { "✗" }, e.numero, e.titre);
    }
    let rapport = serde_json::json!({
        "date": double_auth::maintenant(),
        "reseau": "testnet-10",
        "etapes": etapes.iter().map(|e| serde_json::json!({ "numero": e.numero, "titre": e.titre, "ok": e.ok, "detail": e.detail })).collect::<Vec<_>>(),
    });
    let fichier = format!("demo-rapport-{}.json", double_auth::maintenant());
    std::fs::write(&fichier, serde_json::to_string_pretty(&rapport)?)?;
    println!("Rapport : {fichier}");
    if etapes.len() == 7 && etapes.iter().all(|e| e.ok) {
        println!("Les 7 étapes sont vérifiées.");
        Ok(())
    } else {
        Err("démonstration incomplète : voir le rapport".into())
    }
}

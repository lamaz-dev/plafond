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

/// Attend que les pièces du coffre soient inscrites (un paiement depuis une pièce non confirmée est
/// refusé par le réseau : c'est voulu, le verrou relatif court depuis l'inscription).
async fn attendre_inscription(owner_pk: &[u8], agent: &Keypair, quoi: &str) -> Res<()> {
    let debut = Instant::now();
    let c = connect_silencieux().await?;
    loop {
        if let Ok(v) = coffre::vue(&c, owner_pk, &xonly(agent)).await {
            if !v.pieces.is_empty() && v.pieces.iter().all(|p| p.creation.is_some()) {
                liberer(&c).await?;
                return Ok(());
            }
        }
        if debut.elapsed() > Duration::from_secs(120) {
            liberer(&c).await?;
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

/// Clés jetables de la démo : créées une fois sur cet ordinateur (fichier lisible par ce seul compte),
/// réutilisées ensuite pour ne pas redemander de jetons de test. Réseau de test uniquement ; aucune
/// phrase à fournir. Tout le travail de la démo reste dans `demo-jetable/` (supprimable à tout moment).
pub fn cles_jetables() -> Res<(Keypair, Keypair)> {
    const DOSSIER: &str = "demo-jetable";
    let chemin = format!("{DOSSIER}/cles-test.json");
    *ETAT_DEFAUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("{DOSSIER}/etat-coffre.json"));
    let lire = |v: &serde_json::Value, k: &str| -> Res<Keypair> {
        let b = hex::decode(v[k].as_str().ok_or("fichier de clés de démo illisible")?)?;
        Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &b)?)
    };
    if let Ok(t) = std::fs::read_to_string(&chemin) {
        let v: serde_json::Value = serde_json::from_str(&t)?;
        println!("Clés de démo (réseau de test) : {chemin}");
        return Ok((lire(&v, "proprietaire")?, lire(&v, "agent")?));
    }
    let nouvelle = || -> Res<Keypair> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| format!("aléa : {e}"))?;
        Ok(Keypair::from_seckey_slice(secp256k1::SECP256K1, &b)?)
    };
    let (o, a) = (nouvelle()?, nouvelle()?);
    std::fs::create_dir_all(DOSSIER)?;
    let contenu = serde_json::json!({
        "avertissement": "Clés jetables du réseau de test (testnet-10), sans valeur. Ne jamais y envoyer de fonds réels.",
        "proprietaire": hex::encode(o.secret_bytes()),
        "agent": hex::encode(a.secret_bytes()),
    });
    let mut f = std::fs::OpenOptions::new();
    f.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut f, 0o600);
    std::io::Write::write_all(&mut f.open(&chemin)?, serde_json::to_string_pretty(&contenu)?.as_bytes())?;
    println!("Clés de démo créées pour le réseau de test : {chemin} (aucune phrase à fournir)");
    Ok((o, a))
}

/// Trésorerie insuffisante : afficher l'adresse, un QR code et le montant exact, puis attendre les fonds.
async fn attendre_fonds(c: &KaspaRpcClient, owner: &Keypair, besoin: u64) -> Res<u64> {
    let adr = address(owner).to_string();
    let manque = besoin.saturating_sub(solde(c, owner).await?);
    println!("\nIl faut des jetons de test (gratuits) sur cette adresse, au moins {} unités de plus :\n\n  {adr}\n", unites(manque as i64));
    if let Ok(q) = qrcode::QrCode::new(adr.as_bytes()) {
        println!("{}", q.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build());
    }
    println!("Distributeur du réseau de test : https://faucet-tn10.kaspanet.io/ (collez l'adresse, validez).");
    println!("La démo reprend toute seule dès que les fonds arrivent (attente maximale : 20 min ; Ctrl+C pour abandonner).");
    let debut = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = solde(c, owner).await?;
        if s >= besoin {
            println!("Fonds reçus : {} unités.", unites(s as i64));
            return Ok(s);
        }
        if debut.elapsed() > Duration::from_secs(1200) {
            return Err(format!("fonds non reçus après 20 min sur {adr} (distributeur indisponible ?) ; relancer la démo plus tard, l'adresse reste la même").into());
        }
    }
}

pub async fn lancer(owner: Keypair, principal: Keypair) -> Res<()> {
    // La console s'ouvre dans le même programme : un seul terminal, rien à recopier.
    if std::env::var("DEMO_SANS_NAVIGATEUR").is_err() {
        console::OUVRIR_NAVIGATEUR.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let console_ouverte = {
        let (h, o, a) = (tokio::runtime::Handle::current(), owner, principal);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Err(e) = console::lancer(h, o, a) {
                eprintln!("(console non ouverte : {e})");
                let _ = tx.send(());
            }
        });
        tokio::time::sleep(Duration::from_millis(800)).await;
        rx.try_recv().is_err()
    };
    if !console_ouverte {
        return Err("la console ne s'est pas ouverte (port 8404 déjà occupé par une autre console ?) : fermez-la puis relancez ; aucune opération n'a été faite".into());
    }
    println!("La console s'ouvre dans votre navigateur (sinon, ouvrez le lien ci-dessus) : c'est l'écran à filmer.\n");
    let mut etapes: Vec<Etape> = Vec::new();
    if let Err(e) = derouler(owner, principal, &mut etapes).await {
        eprintln!("\n✗ Démo interrompue : {e}");
        let numero = etapes.len() as u8 + 1;
        etapes.push(Etape { numero, titre: "Interruption", ok: false, detail: e.to_string() });
    }
    let _ = bilan(&etapes);
    println!("\nLa console reste ouverte pour consulter le résultat. Ctrl+C pour quitter.");
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

/// Déroule les 7 étapes en les notant dans `etapes`. Toute erreur interrompt la démo, mais l'appelant
/// écrit toujours le bilan et le rapport (étapes faites + cause de l'interruption).
async fn derouler(owner: Keypair, principal: Keypair, etapes: &mut Vec<Etape>) -> Res<()> {
    let defaut = etat_par_defaut();
    let mut note = |numero, titre, ok, detail: String| {
        println!("\n[{numero}/7] {titre} : {}\n      {detail}", if ok { "OK" } else { "ÉCHEC" });
        etapes.push(Etape { numero, titre, ok, detail });
        ok
    };
    // Paramètres : 2 unités par heure, 0,5 au plus par achat. Cœur v0.6 : le budget part de zéro
    // et se remplit au rythme de 1,5 unité par heure ; la perte maximale immédiate est nulle.
    let regles = Regles::calculer(200_000_000, 36_000, 50_000_000)?;
    let c = connect().await?;
    let tresorerie_avant = solde(&c, &owner).await?;
    let besoin = regles.depot + 10_000_000;
    println!("Trésorerie du propriétaire : {} unités (il en faut {} pour la démo)", unites(tresorerie_avant as i64), unites(besoin as i64));
    if tresorerie_avant < besoin {
        attendre_fonds(&c, &owner, besoin).await?;
    }
    let service = address(&payee(&owner));
    liberer(&c).await?;

    // 1. Créer un agent
    let nom = format!("Démo DSI {}", double_auth::maintenant() % 100_000);
    let a = agents::nouveau(&defaut, &nom, Some(regles))?;
    let pub_agent = agents::xonly_pub(&a, &principal);
    note(1, "Créer un agent", true, format!("« {nom} » ({})", a.id));

    // 2. Lui attribuer un budget : ouverture de son coffre
    let k = agents::cle(&a, &principal)?;
    let r = avec_coffre(&a.etat, a.regles, pub_agent, || bloquant(deployer(&owner, &k)));
    let ok = match &r {
        Ok(tx) => note(2, "Lui attribuer un budget", true, format!(
            "2 unités par heure, 0,5 au plus par achat ; courbe promise : 0 maintenant, au plus {} au bout d'une heure, jamais plus que {} (le dépôt) ; coffre ouvert : {}",
            unites(regles.maximum_sur(36_000) - regles.capacite), unites(regles.depot as i64), explorer(tx))),
        Err(e) => note(2, "Lui attribuer un budget", false, e.to_string()),
    };
    if !ok {
        return Ok(());
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

    // 5. Il paie un service (service de démonstration que nous opérons). Le budget se remplit depuis
    // l'ouverture : l'outil attend qu'il couvre l'achat (quelques minutes), le réseau fait le reste.
    println!("      le budget se remplit depuis l'ouverture : attente que 0,05 unité (+ frais) soit disponible…");
    let r = avec_coffre(&etat_agent, a.regles, None, || bloquant(coffre::payer(&owner_pk, &cle_agent, 5_000_000, pay_to_address_script(&service), false, 900)));
    if r.is_ok() {
        agents::noter(&defaut, &a.nom, "paiement", Some(5_000_000));
    }
    let ok = match &r {
        Ok(tx) => note(5, "Payer un service", true, format!("0,05 unité payée au service de démonstration {service} : {}", explorer(tx))),
        Err(e) => note(5, "Payer un service", false, e.to_string()),
    };
    if !ok {
        return Ok(());
    }
    avec_coffre(&etat_agent, a.regles, None, || bloquant(attendre_inscription(&owner_pk, &cle_agent, "paiement")))?;

    // 6. Il tente de dépasser son budget : c'est le réseau qui refuse. La transaction annonce tout
    // l'âge réel de la pièce (le maximum que le réseau accepte) ; le contrat exige davantage.
    let r = avec_coffre(&etat_agent, a.regles, None, || bloquant(coffre::payer(&owner_pk, &cle_agent, 45_000_000, pay_to_address_script(&service), true, 0)));
    if matches!(&r, Err(e) if e.to_string().starts_with("REFUSÉ")) {
        agents::noter(&defaut, &a.nom, "bloque", Some(45_000_000));
    }
    match &r {
        Err(e) if e.to_string().starts_with("REFUSÉ") => note(6, "Bloqué au-delà du budget", true, format!("0,45 unité demandée juste après un achat (sous le plafond, au-delà du budget disponible) : {e}")),
        Ok(tx) => note(6, "Bloqué au-delà du budget", false, format!("paiement accepté alors qu'il devait être refusé : {}", explorer(tx))),
        Err(e) => note(6, "Bloqué au-delà du budget", false, format!("erreur inattendue : {e}")),
    };

    // 7. Arrêt d'urgence depuis la console (état périmé côté console : le coffre est retrouvé sur le registre)
    let c = connect_silencieux().await?;
    let avant = solde(&c, &owner).await?;
    liberer(&c).await?;
    let k_console = agents::cle(&agents::charger(&defaut).into_iter().find(|x| x.id == a.id).ok_or("agent disparu du registre")?, &principal)?;
    let mut r = avec_coffre(&a.etat, a.regles, pub_agent, || bloquant(geler(&owner, &k_console, false, 0)));
    if let Err(e) = &r {
        // Second essai : le nœud peut ne pas encore voir la dernière inscription.
        println!("      arrêt non abouti ({e}) ; nouvel essai dans 5 s");
        tokio::time::sleep(Duration::from_secs(5)).await;
        r = avec_coffre(&a.etat, a.regles, pub_agent, || bloquant(geler(&owner, &k_console, false, 0)));
    }
    if r.is_ok() {
        agents::noter(&defaut, &a.nom, "arret", None);
    }
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
            liberer(&c).await?;
            note(7, "Arrêt d'urgence", apres > avant, format!("fonds rapatriés dans la trésorerie : +{} unités ({})", unites(apres as i64 - avant as i64), explorer(tx)))
        }
        Err(e) => note(7, "Arrêt d'urgence", false, e.to_string()),
    };
    Ok(())
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

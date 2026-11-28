//! Essais de course sur le réseau de test (étape 3 du plan d'audit).
//!
//! Deux transactions qui dépensent la même pièce du coffre partent en même temps, par deux
//! connexions différentes : le réseau n'en garde qu'une. On vérifie ensuite que, quel que soit le
//! gagnant, rien ne sort du cadre promis :
//! - `course-gel` : un paiement de l'agent contre le gel du propriétaire. Après la course, le gel
//!   est relancé jusqu'au bout ; le coffre doit finir vide et le paiement (s'il est passé) rester
//!   sous le plafond par achat.
//! - `course-recharge` : un paiement de l'agent contre un rechargement de la même pièce. Le
//!   nombre de pièces (donc le rythme du mandat) ne doit pas changer, et si le rechargement perd,
//!   l'argent du propriétaire ne doit pas avoir bougé.

use crate::coeur;
use crate::coffre::{self, Apport, Piece, MARGE};
use crate::*;

/// Petit paiement : au-dessus du minimum de masse KIP-9 (≈ 0,02), bien sous le plafond par achat.
const MONTANT: u64 = 3_000_000;

/// Attend une pièce capable de payer `MONTANT` maintenant (au plus 15 min).
async fn piece_prete(c: &KaspaRpcClient, coeur: &coeur::Coeur, art: &SilAbiArtifact) -> Res<(Piece, Vec<Piece>)> {
    let spent = MONTANT + FEE;
    let debut = std::time::Instant::now();
    loop {
        let now = virtual_daa(c).await?;
        let ps = coffre::pieces(c, art).await?;
        if let Some(p) = ps
            .iter()
            .filter(|p| p.valeur > spent && p.creation.is_some_and(|cr| cr + coeur.attente(spent as i64) + MARGE <= now))
            .max_by_key(|p| p.valeur)
        {
            return Ok((p.clone(), ps));
        }
        let d = coffre::delai(coeur, &ps, now, spent).ok_or("aucune pièce du coffre ne couvre le paiement d'essai")?;
        if debut.elapsed().as_secs() + d / 10 > 900 {
            return Err(format!("aucune pièce prête avant 15 min (encore {} s)", d / 10).into());
        }
        println!("(attente d'une pièce prête : {} s)", d / 10 + 1);
        tokio::time::sleep(Duration::from_secs((d / 10 + 1).min(30))).await;
    }
}

fn paiement(coeur: &coeur::Coeur, art: &SilAbiArtifact, p: &Piece, owner: &Keypair, agent: &Keypair) -> Res<Transaction> {
    let dest = pay_to_address_script(&address(&payee(owner)));
    coeur::build_pay(coeur, art, p.outpoint, p.valeur, dest, MONTANT, FEE, agent, None)
}

/// Envoie les deux transactions en même temps, par deux connexions.
async fn duel(a: &Transaction, b: &Transaction) -> Res<(Result<String, String>, Result<String, String>)> {
    let (c1, c2) = (connect_silencieux().await?, connect_silencieux().await?);
    let (ra, rb) = (garde_diffusion(a)?, garde_diffusion(b)?);
    let (x, y) = tokio::join!(c1.submit_transaction(ra, false), c2.submit_transaction(rb, false));
    let x = x.map(|i| i.to_string()).map_err(|e| e.to_string());
    let y = y.map(|i| i.to_string()).map_err(|e| e.to_string());
    liberer(&c1).await?;
    liberer(&c2).await?;
    Ok((x, y))
}

/// Une transaction est-elle inscrite ? (ses sorties apparaissent à l'une des adresses données)
async fn inscrite(c: &KaspaRpcClient, tx: &Transaction, adresses: Vec<Address>) -> Res<bool> {
    let id = tx.id();
    for _ in 0..30 {
        if c.get_utxos_by_addresses(adresses.clone()).await?.iter().any(|u| u.outpoint.transaction_id == id) {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(false)
}

fn dire(nom: &str, r: &Result<String, String>) {
    match r {
        Ok(id) => println!("  {nom} : accepté par le nœud ({})", explorer(id)),
        Err(e) => println!("  {nom} : refusé par le nœud ({e})"),
    }
}

/// Paiement de l'agent contre gel du propriétaire, sur la même pièce.
pub async fn gel(owner: &Keypair, agent: &Keypair) -> Res<bool> {
    if coffre::lignee_de(coffre::charger().as_ref()).is_some() {
        return Err("essais de course : écrits pour les coffres v0.7 (créer le coffre avec PLAFOND_COEUR=v0.7) ; pas encore adaptés au coffre à lignée".into());
    }
    let coeur = coffre::coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact()?;
    let c = connect().await?;
    let (p, ps) = piece_prete(&c, &coeur, &art).await?;
    let retour = coffre::adresse_retour(coffre::charger().as_ref(), &xonly(owner))?;
    let pay = paiement(&coeur, &art, &p, owner, agent)?;
    // Le lot de gel qui contient la pièce disputée (premier essai, frais de base).
    let lot = coffre::lots(&ps).into_iter().find(|l| l.iter().any(|q| q.outpoint == p.outpoint)).ok_or("pièce disputée hors des lots de gel")?;
    let gels = coffre::gel_txs(&coeur, &art, &lot, owner, &retour, 1)?;
    let g = gels.into_iter().find(|t| t.inputs.iter().any(|i| i.previous_outpoint == p.outpoint)).ok_or("gel sans la pièce disputée")?;
    println!("Course : paiement de l'agent ({} TKAS) contre gel du propriétaire, même pièce ({} TKAS)", MONTANT as f64 / 1e8, p.valeur as f64 / 1e8);
    let (rp, rg) = duel(&pay, &g).await?;
    dire("paiement", &rp);
    dire("gel", &rg);
    let paye = inscrite(&c, &pay, vec![address(&payee(owner))]).await?;
    let gele = !paye && inscrite(&c, &g, vec![retour.clone()]).await?;
    println!("  gagnant inscrit : {}", if paye { "le paiement" } else if gele { "le gel" } else { "aucun (à vérifier)" });
    liberer(&c).await?;
    // Le propriétaire termine le gel : la monnaie rendue par un paiement gagnant doit aussi partir.
    let fin = coffre::geler(owner, agent).await;
    match &fin {
        Ok(ids) => println!("  gel terminé : {ids}"),
        Err(e) => println!("  gel terminé : {e}"),
    }
    let c = connect().await?;
    let reste: u64 = coffre::lots(&coffre::pieces(&c, &art).await?).concat().iter().map(|q| q.valeur).sum();
    liberer(&c).await?;
    let ok_plafond = !paye || (MONTANT + FEE) as i64 <= coeur.capacite;
    let ok = reste == 0 && ok_plafond && (paye || gele);
    println!(
        "[{}] course paiement/gel : coffre vide après gel ({}), paiement sous le plafond par achat ({})",
        if ok { "OK" } else { "ALERTE" },
        if reste == 0 { "oui".to_string() } else { format!("non, {} TKAS restent", reste as f64 / 1e8) },
        if ok_plafond { "oui" } else { "non" }
    );
    Ok(ok)
}

/// Paiement de l'agent contre rechargement de la même pièce par le propriétaire.
pub async fn recharge(owner: &Keypair, agent: &Keypair) -> Res<bool> {
    if coffre::lignee_de(coffre::charger().as_ref()).is_some() {
        return Err("essais de course : écrits pour les coffres v0.7 (créer le coffre avec PLAFOND_COEUR=v0.7) ; pas encore adaptés au coffre à lignée".into());
    }
    let coeur = coffre::coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact()?;
    let c = connect().await?;
    let (p, ps) = piece_prete(&c, &coeur, &art).await?;
    let avant = ps.iter().filter(|q| q.valeur >= coeur_plancher()).count();
    let apport = 100_000_000u64;
    let solde_avant: u64 = c.get_utxos_by_addresses(vec![address(owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
    let pay = paiement(&coeur, &art, &p, owner, agent)?;
    let proprio = coffre::financer(&c, owner, apport).await?;
    let (rec, _) = coffre::tx_regonfler(&art, (p.outpoint, p.valeur), proprio, apport, owner)?;
    println!("Course : paiement de l'agent ({} TKAS) contre rechargement de {} TKAS, même pièce", MONTANT as f64 / 1e8, apport as f64 / 1e8);
    let (rp, rr) = duel(&pay, &rec).await?;
    dire("paiement", &rp);
    dire("rechargement", &rr);
    let paye = inscrite(&c, &pay, vec![address(&payee(owner))]).await?;
    let recharge = !paye && inscrite(&c, &rec, vec![coffre::adresse(&art)?]).await?;
    println!("  gagnant inscrit : {}", if paye { "le paiement" } else if recharge { "le rechargement" } else { "aucun (à vérifier)" });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let apres_ps = coffre::pieces(&c, &art).await?;
    let apres = apres_ps.iter().filter(|q| q.valeur >= coeur_plancher()).count();
    let solde_apres: u64 = c.get_utxos_by_addresses(vec![address(owner)]).await?.iter().map(|u| u.utxo_entry.amount).sum();
    if recharge {
        // Comme « Ajouter des fonds » : l'apport compte dans la courbe promise.
        if let Some(mut e) = coffre::charger() {
            e.apports.push(Apport { txid: rec.id().to_string(), sompi: apport, daa: virtual_daa(&c).await? });
            coffre::enregistrer(&e)?;
        }
    }
    liberer(&c).await?;
    let ok_rythme = apres == avant;
    let ok_proprio = recharge || solde_apres == solde_avant;
    let ok = ok_rythme && ok_proprio && (paye || recharge);
    println!(
        "[{}] course paiement/rechargement : nombre de pièces {avant} → {apres} ({}), argent du propriétaire {}",
        if ok { "OK" } else { "ALERTE" },
        if ok_rythme { "rythme inchangé" } else { "RYTHME CHANGÉ" },
        if recharge { "versé au coffre (rechargement gagnant)".to_string() } else if ok_proprio { "intact".to_string() } else { format!("a bougé de {} TKAS", (solde_avant as i64 - solde_apres as i64) as f64 / 1e8) }
    );
    Ok(ok)
}

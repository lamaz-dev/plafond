//! Le coffre à LIGNÉE (cœur v0.9.2, sas v0.2.1) dans l'outil : création, adresse de dépôt, et les
//! trois gestes du propriétaire : AJOUTER, REPRENDRE, FERMER.
//!
//! Ce qui change par rapport au coffre v0.7 (src/coffre.rs, toujours géré) :
//!  - le coffre s'identifie par son adresse ET sa lignée (L1) : seules les pièces qui portent la
//!    lignée comptent dans le solde et le budget ; une pièce envoyée à l'adresse par un tiers est
//!    affichée à part ;
//!  - le nombre de pièces est fixé à la création, pour toujours : « Ajouter » regonfle une pièce
//!    existante, jamais une de plus ;
//!  - l'adresse de dépôt (le sas) n'est JAMAIS une simple chaîne fournie par quelqu'un (S7) : elle
//!    est recalculée à partir des réglages publics du coffre et de sa création, et signée par la clé
//!    du propriétaire ; `verifier_fiche` refait tout le calcul côté payeur ;
//!  - ordre des opérations (L5) : l'adresse de dépôt n'est publiée qu'une fois la création confirmée ;
//!  - « Fermer » éteint la lignée : toutes les pièces ET les dépôts en attente au sas partent à
//!    l'adresse de retour dans la même transaction. Il n'y a pas de réouverture : on crée un autre
//!    coffre, avec une autre adresse de dépôt.
//! Preuve et notes : spec/borne-de-perte-v0.9.md, spec/red-team/coeur-v0.9.2-2026-11-28.md.

use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use secp256k1::{Message, XOnlyPublicKey, schnorr::Signature};

use crate::coeur::{Coeur, Publics};
use crate::coffre::{self, Apport, EtatCoeur, Genese, MARGE, Piece, VERSION_V092};
use crate::lignee::{self, Sas};
use crate::*;

/// Marge appliquée au minimum de relais mesuré (masse::frais_relais) pour les transactions signées.
fn frais_pour(tx: &Transaction) -> u64 {
    masse::frais_relais(tx) * 3 / 2
}

/// Plus petite pièce de lignée que l'outil accepte de laisser dans un coffre : en dessous, elle ne
/// pourrait plus payer (masse de stockage, KIP-9 : une pièce à lignée pèse deux unités).
pub fn plancher() -> u64 {
    masse::survival_floor(FEE)
}

/// Explication affichée quand le propriétaire choisit plusieurs pièces (décision du 28 nov. 2026 :
/// une pièce par défaut).
pub fn avertissement_pieces(r: &Regles) -> String {
    let k = r.pieces.max(1);
    if k == 1 {
        return "Une pièce : un achat à la fois ; au pire, l'agent sort un plafond d'achat d'un coup, puis au rythme du budget.".into();
    }
    format!(
        "{k} pièces : {k} achats possibles d'affilée. La borne de perte est multipliée par {k} : au pire {} KAS d'un coup au lieu de {} (chaque pièce a son propre rythme). \
         Pour garder la même perte immédiate, divisez le plafond par achat par {k}. Ce nombre est définitif : pour le changer, il faut fermer le coffre et en créer un autre.",
        (r.capacite * k) as f64 / 1e8,
        r.capacite as f64 / 1e8
    )
}

fn hash32(hexa: &str) -> Res<Hash> {
    Ok(Hash::from_bytes(<[u8; 32]>::try_from(hex::decode(hexa)?.as_slice()).map_err(|_| "32 octets attendus")?))
}

/// Identifiant de lignée RECALCULÉ à partir de la création : le même calcul que le réseau (KIP-20).
/// Il engage la pièce dépensée, et l'indice, la valeur et le script de chaque pièce créée : toutes
/// au script du coffre, sorties 0..k.
pub fn lignee_recalculee(coeur: &Coeur, g: &Genese) -> Res<Hash> {
    if g.valeurs.is_empty() || g.valeurs.len() > lignee::PIECES_MAX {
        return Err("création invalide : de 1 à 4 pièces".into());
    }
    let m = vault_spk(&coeur.artifact_v092()?);
    let sorties: Vec<TransactionOutput> = g.valeurs.iter().map(|v| TransactionOutput::new(*v, m.clone())).collect();
    let entree = TransactionOutpoint::new(TransactionId::from_bytes(*hash32(&g.entree_txid)?.as_bytes().first_chunk::<32>().expect("32 octets")), g.entree_index);
    Ok(covenant_id(entree, sorties.iter().enumerate().map(|(i, o)| (i as u32, o))))
}

/// Le sas d'un coffre, recalculé : jamais lu dans un fichier ni reçu d'un tiers. Refuse si la lignée
/// enregistrée n'est pas celle que donne la création enregistrée.
pub fn sas_de(coeur: &Coeur, e: &EtatCoeur) -> Res<Sas> {
    let x = coffre::lignee_de(Some(e)).ok_or("ce coffre n'a pas de lignée (coffre v0.7) : pas d'adresse de dépôt")?;
    let g = e.genese.as_ref().ok_or("création du coffre inconnue : adresse de dépôt non vérifiable")?;
    if lignee_recalculee(coeur, g)? != x {
        return Err("la lignée enregistrée ne correspond pas à la création du coffre : fichier d'état modifié ?".into());
    }
    Sas::pour(coeur, x, e.sas_max_frais.unwrap_or(lignee::FRAIS_MAX_DEFAUT))
}

fn adresse_de(spk: &ScriptPublicKey) -> Res<Address> {
    Ok(extract_script_pub_key_address(spk, Prefix::Testnet).map_err(|_| "adresse invalide")?)
}

/// Ce que le propriétaire signe : « pour le coffre à cette adresse et de cette lignée, l'adresse de
/// dépôt est celle-ci ». Étiquette de domaine : la signature ne peut servir à rien d'autre.
fn message_depot(coffre: &Address, lignee: &Hash, depot: &Address) -> Message {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"PlafondDepotV1")
        .to_state()
        .update(coffre.to_string().as_bytes())
        .update(b"|")
        .update(lignee.to_string().as_bytes())
        .update(b"|")
        .update(depot.to_string().as_bytes())
        .finalize();
    Message::from_digest(*h.as_bytes().first_chunk::<32>().expect("32 octets"))
}

pub fn attester(owner: &Keypair, coffre: &Address, lignee: &Hash, depot: &Address) -> String {
    hex::encode(owner.sign_schnorr(message_depot(coffre, lignee, depot)).as_ref())
}

pub fn attestation_valide(owner_pk: &[u8], coffre: &Address, lignee: &Hash, depot: &Address, signature: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (XOnlyPublicKey::from_slice(owner_pk), hex::decode(signature).map_err(|_| ()).and_then(|s| Signature::from_slice(&s).map_err(|_| ()))) else {
        return false;
    };
    secp256k1::SECP256K1.verify_schnorr(&sig, &message_depot(coffre, lignee, depot), &pk).is_ok()
}

/// Fiche de dépôt : tout ce qu'un payeur (ou un service d'achat) doit recevoir pour envoyer de
/// l'argent au coffre SANS faire confiance à celui qui lui transmet la fiche. Rien de secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Fiche {
    pub version: String,
    pub coffre: Publics,
    pub genese: Genese,
    pub lignee: String,
    pub adresse_coffre: String,
    pub adresse_depot: String,
    pub max_frais_sompi: i64,
    /// S6 : en dessous, le dépôt n'est pas versé automatiquement (il attend le propriétaire).
    pub depot_minimal_sompi: u64,
    /// Signature de la clé du propriétaire (`coffre.owner`) sur (adresse du coffre, lignée, adresse de dépôt).
    pub attestation: String,
}

/// La fiche de dépôt du coffre en cours. Erreur tant que la création n'est pas confirmée (L5).
pub fn fiche(owner_pk: &[u8], agent_pk: &[u8]) -> Res<Fiche> {
    let e = coffre::charger().ok_or("aucun coffre")?;
    let coeur = coffre::coeur_de(owner_pk, agent_pk);
    let sas = sas_de(&coeur, &e)?;
    let attestation = e.attestation.clone().ok_or("adresse de dépôt pas encore publiée : la création du coffre doit d'abord être confirmée par le réseau")?;
    let f = Fiche {
        version: VERSION_V092.into(),
        coffre: coeur.publics(),
        genese: e.genese.clone().expect("vérifié par sas_de"),
        lignee: e.lignee.clone().expect("vérifié par sas_de"),
        adresse_coffre: adresse_de(&vault_spk(&coeur.artifact_v092()?))?.to_string(),
        adresse_depot: adresse_de(&vault_spk(&sas.artifact()?))?.to_string(),
        max_frais_sompi: sas.max_frais,
        depot_minimal_sompi: Sas::depot_minimal(&coeur, lignee::FRAIS_RECHARGE),
        attestation,
    };
    verifier_fiche(&f)?;
    Ok(f)
}

/// CÔTÉ PAYEUR (S7). Refait tout le calcul à partir des réglages publics : script du coffre, lignée
/// (depuis la création), script du sas ; compare avec les adresses annoncées ; vérifie la signature
/// du propriétaire. Une adresse de dépôt qui ne sort pas de ce calcul est refusée, d'où qu'elle vienne.
/// Renvoie le sas vérifié. Ce contrôle est hors ligne ; `fiche_en_ligne` y ajoute la lecture du nœud.
pub fn verifier_fiche(f: &Fiche) -> Res<Sas> {
    if f.version != VERSION_V092 {
        return Err(format!("version de coffre inconnue : {}", f.version).into());
    }
    let coeur = f.coffre.coeur()?;
    let x = hash32(&f.lignee)?;
    if lignee_recalculee(&coeur, &f.genese)? != x {
        return Err("REFUSÉ : la lignée annoncée n'est pas celle de la création annoncée".into());
    }
    let coffre_adr = adresse_de(&vault_spk(&coeur.artifact_v092()?))?;
    if coffre_adr.to_string() != f.adresse_coffre {
        return Err("REFUSÉ : l'adresse du coffre ne correspond pas à ses réglages".into());
    }
    let sas = Sas::pour(&coeur, x, f.max_frais_sompi)?;
    let depot_adr = adresse_de(&vault_spk(&sas.artifact()?))?;
    if depot_adr.to_string() != f.adresse_depot {
        return Err(format!("REFUSÉ : l'adresse de dépôt annoncée n'est pas celle de ce coffre (attendue : {depot_adr})").into());
    }
    if !attestation_valide(&coeur.owner, &coffre_adr, &x, &depot_adr, &f.attestation) {
        return Err("REFUSÉ : l'adresse de dépôt n'est pas signée par la clé du propriétaire du coffre".into());
    }
    if f.depot_minimal_sompi < Sas::depot_minimal(&coeur, 0) {
        return Err("REFUSÉ : dépôt minimal annoncé inférieur à ce que le contrat exige".into());
    }
    Ok(sas)
}

/// Contrôle en ligne d'une fiche : le coffre existe-t-il vraiment, avec cette lignée ?
pub async fn fiche_en_ligne(c: &KaspaRpcClient, f: &Fiche) -> Res<String> {
    verifier_fiche(f)?;
    let coeur = f.coffre.coeur()?;
    let x = hash32(&f.lignee)?;
    let (du_coffre, _) = coffre::du_coffre(coffre::pieces(c, &coeur.artifact_v092()?).await?, Some(x));
    if du_coffre.is_empty() {
        return Err("REFUSÉ : aucune pièce de cette lignée à l'adresse du coffre (coffre fermé, ou jamais créé) : un dépôt ne serait pas versé".into());
    }
    Ok(format!("{} pièce(s) de la lignée à l'adresse du coffre, {} KAS", du_coffre.len(), du_coffre.iter().map(|p| p.valeur).sum::<u64>() as f64 / 1e8))
}

/// Dépôts présents au sas : (pièce, valeur, confirmé).
pub async fn depots(c: &KaspaRpcClient, sas: &Sas) -> Res<Vec<(TransactionOutpoint, u64, bool)>> {
    let spk = vault_spk(&sas.artifact()?);
    Ok(c.get_utxos_by_addresses(vec![adresse_de(&spk)?])
        .await?
        .into_iter()
        .filter(|u| u.utxo_entry.script_public_key == spk)
        .map(|u| (u.outpoint.into(), u.utxo_entry.amount, u.utxo_entry.block_daa_score != u64::MAX))
        .collect())
}

async fn attendre_piece(c: &KaspaRpcClient, art: &SilAbiArtifact, txid: &str, secondes: u64) -> Res<Option<Piece>> {
    for _ in 0..secondes * 2 {
        if let Some(p) = coffre::pieces(c, art).await?.into_iter().find(|p| p.creation.is_some() && p.outpoint.transaction_id.to_string() == txid) {
            return Ok(Some(p));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(None)
}

/// CRÉATION par genèse. Ordre des opérations (L5) : (1) la création est diffusée ; (2) on attend que
/// le réseau l'ait inscrite et que les pièces relues portent bien la lignée ; (3) alors seulement
/// l'adresse de dépôt est calculée, signée par le propriétaire et affichée.
pub async fn creer(owner: &Keypair, agent: &Keypair, retour: Option<&str>) -> Res<String> {
    let r = regles();
    let k = r.pieces.clamp(1, PIECES_MAX);
    let retour_adr = match retour {
        Some(a) => coffre::valider_retour(a)?,
        None => address(owner),
    };
    let coeur = Coeur { owner: xonly(owner), agent: agent_pk(agent), capacite: r.capacite, periode: r.recharge_daa, retour: Some(coffre::empreinte_retour(&retour_adr)) };
    let art = coeur.artifact_v092()?;
    let valeurs = coffre::decouper(r.depot, k);
    if valeurs.iter().any(|v| *v < plancher()) {
        return Err(format!("dépôt trop petit pour {k} pièce(s) : chaque pièce doit valoir au moins {} KAS", plancher() as f64 / 1e8).into());
    }
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let (entries, inputs, total) = coffre::financer(&c, owner, r.depot).await?;
    let fonds: Vec<(TransactionOutpoint, UtxoEntry)> = inputs.iter().map(|i| i.previous_outpoint).zip(entries.iter().cloned()).collect();
    let rendu = total - r.depot - FEE * fonds.len() as u64;
    let (tx, x) = lignee::build_genese(&coeur, &fonds, &valeurs, (rendu > 0).then(|| (rendu, pay_to_address_script(&address(owner)))), owner)?;
    let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?.to_string();
    let mut e = EtatCoeur {
        version: VERSION_V092.into(),
        retour: retour.map(|_| retour_adr.to_string()),
        capacite: coeur.capacite,
        periode: coeur.periode,
        agent: hex::encode(&coeur.agent),
        cree_daa: daa,
        apports: valeurs.iter().map(|sompi| Apport { txid: txid.clone(), sompi: *sompi, daa }).collect(),
        vues: vec![],
        achats: vec![],
        lignee: Some(x.to_string()),
        genese: Some(Genese { txid: txid.clone(), entree_txid: fonds[0].0.transaction_id.to_string(), entree_index: fonds[0].0.index, valeurs: valeurs.clone() }),
        sas_max_frais: Some(lignee::FRAIS_MAX_DEFAUT),
        attestation: None,
        retraits: vec![],
    };
    coffre::enregistrer(&e)?;
    println!("Coffre créé (cœur v0.9.2, à lignée) : {} TKAS en {k} pièce(s) à l'adresse {}", r.depot as f64 / 1e8, coffre::adresse(&art)?);
    println!("{}", avertissement_pieces(&r));
    println!("Lignée du coffre : {x}");
    println!("Adresse de retour (reprise, fermeture) : {retour_adr}");
    println!("Transaction : {}", explorer(&txid));
    // (2) et (3) : l'adresse de dépôt n'existe pour personne tant que la création n'est pas inscrite.
    match publier_depot(&c, owner, &coeur, &mut e).await {
        Ok(adr) => println!("Adresse de dépôt (sas), signée par le propriétaire : {adr}\n  dépôt minimal versé automatiquement : {} TKAS", Sas::depot_minimal(&coeur, lignee::FRAIS_RECHARGE) as f64 / 1e8),
        Err(err) => println!("Adresse de dépôt pas encore publiée ({err}) : relancer la commande `sas` dans quelques secondes."),
    }
    liberer(&c).await?;
    Ok(txid)
}

/// Étapes (2) et (3) de la création : vérifie sur le nœud que les pièces de la création portent la
/// lignée attendue, puis signe et enregistre l'adresse de dépôt. Sans effet si c'est déjà fait.
pub async fn publier_depot(c: &KaspaRpcClient, owner: &Keypair, coeur: &Coeur, e: &mut EtatCoeur) -> Res<String> {
    let sas = sas_de(coeur, e)?;
    let x = sas.id();
    let art = coeur.artifact_v092()?;
    let depot_adr = adresse_de(&vault_spk(&sas.artifact()?))?;
    if e.attestation.is_some() {
        return Ok(depot_adr.to_string());
    }
    let g = e.genese.clone().expect("vérifié par sas_de");
    let Some(_) = attendre_piece(c, &art, &g.txid, 60).await? else {
        return Err("création pas encore confirmée par le réseau".into());
    };
    let inscrites: Vec<Piece> = coffre::pieces(c, &art).await?.into_iter().filter(|p| p.outpoint.transaction_id.to_string() == g.txid).collect();
    if inscrites.len() != g.valeurs.len() || inscrites.iter().any(|p| p.lignee != Some(x)) {
        return Err("les pièces inscrites ne portent pas la lignée attendue : adresse de dépôt NON publiée".into());
    }
    e.attestation = Some(attester(owner, &coffre::adresse(&art)?, &x, &depot_adr));
    coffre::enregistrer(e)?;
    Ok(depot_adr.to_string())
}

/// AJOUTER : l'apport regonfle une pièce existante de la lignée (la plus jeune). Jamais une pièce de
/// plus : le contrat l'interdit, même au propriétaire.
pub async fn ajouter(owner: &Keypair, agent: &Keypair, montant: u64) -> Res<String> {
    let mut e = coffre::charger().ok_or("aucun coffre")?;
    let x = coffre::lignee_de(Some(&e)).ok_or("coffre sans lignée")?;
    let coeur = coffre::coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact_v092()?;
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let (ps, _) = coffre::du_coffre(coffre::pieces(&c, &art).await?, Some(x));
    if ps.is_empty() {
        liberer(&c).await?;
        return Err("ce coffre est fermé (plus aucune pièce de sa lignée) : on ne peut plus y ajouter d'argent ; créez un nouveau coffre".into());
    }
    let Some(p) = ps.iter().filter_map(|p| p.creation.map(|cr| (coeur.immediate(p.valeur, daa.saturating_sub(cr)), p))).min_by_key(|(dispo, p)| (*dispo, p.valeur)).map(|(_, p)| p.clone()) else {
        liberer(&c).await?;
        return Err("le coffre attend la confirmation d'une opération : réessayer dans quelques secondes".into());
    };
    let (entrees_p, inputs_p, total_p) = coffre::financer(&c, owner, montant).await?;
    let m = vault_spk(&art);
    let mut entries = vec![UtxoEntry::new(p.valeur, m.clone(), 0, false, Some(x))];
    entries.extend(entrees_p);
    let mut inputs = vec![TransactionInput::new_with_compute_budget(p.outpoint, vec![], 0, lignee::CB_OWNER)];
    inputs.extend(inputs_p);
    let fee = FEE * inputs.len() as u64;
    let rendu = total_p.checked_sub(montant + fee).ok_or("solde du propriétaire insuffisant pour l'apport et les frais")?;
    let mut outputs = vec![lignee::sortie_liee(p.valeur + montant, m, x, 0)];
    if rendu > 0 {
        outputs.push(TransactionOutput::new(rendu, pay_to_address_script(&address(owner))));
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..tx.inputs.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = if i == 0 { vault_sigscript(&art, "ownerControl", &[s.into()])? } else { ScriptBuilder::new().add_data(&s)?.drain() };
    }
    tx.finalize();
    let r = c.submit_transaction(garde_diffusion(&tx)?, false).await;
    liberer(&c).await?;
    let txid = r.map_err(|err| format!("ajout refusé ({err}) : un achat utilise peut-être cette pièce, réessayer"))?.to_string();
    e.apports.push(Apport { txid: txid.clone(), sompi: montant, daa });
    coffre::enregistrer(&e)?;
    println!("Coffre rechargé de {} TKAS (pièce existante regonflée, nombre de pièces inchangé) : {}", montant as f64 / 1e8, explorer(&txid));
    Ok(txid)
}

/// Ce que « Reprendre » peut faire maintenant : le plus gros montant reprenable sur une seule pièce
/// (il doit rester une pièce viable), et l'attente éventuelle (frais au rythme du contrat).
pub struct Reprise {
    pub maximum: u64,
    pub frais: u64,
    pub attente_secondes: u64,
}

/// Choix de la pièce et calcul des frais d'un retrait partiel de `montant`.
fn preparer_reprise(coeur: &Coeur, x: Hash, ps: &[Piece], retour: &ScriptPublicKey, montant: u64, now: u64, owner: &Keypair) -> Res<(Piece, u64, u64)> {
    let mut erreur: Box<dyn std::error::Error> = "aucune pièce confirmée dans le coffre".into();
    let mut choix: Option<(Piece, u64, u64)> = None;
    for p in ps.iter().filter(|p| p.creation.is_some()) {
        // Frais : le minimum de relais avec une marge, calculé sur la transaction réelle.
        let essai = |frais: u64| lignee::build_retrait_partiel(coeur, (p.outpoint, p.valeur), x, retour, montant, frais, owner, None);
        let frais = match essai(FEE.min(coeur.capacite as u64)) {
            Ok(tx) => frais_pour(&tx).min(coeur.capacite as u64),
            Err(e) => {
                erreur = e;
                continue;
            }
        };
        if p.valeur < montant + frais + plancher() {
            erreur = format!(
                "il doit rester au moins {} KAS dans la pièce : au plus {} KAS reprenables sur cette pièce ; pour tout reprendre, fermez le coffre",
                plancher() as f64 / 1e8,
                p.valeur.saturating_sub(frais + plancher()) as f64 / 1e8
            )
            .into();
            continue;
        }
        let tx = essai(frais)?;
        let entree = UtxoEntry::new(p.valeur, tx.outputs[0].script_public_key.clone(), 0, false, Some(x));
        if masse::masses(&tx, std::slice::from_ref(&entree)).is_none_or(|m| !m.standard()) {
            erreur = "retrait non diffusable : montant repris ou reste trop petit (masse de stockage)".into();
            continue;
        }
        let attente = (p.creation.unwrap_or(now) + coeur.attente(frais as i64) + MARGE).saturating_sub(now);
        if choix.as_ref().is_none_or(|(_, _, a)| attente < *a) {
            choix = Some((p.clone(), frais, attente));
        }
    }
    choix.ok_or(erreur)
}

/// REPRENDRE : retrait partiel vers l'adresse de retour. Les frais sont comptés au rythme du
/// contrat : si la pièce est trop jeune, on attend (au plus `attente_max` secondes) ou l'on dit
/// dans combien de temps ce sera possible. « Fermer » reste immédiat.
pub async fn reprendre(owner: &Keypair, agent: &Keypair, montant: u64, attente_max: u64) -> Res<String> {
    let mut e = coffre::charger().ok_or("aucun coffre")?;
    let x = coffre::lignee_de(Some(&e)).ok_or("reprise partielle : seulement pour un coffre à lignée (v0.9.2) ; un coffre v0.7 se gèle en entier")?;
    let coeur = coffre::coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact_v092()?;
    let retour = pay_to_address_script(&coffre::adresse_retour(Some(&e), &xonly(owner))?);
    if montant == 0 {
        return Err("montant à reprendre manquant".into());
    }
    let c = connect().await?;
    let debut = std::time::Instant::now();
    let (piece, frais) = loop {
        let now = virtual_daa(&c).await?;
        let (ps, _) = coffre::du_coffre(coffre::pieces(&c, &art).await?, Some(x));
        let (p, frais, attente) = match preparer_reprise(&coeur, x, &ps, &retour, montant, now, owner) {
            Ok(r) => r,
            Err(err) => {
                liberer(&c).await?;
                return Err(err);
            }
        };
        if attente == 0 {
            break (p, frais);
        }
        if debut.elapsed().as_secs() + attente / 10 > attente_max {
            liberer(&c).await?;
            return Err(format!(
                "reprise possible dans {} s : les frais d'une reprise sont comptés au rythme du coffre (une clé volée ne peut pas brûler l'argent en frais). Pour reprendre tout de suite, fermez le coffre.",
                attente / 10 + 1
            )
            .into());
        }
        tokio::time::sleep(Duration::from_secs((attente / 10 + 1).min(30))).await;
    };
    let tx = lignee::build_retrait_partiel(&coeur, (piece.outpoint, piece.valeur), x, &retour, montant, frais, owner, None)?;
    let r = c.submit_transaction(garde_diffusion(&tx)?, false).await;
    let daa = virtual_daa(&c).await.unwrap_or(0);
    liberer(&c).await?;
    let txid = r.map_err(|err| format!("reprise refusée par le réseau ({err}) : un achat utilise peut-être cette pièce, réessayer"))?.to_string();
    e.retraits.push(Apport { txid: txid.clone(), sompi: montant, daa });
    coffre::enregistrer(&e)?;
    println!("{} TKAS repris vers l'adresse de retour (frais {} TKAS) : {}", montant as f64 / 1e8, frais as f64 / 1e8, explorer(&txid));
    Ok(txid)
}

/// Ce que « Reprendre » permettrait maintenant (pour l'affichage).
pub fn reprise_possible(coeur: &Coeur, ps: &[Piece], now: u64) -> Option<Reprise> {
    let p = ps.iter().filter(|p| p.creation.is_some()).max_by_key(|p| p.valeur)?;
    let frais = (3 * masse::SOMPI_PAR_GRAMME * 2_000).min(coeur.capacite.max(0) as u64); // ordre de grandeur, recalculé à l'envoi
    Some(Reprise {
        maximum: p.valeur.saturating_sub(frais + plancher()),
        frais,
        attente_secondes: (p.creation.unwrap_or(now) + coeur.attente(frais as i64) + MARGE).saturating_sub(now) / 10,
    })
}

/// VERSEMENT SANS CLÉ des dépôts en attente au sas : n'importe qui peut le faire, l'outil le fait
/// pour le propriétaire. Un dépôt à la fois (chaque versement recrée la pièce). Un dépôt sous le
/// minimum (S6) est laissé : il attend le propriétaire. Renvoie les transactions diffusées.
pub async fn verser_depots(owner_pk: &[u8], agent_pk: &[u8]) -> Res<Vec<String>> {
    let mut e = coffre::charger().ok_or("aucun coffre")?;
    let coeur = coffre::coeur_de(owner_pk, agent_pk);
    let sas = sas_de(&coeur, &e)?;
    let (x, art) = (sas.id(), coeur.artifact_v092()?);
    let c = connect_silencieux().await?;
    let mut faits = vec![];
    let r: Res<()> = async {
        for _ in 0..8 {
            let now = virtual_daa(&c).await?;
            let attente: Vec<(TransactionOutpoint, u64, bool)> = depots(&c, &sas).await?.into_iter().filter(|d| d.2).collect();
            let Some(d) = attente.iter().find(|d| d.1 >= Sas::depot_minimal(&coeur, lignee::FRAIS_RECHARGE)) else { break };
            let (ps, _) = coffre::du_coffre(coffre::pieces(&c, &art).await?, Some(x));
            // La pièce la plus jeune : c'est elle qui perd le moins en repartant d'un âge nul.
            let Some(p) = ps.iter().filter_map(|p| p.creation.map(|cr| (coeur.immediate(p.valeur, now.saturating_sub(cr)), p))).min_by_key(|(dispo, p)| (*dispo, p.valeur)).map(|(_, p)| p.clone()) else { break };
            let brouillon = lignee::build_recharger(&coeur, &sas, (p.outpoint, p.valeur), (d.0, d.1), lignee::FRAIS_RECHARGE)?;
            let frais = lignee::FRAIS_RECHARGE.max(masse::frais_relais(&brouillon) * 6 / 5).min(sas.max_frais.max(0) as u64);
            let tx = lignee::build_recharger(&coeur, &sas, (p.outpoint, p.valeur), (d.0, d.1), frais)?;
            let txid = c.submit_transaction(garde_diffusion(&tx)?, false).await?.to_string();
            e.apports.push(Apport { txid: txid.clone(), sompi: d.1 - frais, daa: now });
            coffre::enregistrer(&e)?;
            faits.push(txid.clone());
            if attendre_piece(&c, &art, &txid, 30).await?.is_none() {
                break;
            }
        }
        Ok(())
    }
    .await;
    liberer(&c).await?;
    r?;
    Ok(faits)
}

/// Chemin de l'archive d'un coffre fermé : garde de quoi renvoyer un dépôt arrivé après la fermeture.
pub fn chemin_archive(etat: &str, lignee: &str) -> String {
    format!("{}.ferme-{}.json", etat.trim_end_matches(".json"), &lignee[..lignee.len().min(12)])
}

/// Une passe de fermeture : UNE transaction qui envoie à l'adresse de retour toutes les pièces de
/// l'adresse du coffre (de la lignée ou non) et tous les dépôts confirmés du sas. `tentative`
/// augmente les frais pour passer devant un paiement de l'agent en attente.
fn tx_fermeture(coeur: &Coeur, sas: &Sas, ps: &[Piece], ds: &[(TransactionOutpoint, u64, bool)], retour: &ScriptPublicKey, owner: &Keypair, tentative: u64) -> Res<Option<Transaction>> {
    let mut frais = (FEE.min(coeur.capacite.max(0) as u64), lignee::FRAIS_RECHARGE.min(sas.max_frais.max(0) as u64));
    let mut tx = None;
    for _ in 0..3 {
        // Une pièce trop petite pour payer sa part (poussière d'un tiers) est laissée : elle est inerte.
        let pieces: Vec<(TransactionOutpoint, u64, Option<Hash>)> = ps.iter().filter(|p| p.creation.is_some() && p.valeur >= 3 * frais.0).take(24).map(|p| (p.outpoint, p.valeur, p.lignee)).collect();
        let depots: Vec<(TransactionOutpoint, u64)> = ds.iter().filter(|d| d.2 && d.1 >= 3 * frais.1).take(24).map(|d| (d.0, d.1)).collect();
        if pieces.is_empty() && depots.is_empty() {
            return Ok(None);
        }
        let essai = lignee::build_fermeture(coeur, sas, &pieces, &depots, retour, frais.0, frais.1, owner)?;
        let n = (pieces.len() + depots.len()) as u64;
        let par_entree = (masse::frais_relais(&essai) * (2 + tentative) / 2).div_ceil(n);
        let besoin = (par_entree.min(coeur.capacite.max(0) as u64), par_entree.min(sas.max_frais.max(0) as u64));
        let suffisant = besoin.0 <= frais.0 && besoin.1 <= frais.1;
        tx = Some(essai);
        if suffisant {
            break;
        }
        frais = (besoin.0.max(frais.0), besoin.1.max(frais.1));
    }
    Ok(tx)
}

/// FERMER : le coffre est fermé définitivement. Les pièces de l'adresse du coffre et les dépôts en
/// attente au sas partent ensemble à l'adresse de retour ; la lignée s'éteint (aucun versement ne
/// sera plus jamais possible). Immédiat : aucun délai n'est exigé. Un paiement de l'agent en
/// attente est remplacé ; s'il passe quand même, son reste est rapatrié à la passe suivante.
pub async fn fermer(owner: &Keypair, agent: &Keypair) -> Res<String> {
    let e = coffre::charger().ok_or("aucun coffre")?;
    let coeur = coffre::coeur_de(&xonly(owner), &agent_pk(agent));
    let sas = sas_de(&coeur, &e)?;
    let (x, art) = (sas.id(), coeur.artifact_v092()?);
    let retour_adr = coffre::adresse_retour(Some(&e), &xonly(owner))?;
    let retour = pay_to_address_script(&retour_adr);
    let c = connect().await?;
    let mut ids: Vec<String> = vec![];
    let (mut tentative, mut vide_depuis, mut stable) = (0u64, None::<u64>, false);
    let debut = std::time::Instant::now();
    while debut.elapsed().as_secs() < 600 {
        let ps = coffre::pieces(&c, &art).await?;
        let ds = depots(&c, &sas).await?;
        let now = virtual_daa(&c).await?;
        let en_vol = ps.iter().any(|p| p.creation.is_none() && p.lignee == Some(x)) || ds.iter().any(|d| !d.2);
        match tx_fermeture(&coeur, &sas, &ps, &ds, &retour, owner, tentative)? {
            None if en_vol => {
                vide_depuis = None;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            None => {
                // Plus rien à rapatrier : on attend que cela reste vrai (blocs concurrents, R58).
                let depuis = *vide_depuis.get_or_insert(now);
                if now.saturating_sub(depuis) >= coffre::GEL_STABLE || (ids.is_empty() && tentative == 0) {
                    stable = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Some(tx) => {
                vide_depuis = None;
                if tentative >= 8 {
                    break;
                }
                tentative += 1;
                let id = tx.id().to_string();
                let envoi = match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                    Ok(_) => Ok(()),
                    Err(err) => {
                        println!("tentative {tentative} : {err} ; remplacement de l'opération en attente");
                        c.submit_transaction_replacement(garde_diffusion(&tx)?).await.map(|_| ()).map_err(|e| e.to_string())
                    }
                };
                if let Err(err) = envoi {
                    println!("tentative {tentative} refusée : {err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                for _ in 0..30 {
                    if c.get_utxos_by_addresses(vec![retour_adr.clone()]).await?.iter().any(|u| u.outpoint.transaction_id.to_string() == id) {
                        let rendu: u64 = tx.outputs.iter().map(|o| o.value).sum();
                        println!("{} pièce(s) et dépôt(s) renvoyés à {retour_adr} : {} TKAS, {}", tx.inputs.len(), rendu as f64 / 1e8, explorer(&id));
                        ids.push(id.clone());
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    let reste = coffre::du_coffre(coffre::pieces(&c, &art).await?, Some(x)).0;
    liberer(&c).await?;
    if !reste.is_empty() {
        return Err(format!("fermeture incomplète : {} pièce(s) de la lignée encore dans le coffre, relancer", reste.len()).into());
    }
    if !stable {
        return Err("fermeture envoyée mais pas encore confirmée de façon stable : relancer pour vérifier".into());
    }
    // Le coffre est fermé pour toujours. On garde de quoi renvoyer un dépôt arrivé trop tard.
    let chemin = state_path();
    let _ = fs::write(chemin_archive(&chemin, &x.to_string()), serde_json::to_string_pretty(&e)?);
    let _ = fs::remove_file(&chemin);
    if ids.is_empty() {
        return Err("coffre déjà vide".into());
    }
    println!("Coffre FERMÉ : sa lignée est éteinte, son adresse de dépôt ne verse plus rien. Un dépôt qui y arriverait encore attendra que vous le renvoyiez (commande `sas-retour`).");
    Ok(ids.join(","))
}

/// Dépôts arrivés au sas d'un coffre FERMÉ : le propriétaire les renvoie à l'adresse de retour.
/// `archive` : le fichier laissé par la fermeture.
pub async fn retour_tardif(owner: &Keypair, archive: &str) -> Res<String> {
    let e: EtatCoeur = serde_json::from_str(&fs::read_to_string(archive)?)?;
    let agent = hex::decode(&e.agent)?;
    let retour_adr = coffre::adresse_retour(Some(&e), &xonly(owner))?;
    let coeur = Coeur { owner: xonly(owner), agent, capacite: e.capacite, periode: e.periode, retour: Some(coffre::empreinte_retour(&retour_adr)) };
    let sas = sas_de(&coeur, &e)?;
    let c = connect().await?;
    let ds = depots(&c, &sas).await?;
    let r: Res<String> = async {
        let Some(tx) = tx_fermeture(&coeur, &sas, &[], &ds, &pay_to_address_script(&retour_adr), owner, 0)? else {
            return Err("aucun dépôt confirmé à renvoyer à cette adresse de dépôt".into());
        };
        Ok(c.submit_transaction(garde_diffusion(&tx)?, false).await?.to_string())
    }
    .await;
    liberer(&c).await?;
    let txid = r?;
    println!("Dépôt(s) tardif(s) renvoyé(s) à {retour_adr} : {}", explorer(&txid));
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }
    fn coeur(agent: u8) -> Coeur {
        Coeur { owner: xonly(&k(1)), agent: xonly(&k(agent)), capacite: 50_000_000, periode: 36_000, retour: Some(coffre::empreinte_retour(&address(&k(11)))) }
    }
    fn genese(n: u8) -> Genese {
        Genese { txid: hex::encode([n; 32]), entree_txid: hex::encode([n + 1; 32]), entree_index: 0, valeurs: vec![300_000_000] }
    }
    /// Une fiche de dépôt honnête, signée par le propriétaire `cle`.
    fn fiche_de(c: &Coeur, g: Genese, cle: u8) -> Fiche {
        let x = lignee_recalculee(c, &g).unwrap();
        let sas = Sas::pour(c, x, lignee::FRAIS_MAX_DEFAUT).unwrap();
        let (coffre_adr, depot_adr) = (adresse_de(&vault_spk(&c.artifact_v092().unwrap())).unwrap(), adresse_de(&vault_spk(&sas.artifact().unwrap())).unwrap());
        Fiche {
            version: VERSION_V092.into(),
            coffre: c.publics(),
            genese: g,
            lignee: x.to_string(),
            adresse_coffre: coffre_adr.to_string(),
            adresse_depot: depot_adr.to_string(),
            max_frais_sompi: sas.max_frais,
            depot_minimal_sompi: Sas::depot_minimal(c, lignee::FRAIS_RECHARGE),
            attestation: attester(&k(cle), &coffre_adr, &x, &depot_adr),
        }
    }

    /// La lignée recalculée par l'outil est celle que le réseau calcule pour la transaction de
    /// création construite par `build_genese`.
    #[test]
    fn lignee_recalculee_egale_celle_de_la_creation() {
        let c = coeur(2);
        let op = TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), 3);
        let fonds = [(op, UtxoEntry::new(1_000_000_000, pay_to_address_script(&address(&k(1))), 5, false, None))];
        let valeurs = [300_000_000u64, 200_000_000];
        let (tx, x) = lignee::build_genese(&c, &fonds, &valeurs, None, &k(1)).unwrap();
        let g = Genese { txid: tx.id().to_string(), entree_txid: op.transaction_id.to_string(), entree_index: 3, valeurs: valeurs.to_vec() };
        assert_eq!(lignee_recalculee(&c, &g).unwrap(), x);
        // Une valeur, un indice ou une pièce dépensée différents donnent une autre lignée.
        assert_ne!(lignee_recalculee(&c, &Genese { valeurs: vec![300_000_000, 200_000_001], ..g.clone() }).unwrap(), x);
        assert_ne!(lignee_recalculee(&c, &Genese { entree_index: 4, ..g.clone() }).unwrap(), x);
        assert_ne!(lignee_recalculee(&coeur(3), &g).unwrap(), x, "autre agent : autre script, autre lignée");
        assert!(lignee_recalculee(&c, &Genese { valeurs: vec![], ..g.clone() }).is_err() && lignee_recalculee(&c, &Genese { valeurs: vec![1; 5], ..g }).is_err());
    }

    /// S7 : l'adresse de dépôt ne vient jamais de l'agent seul. Le payeur refait le calcul et vérifie
    /// la signature du propriétaire ; chaque falsification est refusée.
    #[test]
    fn fiche_de_depot_verifiee_cote_payeur() {
        let c = coeur(2);
        let f = fiche_de(&c, genese(1), 1);
        let sas = verifier_fiche(&f).expect("fiche honnête acceptée");
        assert_eq!(adresse_de(&vault_spk(&sas.artifact().unwrap())).unwrap().to_string(), f.adresse_depot);
        // 1. L'agent remplace l'adresse de dépôt par la sienne.
        let pirate = address(&k(2)).to_string();
        assert!(verifier_fiche(&Fiche { adresse_depot: pirate, ..f.clone() }).is_err(), "adresse de dépôt remplacée");
        // 2. Variante de la note Red Team : l'agent crée SA lignée à l'adresse du coffre et présente
        //    le sas de cette lignée. Tout se recalcule, sauf la signature du propriétaire.
        let fausse = fiche_de(&c, genese(7), 2);
        assert_ne!(fausse.adresse_depot, f.adresse_depot);
        assert_eq!(fausse.adresse_coffre, f.adresse_coffre, "même adresse de coffre : c'est bien le piège L1");
        assert!(verifier_fiche(&fausse).unwrap_err().to_string().contains("signée"), "sas d'une autre lignée, signé par l'agent");
        // 3. Il recopie la vraie signature sur sa fausse fiche.
        assert!(verifier_fiche(&Fiche { attestation: f.attestation.clone(), ..fausse.clone() }).is_err(), "signature recopiée");
        // 4. Il annonce une autre lignée, d'autres réglages, un autre plafond de frais, un dépôt minimal trop bas.
        assert!(verifier_fiche(&Fiche { lignee: fausse.lignee.clone(), ..f.clone() }).is_err(), "lignée remplacée");
        assert!(verifier_fiche(&Fiche { coffre: coeur(3).publics(), ..f.clone() }).is_err(), "réglages d'un autre coffre");
        assert!(verifier_fiche(&Fiche { max_frais_sompi: 2_000_000, ..f.clone() }).is_err(), "plafond de frais changé : autre sas");
        assert!(verifier_fiche(&Fiche { depot_minimal_sompi: 1, ..f.clone() }).is_err(), "dépôt minimal mensonger");
        assert!(verifier_fiche(&Fiche { version: "coeur-v0.7".into(), ..f.clone() }).is_err());
        // 5. Il se donne pour propriétaire : c'est alors un AUTRE coffre (autre adresse), pas celui du payeur.
        let sien = Coeur { owner: xonly(&k(2)), ..c.clone() };
        let f2 = fiche_de(&sien, genese(1), 2);
        assert!(verifier_fiche(&f2).is_ok() && f2.adresse_coffre != f.adresse_coffre, "un autre propriétaire, c'est un autre coffre : le payeur compare la clé du propriétaire à celle qu'il connaît");
        // La signature ne vaut que pour ce triplet.
        let (ca, x, da) = (Address::try_from(f.adresse_coffre.as_str()).unwrap(), hash32(&f.lignee).unwrap(), Address::try_from(f.adresse_depot.as_str()).unwrap());
        assert!(attestation_valide(&c.owner, &ca, &x, &da, &f.attestation));
        assert!(!attestation_valide(&c.owner, &da, &x, &ca, &f.attestation) && !attestation_valide(&c.agent, &ca, &x, &da, &f.attestation));
        assert!(!attestation_valide(&c.owner, &ca, &x, &da, "00") && !attestation_valide(&c.owner, &ca, &x, &da, "zz"));
    }

    /// Le sas d'un coffre est recalculé depuis sa création ; un fichier d'état modifié est refusé.
    #[test]
    fn sas_recalcule_depuis_l_etat() {
        let c = coeur(2);
        let g = genese(1);
        let x = lignee_recalculee(&c, &g).unwrap();
        let e = EtatCoeur { lignee: Some(x.to_string()), genese: Some(g), sas_max_frais: None, attestation: None, retraits: vec![], version: VERSION_V092.into(), retour: None, capacite: c.capacite, periode: c.periode, agent: hex::encode(&c.agent), cree_daa: 0, apports: vec![], vues: vec![], achats: vec![] };
        assert_eq!(sas_de(&c, &e).unwrap().id(), x);
        assert_eq!(coffre::lignee_de(Some(&e)), Some(x));
        assert!(sas_de(&c, &EtatCoeur { lignee: Some(hex::encode([5u8; 32])), ..e.clone() }).is_err(), "lignée du fichier ≠ lignée de la création");
        assert!(sas_de(&c, &EtatCoeur { genese: None, ..e.clone() }).is_err());
        assert!(sas_de(&c, &EtatCoeur { version: coffre::VERSION.into(), ..e.clone() }).is_err(), "coffre v0.7 : pas de sas");
        assert_eq!(coffre::lignee_de(Some(&EtatCoeur { version: coffre::VERSION.into(), ..e })), None);
    }

    /// L1 : seules les pièces de la lignée sont le coffre.
    #[test]
    fn filtrage_par_lignee() {
        let (x, y) = (Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32]));
        let p = |i: u32, l: Option<Hash>| Piece { lignee: l, outpoint: TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), i), valeur: 100_000_000, creation: Some(1) };
        let toutes = vec![p(0, Some(x)), p(1, None), p(2, Some(y)), p(3, Some(x))];
        let (dedans, dehors) = coffre::du_coffre(toutes.clone(), Some(x));
        assert_eq!((dedans.len(), dehors.len()), (2, 2));
        assert!(dedans.iter().all(|q| q.lignee == Some(x)) && dehors.iter().all(|q| q.lignee != Some(x)));
        // Coffre v0.7 (sans lignée) : comme avant, toutes les pièces de l'adresse.
        assert_eq!(coffre::du_coffre(toutes, None).0.len(), 4);
    }

    /// Reprise : le plus petit délai, un reste viable, des frais au-dessus du minimum de relais.
    #[test]
    fn reprise_preparee() {
        let c = coeur(2);
        let x = Hash::from_bytes([1; 32]);
        let rt = pay_to_address_script(&address(&k(11)));
        let p = |i: u32, v: u64, cr: u64| Piece { lignee: Some(x), outpoint: TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), i), valeur: v, creation: Some(cr) };
        let now = 100_000;
        // Deux pièces : la vieille est prête tout de suite, la jeune doit attendre.
        let ps = vec![p(0, 500_000_000, now - 5), p(1, 500_000_000, now - 50_000)];
        let (choisie, frais, attente) = preparer_reprise(&c, x, &ps, &rt, 100_000_000, now, &k(1)).unwrap();
        assert_eq!((choisie.outpoint.index, attente), (1, 0));
        let tx = lignee::build_retrait_partiel(&c, (choisie.outpoint, choisie.valeur), x, &rt, 100_000_000, frais, &k(1), None).unwrap();
        assert!(frais >= masse::frais_relais(&tx) && frais <= c.capacite as u64, "frais {frais} pour un minimum de {}", masse::frais_relais(&tx));
        assert_eq!(tx.inputs[0].sequence, c.attente(frais as i64));
        // La jeune seule : il faut attendre, et l'outil dit combien.
        let (_, f2, a2) = preparer_reprise(&c, x, &ps[..1], &rt, 100_000_000, now, &k(1)).unwrap();
        assert_eq!(a2, c.attente(f2 as i64) + MARGE - 5);
        // Tout reprendre, ou ne laisser qu'une miette : refusé, avec le maximum possible.
        let e = preparer_reprise(&c, x, &ps, &rt, 500_000_000 - plancher(), now, &k(1)).unwrap_err().to_string();
        assert!(e.contains("fermez le coffre"), "{e}");
        assert!(preparer_reprise(&c, x, &[], &rt, 1, now, &k(1)).is_err());
    }

    #[test]
    fn avertissement_selon_le_nombre_de_pieces() {
        let une = Regles::calculer(400_000_000, 36_000, 50_000_000).unwrap();
        assert_eq!(une.pieces, 1, "une pièce par défaut");
        assert!(avertissement_pieces(&une).starts_with("Une pièce"));
        let trois = Regles::calculer_k(400_000_000, 36_000, 50_000_000, Some(3)).unwrap();
        let texte = avertissement_pieces(&trois);
        assert!(texte.contains("multipliée par 3") && texte.contains("1.5 KAS") && texte.contains("définitif"), "{texte}");
    }
}

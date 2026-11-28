//! Essai sur testnet-10 du coffre à lignée (cœur v0.9.2) et de son sas (v0.2.1) : commande
//! `essai-lignee`. Fonds de test seulement. La séquence est celle des notes Red Team
//! (spec/red-team/lignee-2026-11-27.md, retrait-2026-11-27.md, coeur-v0.9.2-2026-11-28.md) :
//! création à deux pièces, dépôt au sas, versement SANS clé, paiement de l'agent, retrait partiel,
//! attaques réelles (S3 : poussière et dépôt détourné ; W10 : pièce de retour marquée), fermeture
//! (pièces, poussière et dépôt en attente dans la même transaction).
//! Chaque transaction est diffusée telle quelle : c'est le nœud qui accepte ou refuse. Les frais sont
//! cherchés en montant depuis le minimum théorique, pour mesurer ce que le réseau exige vraiment.

use std::time::Duration;

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_wrpc_client::KaspaRpcClient;
use secp256k1::Keypair;

use crate::coeur::Coeur;
use crate::lignee::{self, Sas};
use crate::{FEE, Res, address, explorer, sign, vault_spk, virtual_daa, xonly};

const KAS: u64 = 100_000_000;
/// Réglages de l'essai : 0,5 TKAS par paiement, période d'une minute (600 unités DAA).
const CAPACITE: i64 = 50_000_000;
const PERIODE: i64 = 600;
const PIECE: u64 = 3 * KAS;
const DEPOT: u64 = 2 * KAS;
const POUSSIERE: u64 = 20_000_000;

/// Une pièce lue sur le nœud.
#[derive(Clone)]
struct Vue {
    op: TransactionOutpoint,
    e: UtxoEntry,
}

async fn pieces_a(c: &KaspaRpcClient, spk: &ScriptPublicKey) -> Res<Vec<Vue>> {
    let adr = kaspa_txscript::extract_script_pub_key_address(spk, kaspa_addresses::Prefix::Testnet)?;
    Ok(c.get_utxos_by_addresses(vec![adr])
        .await?
        .into_iter()
        .filter(|u| u.utxo_entry.block_daa_score != u64::MAX)
        .map(|u| Vue { op: u.outpoint.into(), e: u.utxo_entry.into() })
        .collect())
}

/// Attend que la sortie `index` de la transaction `txid` soit inscrite à l'adresse `spk`.
async fn attendre(c: &KaspaRpcClient, spk: &ScriptPublicKey, txid: &str, index: u32) -> Res<Vue> {
    for _ in 0..240 {
        if let Some(v) = pieces_a(c, spk).await?.into_iter().find(|v| v.op.transaction_id.to_string() == txid && v.op.index == index) {
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!("la sortie {index} de {txid} n'est pas apparue en 120 s").into())
}

async fn attendre_daa(c: &KaspaRpcClient, cible: u64) -> Res<()> {
    loop {
        let now = virtual_daa(c).await?;
        if now >= cible {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(((cible - now) * 100).clamp(300, 5_000))).await;
    }
}

fn lignee_de(v: &Vue) -> String {
    v.e.covenant_id.map(|h| h.to_string()).unwrap_or_else(|| "aucune".into())
}

/// Masses et frais d'une transaction, sur une ligne.
fn mesure(tx: &Transaction, entries: &[UtxoEntry]) -> String {
    let entrees: u64 = entries.iter().map(|e| e.amount).sum();
    let sorties: u64 = tx.outputs.iter().map(|o| o.value).sum();
    let frais = entrees.saturating_sub(sorties);
    match crate::masse::masses(tx, entries) {
        Some(m) => {
            let masse = m.compute.max(m.transient).max(m.storage).max(1);
            format!("frais {frais} sompi ; masse calcul {} g, transitoire {} g, stockage {} g ; {:.1} sompi par gramme de la plus grande", m.compute, m.transient, m.storage, frais as f64 / masse as f64)
        }
        None => format!("frais {frais} sompi ; masse non calculable"),
    }
}

async fn diffuser(c: &KaspaRpcClient, tx: &Transaction) -> Result<String, String> {
    let rpc = crate::garde_diffusion(tx).map_err(|e| e.to_string())?;
    c.submit_transaction(rpc, false).await.map(|id| id.to_string()).map_err(|e| e.to_string())
}

/// Bilan de l'essai : chaque étape dit si le réseau a fait ce qui était attendu.
struct Bilan {
    ok: bool,
}
impl Bilan {
    fn accepte(&mut self, nom: &str, tx: &Transaction, entries: &[UtxoEntry], r: &Result<String, String>) -> Option<String> {
        match r {
            Ok(id) => {
                println!("[OK] {nom} : acceptée : {}\n     {}", explorer(id), mesure(tx, entries));
                Some(id.clone())
            }
            Err(e) => {
                println!("[ÉCHEC] {nom} : refusée par le nœud alors qu'elle devait passer\n     message du nœud : {e}");
                self.ok = false;
                None
            }
        }
    }
    fn refuse(&mut self, nom: &str, r: &Result<String, String>) {
        match r {
            Err(e) => println!("[OK] attaque « {nom} » : REFUSÉE par le réseau\n     message du nœud : {e}"),
            Ok(id) => {
                println!("[ALERTE] attaque « {nom} » : ACCEPTÉE alors qu'elle devait être refusée : {}", explorer(id));
                self.ok = false;
            }
        }
    }
}

/// Paiement ordinaire depuis une clé (propriétaire, attaquant) vers un script, sans lignée.
async fn envoyer(c: &KaspaRpcClient, de: &Keypair, vers: &ScriptPublicKey, montant: u64) -> Res<String> {
    let (entries, inputs, total) = crate::coffre::financer(c, de, montant).await?;
    let fee = FEE * inputs.len() as u64;
    let mut outputs = vec![TransactionOutput::new(montant, vers.clone())];
    if total - montant - fee > 0 {
        outputs.push(TransactionOutput::new(total - montant - fee, pay_to_address_script(&address(de))));
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..tx.inputs.len() {
        let s = sign(&tx, &entries, i, de);
        tx.inputs[i].signature_script = ScriptBuilder::new().add_data(&s)?.drain();
    }
    tx.finalize();
    Ok(c.submit_transaction(crate::garde_diffusion(&tx)?, false).await?.to_string())
}

/// Versement sans clé avec des frais croissants : renvoie la transaction acceptée et ses frais.
/// Les essais refusés montrent le minimum que le nœud exige (son message est affiché).
async fn verser_au_moins_cher(c: &KaspaRpcClient, b: &mut Bilan, coeur: &Coeur, sas: &Sas, piece: &Vue, depot: &Vue) -> Res<Option<(String, u64)>> {
    let entries = vec![piece.e.clone(), depot.e.clone()];
    let masse = {
        let tx = lignee::build_recharger(coeur, sas, (piece.op, piece.e.amount), (depot.op, depot.e.amount), 0)?;
        crate::masse::masses(&tx, &entries).map(|m| m.compute.max(m.transient).max(m.storage)).ok_or("masse non calculable")?
    };
    // 1, 2, 5, 10, 20, 50, 100, 200 sompi par gramme : le premier accepté donne le prix réel.
    for par_gramme in [1u64, 2, 5, 10, 20, 50, 100, 200] {
        let frais = masse * par_gramme;
        if frais as i64 > sas.max_frais {
            println!("     ({par_gramme} sompi/g = {frais} sompi : au-delà du plafond du sas, {} ; arrêt)", sas.max_frais);
            break;
        }
        let tx = lignee::build_recharger(coeur, sas, (piece.op, piece.e.amount), (depot.op, depot.e.amount), frais)?;
        match diffuser(c, &tx).await {
            Ok(id) => {
                println!("[OK] versement SANS clé (aucune signature dans la transaction) à {par_gramme} sompi/g : accepté et relayé : {}\n     {}", explorer(&id), mesure(&tx, &entries));
                return Ok(Some((id, frais)));
            }
            Err(e) => println!("     versement à {par_gramme} sompi/g ({frais} sompi) refusé : {e}"),
        }
    }
    println!("[ÉCHEC] versement sans clé : aucun niveau de frais accepté sous le plafond du sas");
    b.ok = false;
    Ok(None)
}

pub async fn lancer(c: &KaspaRpcClient, owner: &Keypair, agent: &Keypair, retour: &Keypair, vendeur: &ScriptPublicKey) -> Res<bool> {
    let mut b = Bilan { ok: true };
    let rt = pay_to_address_script(&address(retour));
    let coeur = Coeur { owner: xonly(owner), agent: xonly(agent), capacite: CAPACITE, periode: PERIODE, retour: Some(crate::sequestre::spk_hash(&rt).to_vec()) };
    let art = coeur.artifact_v092()?;
    let m = vault_spk(&art);
    println!("Essai du coffre à lignée : cœur v0.9.2 ({} octets), capacité {} TKAS par paiement, période {} unités DAA", crate::bytecode(&art).len(), CAPACITE as f64 / 1e8, PERIODE);
    println!("Adresse du coffre : {}", crate::coffre::adresse(&art)?);
    println!("Adresse de retour : {}", address(retour));

    // ------------------------------------------------------------------ 1. création (genèse), 2 pièces
    println!("\n== 1. Création : genèse à deux pièces ==");
    let (entries, inputs, total) = crate::coffre::financer(c, owner, 2 * PIECE).await?;
    let fonds: Vec<(TransactionOutpoint, UtxoEntry)> = inputs.iter().map(|i| i.previous_outpoint).zip(entries.iter().cloned()).collect();
    let rendu = total - 2 * PIECE - FEE * fonds.len() as u64;
    let (genese, x) = lignee::build_genese(&coeur, &fonds, &[PIECE, PIECE], (rendu > 0).then(|| (rendu, pay_to_address_script(&address(owner)))), owner)?;
    let r = diffuser(c, &genese).await;
    let Some(gid) = b.accepte("genèse (2 pièces, une lignée)", &genese, &entries, &r) else { return Ok(false) };
    println!("     lignée du coffre : {x}");
    let (p0, p1) = (attendre(c, &m, &gid, 0).await?, attendre(c, &m, &gid, 1).await?);
    for (i, p) in [&p0, &p1].iter().enumerate() {
        let bonne = p.e.covenant_id == Some(x);
        println!("     pièce {i} relue sur le nœud : {} TKAS, lignée {} {}", p.e.amount as f64 / 1e8, lignee_de(p), if bonne { "(celle du coffre)" } else { "(INATTENDUE)" });
        b.ok &= bonne;
    }

    // ------------------------------------------------------------------ 2. sas et dépôt ordinaire
    println!("\n== 2. Sas : adresse recalculée depuis la genèse, dépôt ordinaire ==");
    let sas = Sas::pour(&coeur, x, lignee::FRAIS_MAX_DEFAUT)?;
    let art_s = sas.artifact()?;
    let s = vault_spk(&art_s);
    println!("Adresse du sas (v0.2.1, {} octets, plafond de frais {} sompi) : {}", crate::bytecode(&art_s).len(), sas.max_frais, crate::coffre::adresse(&art_s)?);
    let did = envoyer(c, owner, &s, DEPOT).await?;
    println!("[OK] dépôt de {} TKAS envoyé au sas par un paiement ordinaire : {}", DEPOT as f64 / 1e8, explorer(&did));
    let depot = attendre(c, &s, &did, 0).await?;

    // ------------------------------------------------------------------ 3. versement sans clé
    println!("\n== 3. Versement SANS clé du dépôt dans la pièce 0 ==");
    let Some((vid, frais_versement)) = verser_au_moins_cher(c, &mut b, &coeur, &sas, &p0, &depot).await? else { return Ok(false) };
    let p0 = attendre(c, &m, &vid, 0).await?;
    println!("     pièce regonflée relue : {} TKAS, lignée {}", p0.e.amount as f64 / 1e8, lignee_de(&p0));
    b.ok &= p0.e.covenant_id == Some(x) && p0.e.amount == PIECE + DEPOT - frais_versement;
    // Frais des transactions signées de la suite : le même prix au gramme, avec une marge de moitié.
    let frais_de = |tx: &Transaction, entries: &[UtxoEntry], par_gramme: u64| crate::masse::masses(tx, entries).map(|m| m.compute.max(m.transient).max(m.storage) * par_gramme * 3 / 2).unwrap_or(FEE);
    let par_gramme = {
        let tx = lignee::build_recharger(&coeur, &sas, (p0.op, p0.e.amount), (depot.op, depot.e.amount), 0)?;
        let masse = crate::masse::masses(&tx, &[p0.e.clone(), depot.e.clone()]).map(|m| m.compute.max(m.transient).max(m.storage)).unwrap_or(1);
        (frais_versement / masse.max(1)).max(1)
    };
    println!("     prix retenu pour la suite : {par_gramme} sompi par gramme, plus une marge de moitié");

    // ------------------------------------------------------------------ 4. paiement de l'agent
    println!("\n== 4. Paiement de l'agent : trop tôt, puis à l'heure ==");
    let montant = 20_000_000u64;
    // Trop tôt : la pièce 0 vient d'être regonflée, son âge est presque nul.
    let brouillon = lignee::build_pay(&coeur, (p0.op, p0.e.amount), x, vendeur.clone(), montant, FEE, agent, None)?;
    let fp = frais_de(&brouillon, std::slice::from_ref(&p0.e), par_gramme);
    let tot = lignee::build_pay(&coeur, (p0.op, p0.e.amount), x, vendeur.clone(), montant, fp, agent, None)?;
    b.refuse("paiement de l'agent trop tôt (pièce qui vient d'être regonflée)", &diffuser(c, &tot).await);
    // À l'heure : la pièce 1 date de la genèse.
    attendre_daa(c, p1.e.block_daa_score + coeur.attente((montant + fp) as i64) + 30).await?;
    let pay = lignee::build_pay(&coeur, (p1.op, p1.e.amount), x, vendeur.clone(), montant, fp, agent, None)?;
    let r = diffuser(c, &pay).await;
    let Some(pid) = b.accepte("paiement de l'agent (0,2 TKAS au vendeur)", &pay, std::slice::from_ref(&p1.e), &r) else { return Ok(false) };
    let p1 = attendre(c, &m, &pid, 1).await?;
    println!("     reste relu : {} TKAS, lignée {}", p1.e.amount as f64 / 1e8, lignee_de(&p1));
    b.ok &= p1.e.covenant_id == Some(x);

    // ------------------------------------------------------------------ 5. retrait partiel
    println!("\n== 5. Retrait partiel par le propriétaire (pièce 0) ==");
    let repris = KAS;
    // Frais égaux à la capacité : il faudrait une période entière d'attente ; la pièce est trop jeune.
    let gourmand = lignee::build_retrait_partiel(&coeur, (p1.op, p1.e.amount), x, &rt, repris, CAPACITE as u64, owner, None)?;
    b.refuse("retrait partiel dont les frais vont plus vite que le rythme (pièce trop jeune)", &diffuser(c, &gourmand).await);
    let brouillon = lignee::build_retrait_partiel(&coeur, (p0.op, p0.e.amount), x, &rt, repris, FEE, owner, None)?;
    let fr = frais_de(&brouillon, std::slice::from_ref(&p0.e), par_gramme);
    println!("     frais {fr} sompi : attente exigée {} unités DAA après la création de la pièce", coeur.attente(fr as i64));
    attendre_daa(c, p0.e.block_daa_score + coeur.attente(fr as i64) + 30).await?;
    let rp = lignee::build_retrait_partiel(&coeur, (p0.op, p0.e.amount), x, &rt, repris, fr, owner, None)?;
    let r = diffuser(c, &rp).await;
    let Some(rid) = b.accepte("retrait partiel (1 TKAS vers l'adresse de retour)", &rp, std::slice::from_ref(&p0.e), &r) else { return Ok(false) };
    let p0 = attendre(c, &m, &rid, 0).await?;
    let repris_vu = attendre(c, &rt, &rid, 1).await?;
    println!("     reste relu : {} TKAS, lignée {} ; part reprise : {} TKAS à l'adresse de retour, lignée {}", p0.e.amount as f64 / 1e8, lignee_de(&p0), repris_vu.e.amount as f64 / 1e8, lignee_de(&repris_vu));
    b.ok &= p0.e.covenant_id == Some(x) && repris_vu.e.covenant_id.is_none();

    // ------------------------------------------------------------------ 6. attaques réelles
    println!("\n== 6. Attaques réelles : poussière (S3), dépôt détourné, pièce de retour marquée (W10) ==");
    let aid = envoyer(c, owner, &m, POUSSIERE).await?;
    println!("     poussière de {} TKAS envoyée à l'adresse du coffre (sans lignée) : {}", POUSSIERE as f64 / 1e8, explorer(&aid));
    let poussiere = attendre(c, &m, &aid, 0).await?;
    let did2 = envoyer(c, owner, &s, DEPOT).await?;
    println!("     second dépôt de {} TKAS au sas : {}", DEPOT as f64 / 1e8, explorer(&did2));
    let depot2 = attendre(c, &s, &did2, 0).await?;
    // S3 : faire verser le dépôt dans la poussière. Même transaction que le versement légitime, pièce changée.
    let fv = frais_versement;
    let vers_poussiere = |sortie: TransactionOutput| -> Res<Transaction> {
        let mut tx = lignee::build_recharger(&coeur, &sas, (poussiere.op, poussiere.e.amount), (depot2.op, depot2.e.amount), fv)?;
        tx.outputs[0] = sortie;
        tx.finalize();
        Ok(tx)
    };
    let total = poussiere.e.amount + depot2.e.amount - fv;
    b.refuse("S3 : dépôt versé dans la poussière, sortie sans lignée", &diffuser(c, &vers_poussiere(TransactionOutput::new(total, m.clone()))?).await);
    b.refuse("S3 : dépôt versé dans la poussière, sortie déclarée dans la lignée du coffre", &diffuser(c, &vers_poussiere(lignee::sortie_liee(total, m.clone(), x, 0))?).await);
    let neuve = {
        let out = TransactionOutput::new(total, m.clone());
        lignee::sortie_liee(total, m.clone(), covenant_id(poussiere.op, std::iter::once((0u32, &out))), 0)
    };
    b.refuse("S3 : dépôt versé dans la poussière adoptée par une lignée neuve", &diffuser(c, &vers_poussiere(neuve)?).await);
    // L'agent tente de payer avec la poussière (assez vieille pour un petit paiement).
    attendre_daa(c, poussiere.e.block_daa_score + coeur.attente((5_000_000 + fp) as i64) + 30).await?;
    for (nom, lien) in [("sans lignée", None), ("en déclarant la lignée du coffre", Some(x))] {
        let mut tx = lignee::build_pay(&coeur, (poussiere.op, poussiere.e.amount), x, vendeur.clone(), 5_000_000, fp, agent, None)?;
        tx.outputs[1].covenant = lien.map(|id| CovenantBinding { authorizing_input: 0, covenant_id: id });
        let entree = UtxoEntry::new(poussiere.e.amount, m.clone(), 0, false, None);
        let sig = sign(&tx, std::slice::from_ref(&entree), 0, agent);
        tx.inputs[0].signature_script = crate::vault_sigscript(&art, "pay", &[sig.into()])?;
        tx.finalize();
        b.refuse(&format!("l'agent paie avec la poussière, {nom}"), &diffuser(c, &tx).await);
    }
    // W10 : le propriétaire (ou sa clé volée) gèle une pièce en marquant la pièce de retour d'une lignée neuve.
    {
        let valeur = p1.e.amount;
        let fg = frais_de(&lignee::build_gel(&coeur, &[(p1.op, valeur, Some(x))], &rt, FEE, owner)?, std::slice::from_ref(&p1.e), par_gramme);
        let out = TransactionOutput::new(valeur - fg, rt.clone());
        let z = covenant_id(p1.op, std::iter::once((0u32, &out)));
        let mut tx = Transaction::new(1, vec![TransactionInput::new_with_compute_budget(p1.op, vec![], 0, lignee::CB_OWNER)], vec![lignee::sortie_liee(valeur - fg, rt.clone(), z, 0)], 0, Default::default(), 0, vec![]);
        let sig = sign(&tx, std::slice::from_ref(&p1.e), 0, owner);
        tx.inputs[0].signature_script = crate::vault_sigscript(&art, "ownerControl", &[sig.into()])?;
        tx.finalize();
        b.refuse("W10 : gel dont la pièce de retour naît marquée d'une lignée neuve", &diffuser(c, &tx).await);
    }
    // Le dépôt n'a pas bougé : il reste disponible pour le coffre ou pour le retour.
    let encore = pieces_a(c, &s).await?.iter().any(|v| v.op == depot2.op);
    println!("     le second dépôt est toujours au sas : {}", if encore { "oui" } else { "NON" });
    b.ok &= encore;

    // ------------------------------------------------------------------ 7. fermeture
    println!("\n== 7. Fermeture : pièces, poussière et dépôt en attente, en une transaction ==");
    let au_coffre = pieces_a(c, &m).await?;
    let au_sas = pieces_a(c, &s).await?;
    let pieces: Vec<(TransactionOutpoint, u64, Option<Hash>)> = au_coffre.iter().map(|v| (v.op, v.e.amount, v.e.covenant_id)).collect();
    let depots: Vec<(TransactionOutpoint, u64)> = au_sas.iter().map(|v| (v.op, v.e.amount)).collect();
    println!("     à fermer : {} pièce(s) à l'adresse du coffre (dont {} de la lignée), {} dépôt(s) au sas", pieces.len(), pieces.iter().filter(|p| p.2 == Some(x)).count(), depots.len());
    let entries: Vec<UtxoEntry> = au_coffre.iter().chain(au_sas.iter()).map(|v| v.e.clone()).collect();
    let brouillon = lignee::build_fermeture(&coeur, &sas, &pieces, &depots, &rt, FEE, FEE, owner)?;
    let par_entree = frais_de(&brouillon, &entries, par_gramme).div_ceil(entries.len() as u64);
    let fermeture = lignee::build_fermeture(&coeur, &sas, &pieces, &depots, &rt, par_entree, par_entree.min(sas.max_frais as u64), owner)?;
    let r = diffuser(c, &fermeture).await;
    let Some(fid) = b.accepte("fermeture (gel de toutes les pièces et retour du dépôt, ensemble)", &fermeture, &entries, &r) else { return Ok(false) };
    attendre(c, &rt, &fid, 0).await?;
    let (reste_coffre, reste_sas) = (pieces_a(c, &m).await?, pieces_a(c, &s).await?);
    println!("     après fermeture : {} pièce(s) à l'adresse du coffre, {} au sas", reste_coffre.len(), reste_sas.len());
    b.ok &= reste_coffre.is_empty() && reste_sas.is_empty();
    let chez_retour = pieces_a(c, &rt).await?;
    let ordinaires = chez_retour.iter().all(|v| v.e.covenant_id.is_none());
    println!("     adresse de retour : {} pièce(s), {} TKAS, toutes ordinaires (sans lignée) : {}", chez_retour.len(), chez_retour.iter().map(|v| v.e.amount).sum::<u64>() as f64 / 1e8, if ordinaires { "oui" } else { "NON" });
    b.ok &= ordinaires;
    // Après la fermeture, un dépôt tardif ne peut plus être versé : il n'existe plus de pièce de la lignée.
    println!("     plus aucune pièce ne porte la lignée {x} : un dépôt tardif attendrait le propriétaire (retour seulement)");

    // Les fonds de test reviennent au propriétaire de test.
    let total: u64 = chez_retour.iter().map(|v| v.e.amount).sum();
    if total > 2 * FEE * chez_retour.len() as u64 {
        match envoyer(c, retour, &pay_to_address_script(&address(owner)), total - FEE * chez_retour.len().min(20) as u64).await {
            Ok(id) => println!("\n(fonds de test rendus au propriétaire de test : {})", explorer(&id)),
            Err(e) => println!("\n(fonds de test restés à l'adresse de retour : {e})"),
        }
    }
    println!("\nVERDICT : {}", if b.ok { "tout s'est passé comme prévu." } else { "au moins une étape n'a pas eu le résultat attendu." });
    Ok(b.ok)
}

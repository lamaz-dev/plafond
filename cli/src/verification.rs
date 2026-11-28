//! Vérification d'un coffre à lignée PAR UN TIERS (payeur, vendeur, auditeur), sans confiance.
//! Protocole décrit dans spec/verification-sas.md ; rapport d'attaque spec/red-team/genese-2026-11-28.md.
//!
//! Ce module ne suppose rien de celui qui remet la fiche de dépôt, ni de l'outil qui a créé le
//! coffre, ni d'UN nœud. Trois niveaux, dans l'ordre :
//!  1. CALCUL (hors ligne) : `coffre092::verifier_fiche`. Script du coffre, lignée, script du sas et
//!     signature du propriétaire sont recalculés. L'identifiant de lignée est un hachage de la pièce
//!     dépensée par la création ET de toutes les sorties qui ouvrent la lignée (indice, valeur,
//!     script) : s'il se recalcule avec « k sorties au script du coffre », alors la création n'a pas
//!     pu ouvrir la lignée ailleurs ni avec un autre nombre de pièces (résistance de blake2b).
//!  2. GENÈSE RELUE (`auditer_genese`) : la transaction de création, relue sur le réseau, est
//!     comparée champ par champ à la fiche. Toute sortie de la lignée hors du script du coffre, tout
//!     écart de nombre, de valeur ou d'indice, toute lignée de plus ouverte à la même adresse est
//!     une anomalie nommée.
//!  3. ACCORD DE NŒUDS (`verdict`) : un nœud peut mentir sur ce qui existe. Au moins deux nœuds
//!     indépendants doivent donner EXACTEMENT la même création et les mêmes pièces vivantes.
//! « Adresse vérifiée » n'est prononcé que si les trois niveaux passent ; une création trop
//! ancienne pour être relue (blocs élagués) est dite telle, et le niveau 1 en reste la preuve.

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::tx::{ScriptPublicKey, Transaction, TransactionOutpoint};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::model::RpcDataVerbosityLevel;
use kaspa_wrpc_client::KaspaRpcClient;

use crate::coeur::Coeur;
use crate::coffre::{self, Genese, Piece};
use crate::coffre092::{self, Fiche};
use crate::{Res, vault_spk};

/// Nombre de nœuds indépendants exigés.
pub const QUORUM: usize = 2;
/// Blocs de chaîne parcourus au plus pour retrouver la création à partir de son repère (≈ 15 min).
const BLOCS_GENESE: usize = 10_000;

/// Ce que l'audit de la création établit.
#[derive(Debug, Clone, PartialEq)]
pub struct Audit {
    /// Nombre RÉEL de pièces ouvertes dans la lignée par la création : c'est le `k` de la borne.
    pub k: usize,
    pub valeurs: Vec<u64>,
}

fn hash32(hexa: &str) -> Result<Hash, String> {
    let o = hex::decode(hexa).map_err(|_| "identifiant illisible".to_string())?;
    Ok(Hash::from_bytes(<[u8; 32]>::try_from(o.as_slice()).map_err(|_| "identifiant : 32 octets attendus".to_string())?))
}

/// NIVEAU 2. Compare la transaction de création relue sur le réseau à ce que la fiche annonce.
/// `tx` vient d'un nœud : rien n'y est cru sur parole. Chaque refus nomme ce qui ne va pas.
pub fn auditer_genese(coeur: &Coeur, g: &Genese, x: Hash, tx: &Transaction) -> Result<Audit, String> {
    let s = vault_spk(&coeur.artifact_v092().map_err(|e| e.to_string())?);
    // La transaction présentée est-elle celle que la fiche nomme ? L'identifiant se recalcule : il
    // engage entrées, sorties et lignées déclarées (consensus-core, hashing/tx.rs).
    let mut copie = tx.clone();
    copie.finalize();
    if copie.id().to_string() != g.txid {
        return Err(format!("la transaction présentée ({}) n'est pas la création annoncée ({})", copie.id(), g.txid));
    }
    // L'identifiant de lignée naît de la pièce dépensée par l'entrée 0 : c'est elle qui rend la
    // lignée unique (une pièce ne se dépense qu'une fois).
    let entree = tx.inputs.first().ok_or("création sans entrée")?.previous_outpoint;
    if entree.transaction_id.to_string() != g.entree_txid || entree.index != g.entree_index {
        return Err("la création ne dépense pas la pièce annoncée en entrée 0 : ce n'est pas l'origine de cette lignée".into());
    }
    let dans_x: Vec<(usize, &kaspa_consensus_core::tx::TransactionOutput)> =
        tx.outputs.iter().enumerate().filter(|(_, o)| o.covenant.is_some_and(|b| b.covenant_id == x)).collect();
    if dans_x.is_empty() {
        return Err("cette transaction n'ouvre pas la lignée annoncée (continuation ou transaction étrangère présentée comme création ?)".into());
    }
    // Genèse hybride : une sortie de la lignée sous un autre script que celui du coffre.
    if let Some((i, _)) = dans_x.iter().find(|(_, o)| o.script_public_key != s) {
        return Err(format!("GENÈSE HYBRIDE : la sortie {i} porte la lignée du coffre mais n'est pas au script du coffre"));
    }
    if dans_x.iter().any(|(_, o)| o.covenant.is_some_and(|b| b.authorizing_input != 0)) {
        return Err("une sortie de la lignée n'est pas autorisée par l'entrée 0 : ce n'est pas la genèse de cette lignée".into());
    }
    // Genèse sur-allouée (ou sous-allouée) : le nombre réel de pièces n'est pas celui annoncé.
    if dans_x.len() != g.valeurs.len() {
        return Err(format!("NOMBRE DE PIÈCES : la fiche annonce {} pièce(s), la création en ouvre {} dans la lignée", g.valeurs.len(), dans_x.len()));
    }
    for (attendu, (i, o)) in dans_x.iter().enumerate() {
        if *i != attendu {
            return Err(format!("les pièces de la lignée ne sont pas les sorties 0 à {} de la création (sortie {i} inattendue)", g.valeurs.len() - 1));
        }
        if o.value != g.valeurs[attendu] {
            return Err(format!("valeur de la pièce {attendu} : {} annoncés, {} dans la création", g.valeurs[attendu], o.value));
        }
    }
    // Le calcul du réseau, refait ici sur la transaction lue : il doit redonner la lignée.
    let recalcule = kaspa_consensus_core::hashing::covenant_id::covenant_id(entree, dans_x.iter().map(|(i, o)| (*i as u32, *o)));
    if recalcule != x {
        return Err("l'identifiant de lignée ne se recalcule pas depuis cette transaction : ce n'est pas sa genèse (continuation présentée comme création ?)".into());
    }
    // Pièce cachée : une autre sortie de la création au script du coffre (sans lignée, ou dans une
    // autre lignée). Elle ne fait pas partie du coffre et ne peut pas recevoir de dépôt ; on refuse
    // quand même : une création propre n'en contient pas, et l'outil n'en produit jamais.
    if let Some((i, o)) = tx.outputs.iter().enumerate().find(|(_, o)| o.script_public_key == s && !o.covenant.is_some_and(|b| b.covenant_id == x)) {
        return Err(format!(
            "PIÈCE CACHÉE : la sortie {i} de la création est à l'adresse du coffre {}",
            if o.covenant.is_some() { "dans une AUTRE lignée" } else { "sans lignée" }
        ));
    }
    Ok(Audit { k: dans_x.len(), valeurs: g.valeurs.clone() })
}

/// Ce qu'UN nœud dit du coffre.
#[derive(Debug, Clone, PartialEq)]
pub struct Lecture {
    pub noeud: String,
    /// La transaction de création, si le nœud a pu la retrouver (`Err` : pourquoi il ne l'a pas pu).
    pub genese: Result<Transaction, String>,
    /// Toutes les pièces confirmées à l'adresse du coffre, triées.
    pub pieces: Vec<(TransactionOutpoint, u64, Option<Hash>)>,
}

/// Verdict d'une vérification complète.
#[derive(Debug, Clone, PartialEq)]
pub struct Rapport {
    pub k: usize,
    /// Pièces vivantes de la lignée, et leur valeur totale.
    pub vivantes: usize,
    pub valeur: u64,
    /// Autres pièces à la même adresse (autres lignées, sans lignée) : elles ne sont PAS le coffre.
    pub etrangeres: usize,
    pub autres_lignees: usize,
    /// Vrai si la création a été relue et auditée sur le réseau ; faux si elle n'était plus lisible
    /// (la preuve est alors le seul calcul de l'identifiant).
    pub genese_relue: bool,
    pub noeuds: Vec<String>,
    pub notes: Vec<String>,
}

fn id_tx(tx: &Transaction) -> String {
    let mut c = tx.clone();
    c.finalize();
    c.id().to_string()
}

/// NIVEAU 3. Rend un verdict à partir de la fiche et de ce que disent les nœuds interrogés.
/// Fonction pure : c'est elle que les tests attaquent (nœud menteur, nœuds en désaccord).
pub fn verdict(f: &Fiche, lectures: &[Lecture]) -> Result<Rapport, String> {
    // Niveau 1 : tout ce qui se recalcule, et la signature du propriétaire.
    coffre092::verifier_fiche(f).map_err(|e| e.to_string())?;
    let coeur = f.coffre.coeur().map_err(|e| e.to_string())?;
    let x = hash32(&f.lignee)?;
    let mut noeuds: Vec<&str> = lectures.iter().map(|l| l.noeud.as_str()).collect();
    noeuds.sort();
    noeuds.dedup();
    if noeuds.len() < QUORUM {
        return Err(format!("REFUSÉ : {} nœud(s) interrogé(s), il en faut au moins {QUORUM} indépendants pour dire « adresse vérifiée »", noeuds.len()));
    }
    // Accord exact sur les pièces vivantes.
    let premier = &lectures[0];
    for l in &lectures[1..] {
        if l.pieces != premier.pieces {
            return Err(format!("REFUSÉ : les nœuds {} et {} ne voient pas les mêmes pièces à l'adresse du coffre (l'un d'eux ment ou est en retard) : réessayez, ou utilisez votre propre nœud", premier.noeud, l.noeud));
        }
    }
    // Accord exact sur la création : même transaction partout où elle est lisible, et lisible
    // partout ou nulle part (un nœud qui « ne trouve pas » ce que l'autre montre est un désaccord).
    let lues: Vec<&Transaction> = lectures.iter().filter_map(|l| l.genese.as_ref().ok()).collect();
    if !lues.is_empty() && lues.len() != lectures.len() {
        return Err("REFUSÉ : un nœud montre la création du coffre et un autre ne la trouve pas".into());
    }
    if lues.windows(2).any(|w| id_tx(w[0]) != id_tx(w[1]) || w[0].outputs != w[1].outputs || w[0].inputs.len() != w[1].inputs.len()) {
        return Err("REFUSÉ : les nœuds ne montrent pas la même transaction de création".into());
    }
    let mut notes = vec![];
    let genese_relue = match lues.first() {
        Some(tx) => {
            // Niveau 2 : la création relue est auditée.
            let a = auditer_genese(&coeur, &f.genese, x, tx).map_err(|e| format!("REFUSÉ : {e}"))?;
            debug_assert_eq!(a.k, f.genese.valeurs.len());
            true
        }
        None => {
            notes.push(format!(
                "La création n'a pas pu être relue sur le réseau ({}). Elle reste prouvée par le calcul de l'identifiant de lignée, qui engage toutes ses sorties.",
                lectures[0].genese.as_ref().err().cloned().unwrap_or_default()
            ));
            false
        }
    };
    let k = f.genese.valeurs.len();
    let dans_x: Vec<&(TransactionOutpoint, u64, Option<Hash>)> = premier.pieces.iter().filter(|p| p.2 == Some(x)).collect();
    // L'invariant du contrat : jamais plus de pièces qu'à la création. Le voir violé sur le réseau
    // voudrait dire que la preuve, le réseau ou le nœud est en défaut : on refuse.
    if dans_x.len() > k {
        return Err(format!("REFUSÉ : {} pièces vivantes portent la lignée alors que la création n'en a ouvert que {k}", dans_x.len()));
    }
    if dans_x.is_empty() {
        return Err("REFUSÉ : aucune pièce vivante de cette lignée à l'adresse du coffre. Le coffre est fermé (ou n'a jamais existé) : un dépôt à cette adresse ne serait versé nulle part et attendrait le propriétaire".into());
    }
    let etrangeres = premier.pieces.len() - dans_x.len();
    let mut autres: Vec<Hash> = premier.pieces.iter().filter_map(|p| p.2).filter(|l| *l != x).collect();
    autres.sort();
    autres.dedup();
    if etrangeres > 0 {
        notes.push(format!(
            "{etrangeres} autre(s) pièce(s) à la même adresse ne font PAS partie de ce coffre ({} autre(s) lignée(s), {} sans lignée) : elles ne comptent pas et ne reçoivent aucun dépôt.",
            autres.len(),
            premier.pieces.iter().filter(|p| p.2.is_none()).count()
        ));
    }
    Ok(Rapport {
        k,
        vivantes: dans_x.len(),
        valeur: dans_x.iter().map(|p| p.1).sum(),
        etrangeres,
        autres_lignees: autres.len(),
        genese_relue,
        noeuds: noeuds.into_iter().map(String::from).collect(),
        notes,
    })
}

/// Pièces confirmées à une adresse, triées (pour comparer deux nœuds).
pub fn pieces_triees(ps: &[Piece]) -> Vec<(TransactionOutpoint, u64, Option<Hash>)> {
    let mut v: Vec<(TransactionOutpoint, u64, Option<Hash>)> = ps.iter().filter(|p| p.creation.is_some()).map(|p| (p.outpoint, p.valeur, p.lignee)).collect();
    v.sort_by_key(|p| (p.0.transaction_id.to_string(), p.0.index));
    v
}

/// Retrouve la transaction de création sur UN nœud, sans indexeur : parcours des blocs de chaîne
/// depuis le repère noté à la création. Le nœud renvoie les transactions acceptées, complètes.
pub async fn lire_genese(c: &KaspaRpcClient, g: &Genese) -> Result<Transaction, String> {
    let repere = g.repere.as_deref().ok_or("coffre créé avant le 28 nov. 2026 : pas de repère pour relire sa création")?;
    let mut depart: kaspa_rpc_core::RpcHash = repere.parse().map_err(|_| "repère illisible".to_string())?;
    let mut vus = 0usize;
    loop {
        let r = c
            .get_virtual_chain_from_block_v2(depart, Some(RpcDataVerbosityLevel::Full), None)
            .await
            .map_err(|e| format!("le nœud ne peut plus parcourir la chaîne depuis la création (blocs élagués ?) : {e}"))?;
        if r.added_chain_block_hashes.is_empty() {
            return Err("création introuvable après son repère".into());
        }
        for bloc in r.chain_block_accepted_transactions.iter() {
            for t in bloc.accepted_transactions.iter() {
                if t.verbose_data.as_ref().and_then(|v| v.transaction_id).is_some_and(|id| id.to_string() == g.txid) {
                    return Transaction::try_from(t.clone()).map_err(|e| format!("transaction de création illisible : {e}"));
                }
            }
        }
        vus += r.added_chain_block_hashes.len();
        let dernier = *r.added_chain_block_hashes.last().expect("non vide");
        if dernier == depart || vus >= BLOCS_GENESE {
            return Err("création introuvable dans les blocs qui suivent son repère".into());
        }
        depart = dernier;
    }
}

/// Ce qu'un nœud dit du coffre de la fiche.
pub async fn lire(c: &KaspaRpcClient, f: &Fiche) -> Res<Lecture> {
    let coeur = f.coffre.coeur()?;
    let art = coeur.artifact_v092()?;
    let pieces = pieces_triees(&coffre::pieces(c, &art).await?);
    Ok(Lecture { noeud: c.url().unwrap_or_default(), genese: lire_genese(c, &f.genese).await, pieces })
}

/// Ouvre des connexions vers `QUORUM` nœuds DIFFÉRENTS. Le nœud de l'utilisateur d'abord
/// (NOEUD_WRPC), puis un second nœud qu'il désigne (NOEUD_WRPC_2), sinon des nœuds publics choisis
/// par le découvreur du réseau, jusqu'à obtenir des adresses distinctes.
pub async fn noeuds() -> Res<Vec<KaspaRpcClient>> {
    let mut clients: Vec<KaspaRpcClient> = vec![];
    let fixes: Vec<String> = ["NOEUD_WRPC", "NOEUD_WRPC_2"].iter().filter_map(|v| std::env::var(v).ok()).map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
    for url in &fixes {
        if let Ok(c) = crate::client_vers(Some(url.as_str())).await {
            if !clients.iter().any(|d| d.url() == c.url()) {
                clients.push(c);
            }
        }
    }
    for _ in 0..12 {
        if clients.len() >= QUORUM {
            break;
        }
        if let Ok(c) = crate::client_vers(None).await {
            if clients.iter().any(|d| d.url() == c.url()) {
                let _ = c.disconnect().await;
            } else {
                clients.push(c);
            }
        }
    }
    if clients.len() < QUORUM {
        for c in &clients {
            let _ = c.disconnect().await;
        }
        return Err(format!("impossible de joindre {QUORUM} nœuds différents : vérification refusée (indiquez deux nœuds avec NOEUD_WRPC et NOEUD_WRPC_2)").into());
    }
    Ok(clients)
}

/// Vérification complète d'une fiche de dépôt, en ligne. Les nœuds sont relus jusqu'à trois fois
/// s'ils ne sont pas d'accord (une pièce peut être en cours d'inscription) ; sans accord exact, refus.
pub async fn verifier_en_ligne(f: &Fiche) -> Res<Rapport> {
    coffre092::verifier_fiche(f)?;
    let clients = noeuds().await?;
    let mut dernier: Result<Rapport, String> = Err("aucune lecture".into());
    for essai in 0..3 {
        if essai > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        let mut lectures = vec![];
        for c in &clients {
            match lire(c, f).await {
                Ok(l) => lectures.push(l),
                Err(e) => {
                    dernier = Err(format!("REFUSÉ : le nœud {} n'a pas répondu ({e})", c.url().unwrap_or_default()));
                    lectures.clear();
                    break;
                }
            }
        }
        if lectures.is_empty() {
            continue;
        }
        dernier = verdict(f, &lectures);
        // Seul un désaccord entre nœuds mérite un nouvel essai ; les autres refus sont définitifs.
        if !matches!(&dernier, Err(e) if e.contains("ne voient pas les mêmes pièces") || e.contains("ne la trouve pas")) {
            break;
        }
    }
    for c in &clients {
        let _ = c.disconnect().await;
    }
    Ok(dernier?)
}

/// Texte du verdict, pour la ligne de commande et la console.
pub fn texte(f: &Fiche, r: &Rapport) -> String {
    let mut t = format!(
        "ADRESSE VÉRIFIÉE : {}\n  coffre {} ; lignée {}\n  propriétaire (clé publique, à comparer avec celle que vous connaissez) : {}\n  pièces à la création : {} (c'est le k de la borne) ; pièces vivantes de la lignée : {} ; valeur : {} KAS\n  dépôt minimal versé automatiquement : {} KAS\n  création du coffre : {}\n  nœuds d'accord : {}",
        f.adresse_depot,
        f.adresse_coffre,
        f.lignee,
        f.coffre.owner,
        r.k,
        r.vivantes,
        r.valeur as f64 / 1e8,
        f.depot_minimal_sompi as f64 / 1e8,
        if r.genese_relue { "relue sur le réseau et auditée (toutes les sorties de la lignée sont au script du coffre)" } else { "non relue (voir note) ; prouvée par le calcul de l'identifiant" },
        r.noeuds.join(", ")
    );
    for n in &r.notes {
        t.push_str(&format!("\n  note : {n}"));
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lignee::{self, sortie_liee};
    use crate::{address, xonly};
    use kaspa_consensus_core::hashing::covenant_id::covenant_id;
    use kaspa_consensus_core::tx::{TransactionId, TransactionInput, TransactionOutput, UtxoEntry};
    use kaspa_txscript::pay_to_address_script;
    use secp256k1::Keypair;

    fn k(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }
    fn coeur() -> Coeur {
        Coeur { owner: xonly(&k(1)), agent: xonly(&k(2)), capacite: 50_000_000, periode: 36_000, retour: Some(coffre::empreinte_retour(&address(&k(11)))) }
    }
    fn s() -> ScriptPublicKey {
        vault_spk(&coeur().artifact_v092().unwrap())
    }
    fn pirate() -> ScriptPublicKey {
        pay_to_address_script(&address(&k(10)))
    }
    const V: u64 = 300_000_000;
    fn entree() -> TransactionOutpoint {
        TransactionOutpoint::new(TransactionId::from_bytes([9; 32]), 3)
    }
    /// Une création honnête de `n` pièces, construite par l'outil, et sa description.
    fn honnete(n: usize) -> (Transaction, Genese, Hash) {
        let fonds = [(entree(), UtxoEntry::new(10 * V, pay_to_address_script(&address(&k(1))), 5, false, None))];
        let (tx, x) = lignee::build_genese(&coeur(), &fonds, &vec![V; n], Some((V, pay_to_address_script(&address(&k(1))))), &k(1)).unwrap();
        let g = Genese { txid: tx.id().to_string(), entree_txid: entree().transaction_id.to_string(), entree_index: 3, valeurs: vec![V; n], repere: None };
        (tx, g, x)
    }
    /// Une création quelconque : sorties choisies, lignée = celle que le réseau calculerait pour
    /// les sorties `dans_x` (indices), autorisée par l'entrée 0.
    fn forgee(sorties: Vec<(u64, ScriptPublicKey)>, dans_x: &[usize]) -> (Transaction, Hash) {
        let mut outs: Vec<TransactionOutput> = sorties.into_iter().map(|(v, spk)| TransactionOutput::new(v, spk)).collect();
        let x = covenant_id(entree(), dans_x.iter().map(|i| (*i as u32, &outs[*i])));
        for i in dans_x {
            outs[*i] = sortie_liee(outs[*i].value, outs[*i].script_public_key.clone(), x, 0);
        }
        let mut tx = Transaction::new(1, vec![TransactionInput::new_with_compute_budget(entree(), vec![], 0, 15)], outs, 0, Default::default(), 0, vec![]);
        tx.finalize();
        (tx, x)
    }
    fn decrit(tx: &Transaction, valeurs: Vec<u64>) -> Genese {
        Genese { txid: tx.id().to_string(), entree_txid: entree().transaction_id.to_string(), entree_index: 3, valeurs, repere: None }
    }
    /// Le réseau accepterait-il cette création ? (contrôle des lignées par la fonction du nœud)
    fn valide_pour_le_reseau(tx: &Transaction) -> bool {
        let e = vec![UtxoEntry::new(10 * V, pay_to_address_script(&address(&k(1))), 5, false, None); tx.inputs.len()];
        kaspa_txscript::covenants::CovenantsContext::from_tx(&kaspa_consensus_core::tx::PopulatedTransaction::new(tx, e)).is_ok()
    }

    #[test]
    fn creation_honnete_auditee() {
        for n in 1..=4 {
            let (tx, g, x) = honnete(n);
            assert_eq!(auditer_genese(&coeur(), &g, x, &tx).unwrap(), Audit { k: n, valeurs: vec![V; n] });
            assert_eq!(coffre092::lignee_recalculee(&coeur(), &g).unwrap(), x, "le calcul hors ligne donne la même lignée");
        }
    }

    /// GENÈSES PIÉGÉES. Chacune est une transaction que le RÉSEAU ACCEPTERAIT (ses lignées sont
    /// valides pour KIP-20) : le piège est dans ce qu'on en dit au payeur. Critère : 100 % refusées,
    /// par l'audit de la transaction (niveau 2) ET par le seul calcul (niveau 1) quand la fiche ment.
    #[test]
    fn geneses_piegees_toutes_refusees() {
        let c = coeur();
        let (s, p) = (s(), pirate());
        let mut refusees = 0;
        let mut piege = |nom: &str, tx: &Transaction, x: Hash, g: Genese, motif: &str| {
            assert!(valide_pour_le_reseau(tx), "{nom} : le piège doit être une transaction que le réseau accepte");
            let e = auditer_genese(&c, &g, x, tx).err().unwrap_or_else(|| panic!("GENÈSE PIÉGÉE ACCEPTÉE : {nom}"));
            assert!(e.contains(motif), "{nom} : refusée, mais pas pour la bonne raison : {e}");
            // Niveau 1 : la lignée de la fiche ne se recalcule pas comme « k pièces au script du coffre ».
            assert_ne!(coffre092::lignee_recalculee(&c, &g).ok(), Some(x), "{nom} : le calcul hors ligne devait aussi échouer");
            refusees += 1;
        };
        // 1. Hybride : deux sorties dans la lignée, l'une au coffre, l'autre chez l'attaquant.
        let (tx, x) = forgee(vec![(V, s.clone()), (V, p.clone())], &[0, 1]);
        piege("hybride (2 sorties X, une au script d'un attaquant)", &tx, x, decrit(&tx, vec![V]), "GENÈSE HYBRIDE");
        piege("hybride, annoncée à deux pièces", &tx, x, decrit(&tx, vec![V, V]), "GENÈSE HYBRIDE");
        // 2. Hybride inversée : la pièce de l'attaquant d'abord.
        let (tx, x) = forgee(vec![(V, p.clone()), (V, s.clone())], &[0, 1]);
        piege("hybride, pièce de l'attaquant en sortie 0", &tx, x, decrit(&tx, vec![V]), "GENÈSE HYBRIDE");
        // 3. Sur-allouée : une pièce annoncée, trois réelles (trois rythmes au lieu d'un).
        let (tx, x) = forgee(vec![(V, s.clone()), (V, s.clone()), (V, s.clone())], &[0, 1, 2]);
        piege("sur-allouée (k annoncé 1, réel 3)", &tx, x, decrit(&tx, vec![V]), "NOMBRE DE PIÈCES");
        piege("sur-allouée (k annoncé 2, réel 3)", &tx, x, decrit(&tx, vec![V, V]), "NOMBRE DE PIÈCES");
        // 4. Sous-allouée : quatre annoncées, une réelle.
        let (tx, x) = forgee(vec![(V, s.clone())], &[0]);
        piege("sous-allouée (k annoncé 4, réel 1)", &tx, x, decrit(&tx, vec![V; 4]), "NOMBRE DE PIÈCES");
        // 5. Valeurs inattendues.
        piege("valeur annoncée fausse", &tx, x, decrit(&tx, vec![V + 1]), "valeur de la pièce");
        // 6. Pièces de la lignée ailleurs qu'en sorties 0..k.
        let (tx, x) = forgee(vec![(V, p.clone()), (V, s.clone())], &[1]);
        piege("pièce de la lignée en sortie 1, un tiers en sortie 0", &tx, x, decrit(&tx, vec![V]), "sorties 0 à");
        // 7. Script inattendu : toute la lignée chez l'attaquant, présentée comme un coffre.
        let (tx, x) = forgee(vec![(V, p.clone())], &[0]);
        piege("lignée ouverte sous le script d'un attaquant", &tx, x, decrit(&tx, vec![V]), "GENÈSE HYBRIDE");
        // 8. Autre coffre du même propriétaire (autre agent) présenté pour celui-ci.
        let autre = vault_spk(&Coeur { agent: xonly(&k(3)), ..coeur() }.artifact_v092().unwrap());
        let (tx, x) = forgee(vec![(V, autre)], &[0]);
        piege("genèse d'un autre coffre (autre agent)", &tx, x, decrit(&tx, vec![V]), "GENÈSE HYBRIDE");
        assert_eq!(refusees, 10);

        // --- pièges où la fiche dit vrai sur la lignée, mais où la transaction cache autre chose
        let mut cache = |nom: &str, tx: &Transaction, x: Hash, g: Genese, motif: &str| {
            assert!(valide_pour_le_reseau(tx), "{nom}");
            let e = auditer_genese(&c, &g, x, tx).err().unwrap_or_else(|| panic!("GENÈSE PIÉGÉE ACCEPTÉE : {nom}"));
            assert!(e.contains(motif), "{nom} : {e}");
            refusees += 1;
        };
        // 9. Pièce cachée sans lignée à l'adresse du coffre, dans la création.
        let (tx, x) = forgee(vec![(V, s.clone()), (V, s.clone())], &[0]);
        cache("pièce cachée sans lignée à l'adresse du coffre", &tx, x, decrit(&tx, vec![V]), "PIÈCE CACHÉE");
        // 10. Seconde lignée ouverte à l'adresse du coffre dans la même création.
        let (mut tx, x) = forgee(vec![(V, s.clone()), (V, s.clone())], &[0]);
        let y = covenant_id(entree(), std::iter::once((1u32, &TransactionOutput::new(V, s.clone()))));
        tx.outputs[1] = sortie_liee(V, s.clone(), y, 0);
        tx.finalize();
        cache("seconde lignée à l'adresse du coffre dans la même création", &tx, x, decrit(&tx, vec![V]), "AUTRE lignée");
        assert_eq!(refusees, 12);
    }

    /// Pièges qui ne sont pas des créations : transaction étrangère, continuation, autre pièce dépensée.
    #[test]
    fn fausses_geneses_refusees() {
        let c = coeur();
        let (tx, g, x) = honnete(2);
        // La bonne description, une autre transaction.
        let (autre, _, _) = honnete(3);
        assert!(auditer_genese(&c, &g, x, &autre).unwrap_err().contains("n'est pas la création annoncée"));
        // Continuation présentée comme genèse : un paiement de l'agent (le reste garde la lignée).
        let pay = lignee::build_pay(&c, (TransactionOutpoint::new(tx.id(), 0), V), x, pirate(), 10_000_000, 1_500_000, &k(2), None).unwrap();
        let g_pay = Genese { txid: pay.id().to_string(), entree_txid: tx.id().to_string(), entree_index: 0, valeurs: vec![V - 11_500_000], repere: None };
        let e = auditer_genese(&c, &g_pay, x, &pay).unwrap_err();
        assert!(e.contains("sorties 0 à") || e.contains("ne se recalcule pas"), "{e}");
        assert_ne!(coffre092::lignee_recalculee(&c, &g_pay).unwrap(), x, "une continuation ne redonne jamais l'identifiant : il faut remonter à la vraie création");
        // Même pour une continuation dont le reste serait en sortie 0 (retrait partiel) : le calcul refuse.
        let rp = lignee::build_retrait_partiel(&c, (TransactionOutpoint::new(tx.id(), 0), V), x, &pay_to_address_script(&address(&k(11))), V / 2, 1_000_000, &k(1), None).unwrap();
        let g_rp = Genese { txid: rp.id().to_string(), entree_txid: tx.id().to_string(), entree_index: 0, valeurs: vec![V / 2 - 1_000_000], repere: None };
        assert!(auditer_genese(&c, &g_rp, x, &rp).unwrap_err().contains("ne se recalcule pas"));
        // Autre pièce dépensée annoncée ; identifiant inattendu ; transaction sans rapport.
        assert!(auditer_genese(&c, &Genese { entree_index: 4, ..g.clone() }, x, &tx).unwrap_err().contains("pièce annoncée en entrée 0"));
        assert!(auditer_genese(&c, &g, Hash::from_bytes([7; 32]), &tx).unwrap_err().contains("n'ouvre pas la lignée"));
        // Un octet de la transaction changé par le nœud : l'identifiant ne correspond plus.
        let mut modifiee = tx.clone();
        modifiee.outputs[2].value += 1;
        assert!(auditer_genese(&c, &g, x, &modifiee).unwrap_err().contains("n'est pas la création annoncée"));
    }

    // ------------------------------------------------------------------ verdict : fiches et nœuds

    fn fiche(n: usize, signataire: u8) -> (Fiche, Transaction, Hash) {
        let (tx, g, x) = honnete(n);
        (coffre092::fiche_d_essai(&coeur(), g, &k(signataire)), tx, x)
    }
    fn piece(tx: &Transaction, i: u32, l: Option<Hash>) -> (TransactionOutpoint, u64, Option<Hash>) {
        (TransactionOutpoint::new(tx.id(), i), V, l)
    }
    fn lecture(noeud: &str, tx: &Transaction, pieces: Vec<(TransactionOutpoint, u64, Option<Hash>)>) -> Lecture {
        Lecture { noeud: noeud.into(), genese: Ok(tx.clone()), pieces }
    }

    #[test]
    fn adresse_verifiee_seulement_avec_deux_noeuds_d_accord() {
        let (f, tx, x) = fiche(2, 1);
        let vivantes = vec![piece(&tx, 0, Some(x)), piece(&tx, 1, Some(x))];
        let r = verdict(&f, &[lecture("a", &tx, vivantes.clone()), lecture("b", &tx, vivantes.clone())]).unwrap();
        assert_eq!((r.k, r.vivantes, r.valeur, r.etrangeres, r.genese_relue), (2, 2, 2 * V, 0, true));
        assert!(texte(&f, &r).starts_with("ADRESSE VÉRIFIÉE"));
        // Un seul nœud, ou deux fois le même : pas de verdict.
        assert!(verdict(&f, &[lecture("a", &tx, vivantes.clone())]).unwrap_err().contains("au moins 2"));
        assert!(verdict(&f, &[lecture("a", &tx, vivantes.clone()), lecture("a", &tx, vivantes.clone())]).unwrap_err().contains("au moins 2"));
        // Trois nœuds d'accord : accepté.
        assert!(verdict(&f, &[lecture("a", &tx, vivantes.clone()), lecture("b", &tx, vivantes.clone()), lecture("c", &tx, vivantes)]).is_ok());
    }

    /// Un nœud qui ment : pièce cachée, pièce inventée, valeur changée, lignée changée, création
    /// remplacée ou « introuvable ». Le désaccord avec l'autre nœud suffit à refuser.
    #[test]
    fn noeud_menteur_refuse() {
        let (f, tx, x) = fiche(2, 1);
        let vrai = vec![piece(&tx, 0, Some(x)), piece(&tx, 1, Some(x))];
        let honnete = lecture("honnete", &tx, vrai.clone());
        let inventee = TransactionOutpoint::new(TransactionId::from_bytes([0xEE; 32]), 0);
        let mensonges: Vec<(&str, Lecture)> = vec![
            ("cache une pièce", lecture("menteur", &tx, vrai[..1].to_vec())),
            ("cache tout (coffre « fermé »)", lecture("menteur", &tx, vec![])),
            ("invente une pièce de la lignée", lecture("menteur", &tx, vec![vrai[0], vrai[1], (inventee, V, Some(x))])),
            ("gonfle une valeur", lecture("menteur", &tx, vec![(vrai[0].0, 100 * V, Some(x)), vrai[1]])),
            ("retire la lignée d'une pièce", lecture("menteur", &tx, vec![(vrai[0].0, V, None), vrai[1]])),
            ("ne trouve pas la création", Lecture { noeud: "menteur".into(), genese: Err("introuvable".into()), pieces: vrai.clone() }),
            ("montre une autre création", lecture("menteur", &super::tests::honnete(3).0, vrai.clone())),
        ];
        for (nom, l) in mensonges {
            let e = verdict(&f, &[honnete.clone(), l.clone()]).err().unwrap_or_else(|| panic!("nœud menteur cru : {nom}"));
            assert!(e.starts_with("REFUSÉ"), "{nom} : {e}");
            assert!(verdict(&f, &[l, honnete.clone()]).is_err(), "{nom}, dans l'autre ordre");
        }
        // Deux nœuds complices qui montrent la même fausse création : l'audit de la transaction refuse.
        let (hybride, xh) = forgee(vec![(V, s()), (V, pirate())], &[0, 1]);
        let g = decrit(&hybride, vec![V]);
        let fausse = Fiche { genese: g, ..f.clone() };
        let _ = xh;
        assert!(verdict(&fausse, &[lecture("a", &hybride, vrai.clone()), lecture("b", &hybride, vrai.clone())]).is_err(), "la fiche ne se recalcule plus");
        // Deux nœuds complices qui inventent des pièces vivantes au-delà de k : refusé (invariant).
        let trop = vec![vrai[0], vrai[1], (inventee, V, Some(x))];
        assert!(verdict(&f, &[lecture("a", &tx, trop.clone()), lecture("b", &tx, trop)]).unwrap_err().contains("n'en a ouvert que 2"));
    }

    /// Les fiches adversariales de la mission. Toutes refusées, avec des nœuds honnêtes.
    #[test]
    fn fiches_adversariales_refusees() {
        let (f, tx, x) = fiche(1, 1);
        let vivantes = vec![piece(&tx, 0, Some(x))];
        let noeuds = |ps: Vec<(TransactionOutpoint, u64, Option<Hash>)>, t: &Transaction| vec![lecture("a", t, ps.clone()), lecture("b", t, ps)];
        assert!(verdict(&f, &noeuds(vivantes.clone(), &tx)).is_ok(), "témoin");
        // 1. Fiche valide en apparence, mais sas d'une lignée Y ouverte par l'agent à la MÊME adresse.
        let (ty, y) = forgee(vec![(V, s())], &[0]);
        let gy = Genese { entree_txid: hex::encode([0x77; 32]), ..decrit(&ty, vec![V]) };
        let fy = coffre092::fiche_d_essai(&coeur(), gy, &k(2));
        assert_eq!(fy.adresse_coffre, f.adresse_coffre);
        assert_ne!(fy.adresse_depot, f.adresse_depot);
        let _ = y;
        assert!(verdict(&fy, &noeuds(vivantes.clone(), &ty)).unwrap_err().contains("signée"), "sas d'une autre lignée, signé par l'agent");
        // 2. Signature recopiée de la vraie fiche.
        assert!(verdict(&Fiche { attestation: f.attestation.clone(), ..fy.clone() }, &noeuds(vivantes.clone(), &ty)).is_err());
        // 3. Vraie fiche, adresse de dépôt remplacée.
        assert!(verdict(&Fiche { adresse_depot: address(&k(2)).to_string(), ..f.clone() }, &noeuds(vivantes.clone(), &tx)).is_err());
        // 4. Ancien sas : fiche authentique d'un coffre FERMÉ (plus aucune pièce de la lignée), y
        //    compris si une pièce d'une autre lignée ou sans lignée traîne à l'adresse.
        assert!(verdict(&f, &noeuds(vec![], &tx)).unwrap_err().contains("fermé"));
        let poussiere = vec![(TransactionOutpoint::new(TransactionId::from_bytes([0xAA; 32]), 0), V, None), (TransactionOutpoint::new(TransactionId::from_bytes([0xAB; 32]), 0), V, Some(Hash::from_bytes([0xB2; 32])))];
        assert!(verdict(&f, &noeuds(poussiere.clone(), &tx)).unwrap_err().contains("fermé"), "des pièces étrangères ne font pas un coffre ouvert");
        // 5. Coffre ouvert avec des pièces étrangères à la même adresse : accepté, et elles sont comptées à part.
        let mut melange = vivantes.clone();
        melange.extend(poussiere);
        melange.sort_by_key(|p| (p.0.transaction_id.to_string(), p.0.index));
        let r = verdict(&f, &noeuds(melange, &tx)).unwrap();
        assert_eq!((r.vivantes, r.valeur, r.etrangeres, r.autres_lignees), (1, V, 2, 1), "seule la lignée du coffre compte");
        assert!(r.notes.iter().any(|n| n.contains("ne font PAS partie")));
        // 6. Création non relisible sur les deux nœuds (blocs élagués) : accepté, mais dit.
        let vieux: Vec<Lecture> = ["a", "b"].iter().map(|n| Lecture { noeud: n.to_string(), genese: Err("blocs élagués".into()), pieces: vivantes.clone() }).collect();
        let r = verdict(&f, &vieux).unwrap();
        assert!(!r.genese_relue && texte(&f, &r).contains("non relue"));
    }
}

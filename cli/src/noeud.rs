//! Retrouver un coffre SANS indexeur public : parcours de la chaîne d'un nœud Kaspa.
//!
//! Le mode survie (`retrouver`) suit la lignée d'un coffre depuis son origine. Il s'appuie d'abord sur
//! l'API REST publique ; si elle est injoignable ou en retard, cette source prend le relais avec le seul
//! nœud déjà utilisé pour diffuser : `get_virtual_chain_from_block_v2` (verbosité complète) renvoie, bloc
//! de chaîne après bloc de chaîne, les transactions ACCEPTÉES et le score DAA du bloc qui les accepte.
//!
//! Le parcours part d'un REPÈRE : le bloc de tête du réseau noté juste avant la création du coffre
//! (fichier `<état>-repere.txt`). Seules les transactions qui descendent de l'origine (elles dépensent
//! une sortie d'une transaction déjà retenue) sont gardées : la mémoire reste petite.
//!
//! Comme avec l'indexeur, rien n'est cru : `retrouver` recalcule chaque saut et exige qu'il retombe
//! exactement sur le script publié ; le coffre trouvé est ensuite confirmé auprès du nœud.

use crate::retrouver::{Source, TxInfo};
use crate::Res;
use kaspa_rpc_core::model::{RpcDataVerbosityLevel, RpcOptionalTransaction};
use kaspa_wrpc_client::prelude::*;
use std::collections::{HashMap, HashSet};

/// Nombre maximal de blocs de chaîne parcourus (≈ 2 jours à 10 blocs par seconde).
const BLOCS_MAX: usize = 2_000_000;

pub fn chemin_repere(etat: &str) -> String {
    etat.replace(".json", "-repere.txt")
}

/// Bloc de tête actuel du réseau, à noter AVANT de diffuser la création d'un coffre.
pub async fn tete(c: &KaspaRpcClient) -> Res<String> {
    Ok(c.get_sink().await?.sink.to_string())
}

pub fn ecrire_repere(etat: &str, hash: &str) -> Res<()> {
    std::fs::write(chemin_repere(etat), hash)?;
    Ok(())
}

pub fn lire_repere(etat: &str) -> Option<String> {
    std::fs::read_to_string(chemin_repere(etat)).ok().map(|s| s.trim().to_string()).filter(|s| s.len() == 64)
}

/// Index en mémoire des transactions de la lignée (logique pure, testable sans réseau).
#[derive(Default, Clone)]
pub struct Lignee {
    retenues: HashSet<String>,
    txs: HashMap<String, TxInfo>,
    ordre: Vec<String>,
    daa: HashMap<String, i64>,
}

impl Lignee {
    pub fn depuis(origine_txid: &str) -> Self {
        let mut l = Lignee::default();
        l.retenues.insert(origine_txid.to_lowercase());
        l
    }

    /// Ajoute un bloc de chaîne et les transactions qu'il accepte, dans l'ordre de la chaîne.
    pub fn bloc(&mut self, hash: &str, daa: i64, txs: Vec<TxInfo>) {
        let mut garde = false;
        for t in txs {
            let id = t.txid.to_lowercase();
            let descend = self.retenues.contains(&id) || t.entrees.iter().any(|(h, _, _)| self.retenues.contains(&h.to_lowercase()));
            if descend && !self.txs.contains_key(&id) {
                self.retenues.insert(id.clone());
                self.ordre.push(id.clone());
                self.txs.insert(id, TxInfo { bloc_acceptant: Some(hash.to_string()), acceptee: true, ..t });
                garde = true;
            }
        }
        if garde {
            self.daa.insert(hash.to_string(), daa);
        }
    }

    pub fn taille(&self) -> usize {
        self.txs.len()
    }
}

impl Source for Lignee {
    /// Toutes les transactions de la lignée : `retrouver` y cherche la dépense de la sortie courante.
    fn transactions_adresse(&self, _adresse: &str) -> Res<Vec<TxInfo>> {
        Ok(self.ordre.iter().filter_map(|id| self.txs.get(id).cloned()).collect())
    }
    fn transaction(&self, txid: &str) -> Res<TxInfo> {
        self.txs.get(&txid.to_lowercase()).cloned().ok_or_else(|| format!("transaction {txid} absente du parcours du nœud (repère trop récent ?)").into())
    }
    fn daa_bloc(&self, hash: &str) -> Res<i64> {
        self.daa.get(hash).copied().ok_or_else(|| format!("bloc {hash} absent du parcours du nœud").into())
    }
}

/// Conversion d'une transaction acceptée (verbosité complète) vers la forme lue par `retrouver`.
pub fn tx_info(t: &RpcOptionalTransaction) -> Option<TxInfo> {
    let txid = t.verbose_data.as_ref()?.transaction_id?.to_string();
    let entrees = t
        .inputs
        .iter()
        .filter_map(|i| {
            let p = i.previous_outpoint.as_ref()?;
            Some((p.transaction_id?.to_string(), p.index?, i.signature_script.clone().unwrap_or_default()))
        })
        .collect();
    let sorties = t
        .outputs
        .iter()
        .enumerate()
        .filter_map(|(k, o)| {
            let cov = o.covenant.as_ref().and_then(|c| c.0.as_ref()).map(|b| b.0.covenant_id.to_string());
            Some((k as u32, o.value?, o.script_public_key.as_ref()?.script().to_vec(), cov))
        })
        .collect();
    Some(TxInfo { txid, acceptee: true, bloc_acceptant: None, entrees, sorties })
}

/// Dernier parcours, gardé en mémoire : le tableau de bord se rafraîchit souvent, on ne relit que les
/// blocs nouveaux. En cas de réorganisation de la chaîne, on repart du repère.
static CACHE: std::sync::Mutex<Option<(String, String, Lignee)>> = std::sync::Mutex::new(None);

/// Index de la lignée d'après le seul nœud, du repère jusqu'à la tête actuelle.
pub async fn lignee(c: &KaspaRpcClient, repere: &str, origine_txid: &str) -> Res<Lignee> {
    let cle = format!("{repere}:{origine_txid}");
    let reprise = CACHE.lock().ok().and_then(|g| g.as_ref().filter(|(k, _, _)| *k == cle).map(|(_, h, l)| (h.clone(), l.clone())));
    let (mut depart, mut l, reprise) = match reprise {
        Some((h, l)) => (h, l, true),
        None => (repere.to_string(), Lignee::depuis(origine_txid), false),
    };
    let mut vus = 0usize;
    loop {
        let h: kaspa_rpc_core::RpcHash = depart.parse().map_err(|_| "repère illisible")?;
        let r = c.get_virtual_chain_from_block_v2(h, Some(RpcDataVerbosityLevel::Full), None).await?;
        if reprise && vus == 0 && !r.removed_chain_block_hashes.is_empty() {
            // Réorganisation depuis le dernier parcours : on oublie tout et on repart du repère.
            if let Ok(mut g) = CACHE.lock() {
                *g = None;
            }
            return Box::pin(lignee(c, repere, origine_txid)).await;
        }
        if r.added_chain_block_hashes.is_empty() {
            break;
        }
        for (k, bloc) in r.chain_block_accepted_transactions.iter().enumerate() {
            let hash = bloc.chain_block_header.hash.or_else(|| r.added_chain_block_hashes.get(k).copied());
            let (Some(hash), Some(daa)) = (hash, bloc.chain_block_header.daa_score) else { continue };
            l.bloc(&hash.to_string(), daa as i64, bloc.accepted_transactions.iter().filter_map(tx_info).collect());
        }
        vus += r.added_chain_block_hashes.len();
        let dernier = r.added_chain_block_hashes.last().expect("non vide").to_string();
        if dernier == depart || vus >= BLOCS_MAX {
            break;
        }
        depart = dernier;
    }
    if vus > 0 || !reprise {
        eprintln!("Parcours du nœud : {vus} nouveau(x) bloc(s) de chaîne, {} transaction(s) dans la lignée", l.taille());
    }
    if let Ok(mut g) = CACHE.lock() {
        *g = Some((cle, depart, l.clone()));
    }
    Ok(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(id: &str, entrees: &[(&str, u32)]) -> TxInfo {
        TxInfo {
            txid: id.into(),
            acceptee: false,
            bloc_acceptant: None,
            entrees: entrees.iter().map(|(h, i)| (h.to_string(), *i, vec![])).collect(),
            sorties: vec![(0, 1, vec![], None), (1, 2, vec![], None)],
        }
    }

    #[test]
    fn ne_garde_que_la_lignee_et_note_les_blocs_d_acceptation() {
        let mut l = Lignee::depuis("AA");
        l.bloc("b1", 100, vec![tx("aa", &[("zz", 0)]), tx("x1", &[("zz", 1)])]);
        l.bloc("b2", 200, vec![tx("x2", &[("x1", 0)])]);
        l.bloc("b3", 300, vec![tx("p1", &[("aa", 0)]), tx("s1", &[("p1", 0)])]);
        l.bloc("b4", 400, vec![tx("p2", &[("p1", 1)])]);
        let ids: Vec<String> = l.transactions_adresse("").unwrap().into_iter().map(|t| t.txid).collect();
        assert_eq!(ids, ["aa", "p1", "s1", "p2"], "origine, sa descendance, rien d'autre, dans l'ordre de la chaîne");
        assert_eq!(l.transaction("P1").unwrap().bloc_acceptant.as_deref(), Some("b3"));
        assert!(l.transaction("p1").unwrap().acceptee);
        assert_eq!(l.daa_bloc("b3").unwrap(), 300);
        assert!(l.daa_bloc("b2").is_err(), "bloc sans transaction de la lignée : non retenu");
        assert!(l.transaction("x1").is_err());
    }

    #[test]
    fn conversion_d_une_transaction_du_noeud() {
        use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId};
        use kaspa_rpc_core::model::*;
        let id = TransactionId::from_bytes([3; 32]);
        let prec = TransactionId::from_bytes([4; 32]);
        let t = RpcOptionalTransaction {
            version: None,
            inputs: vec![RpcOptionalTransactionInput {
                previous_outpoint: Some(RpcOptionalTransactionOutpoint { transaction_id: Some(prec), index: Some(1) }),
                signature_script: Some(vec![1, 2, 3]),
                sequence: None,
                sig_op_count: None,
                compute_budget: None,
                verbose_data: None,
            }],
            outputs: vec![RpcOptionalTransactionOutput {
                value: Some(500),
                script_public_key: Some(ScriptPublicKey::from_vec(0, vec![9, 9])),
                verbose_data: None,
                covenant: None,
            }],
            lock_time: None,
            subnetwork_id: None,
            gas: None,
            payload: None,
            storage_mass: None,
            verbose_data: Some(RpcOptionalTransactionVerboseData { transaction_id: Some(id), hash: None, compute_mass: None, block_hash: None, block_time: None }),
        };
        let i = tx_info(&t).expect("convertie");
        assert_eq!(i.txid, id.to_string());
        assert_eq!(i.entrees, vec![(prec.to_string(), 1, vec![1, 2, 3])]);
        assert_eq!(i.sorties, vec![(0, 500, vec![9, 9], None)]);
    }
}

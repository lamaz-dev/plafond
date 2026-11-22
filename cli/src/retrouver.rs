//! Retrouver le coffre courant sans fichier d'état et sans routeur (mode survie).
//!
//! L'état du coffre (jetons, instant) fait partie de son script : chaque paiement le déplace vers
//! une nouvelle adresse. Le propriétaire ne garde que l'ORIGINE (le coffre qu'il a créé). Cette
//! commande suit la lignée, paiement après paiement, à l'aide d'un indexeur public (API REST
//! officielle de Kaspa), SANS LUI FAIRE CONFIANCE : à chaque saut, l'état suivant est recalculé à
//! partir de la transaction elle-même (montant et instant annoncés, frais, inscription) et doit
//! retomber exactement sur le script publié. Un indexeur menteur fait échouer la vérification ;
//! il ne peut pas mener vers un faux coffre.

use crate::{bytecode, compile_params, Etat, Res, VaultParams};
use secp256k1::Keypair;

/// Ce que l'indexeur dit d'une transaction (rien n'est cru sans vérification).
#[derive(Clone, Debug)]
pub struct TxInfo {
    pub txid: String,
    pub acceptee: bool,
    pub bloc_acceptant: Option<String>,
    /// (transaction précédente, index, script de signature)
    pub entrees: Vec<(String, u32, Vec<u8>)>,
    /// (index, montant, script de sortie : octets du script, avec ou sans version en tête,
    /// identifiant de lignée annoncé par l'indexeur, s'il le donne)
    pub sorties: Vec<(u32, u64, Vec<u8>, Option<String>)>,
}

pub trait Source {
    /// Transactions où l'adresse apparaît (entrée ou sortie).
    fn transactions_adresse(&self, adresse: &str) -> Res<Vec<TxInfo>>;
    fn transaction(&self, txid: &str) -> Res<TxInfo>;
    /// Score DAA d'un bloc (celui qui a accepté une transaction = inscription de ses sorties).
    fn daa_bloc(&self, hash: &str) -> Res<i64>;
}

#[derive(Debug, PartialEq)]
pub enum Issue {
    /// Coffre courant, non dépensé selon l'indexeur (à confirmer auprès d'un nœud).
    Courant(Etat),
    /// Coffre fermé par le propriétaire (ownerControl sans continuation).
    Ferme { txid: String },
}

/// Découpe un script de signature en données poussées (OP_0, push direct, PUSHDATA1/2/4).
pub fn pousses(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut v = vec![];
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let n = match op {
            0x00 => 0,
            0x01..=0x4b => op as usize,
            0x4c => { let n = *script.get(i)? as usize; i += 1; n }
            0x4d => { let n = u16::from_le_bytes(script.get(i..i + 2)?.try_into().ok()?) as usize; i += 2; n }
            0x4e => { let n = u32::from_le_bytes(script.get(i..i + 4)?.try_into().ok()?) as usize; i += 4; n }
            0x4f => { v.push(vec![0x81]); continue; }
            0x51..=0x60 => { v.push(vec![op - 0x50]); continue; }
            _ => return None, // pas une suite de poussées : pas un script de dépense de coffre
        };
        v.push(script.get(i..i + n)?.to_vec());
        i += n;
    }
    Some(v)
}

/// Nombre de script (petit-boutiste, signe dans le bit de poids fort du dernier octet).
pub fn nombre(b: &[u8]) -> Option<i64> {
    if b.is_empty() { return Some(0); }
    if b.len() > 8 { return None; }
    let mut x: i64 = 0;
    for (k, o) in b.iter().enumerate() {
        let o = if k == b.len() - 1 { o & 0x7f } else { *o };
        x |= (o as i64) << (8 * k);
    }
    Some(if b[b.len() - 1] & 0x80 != 0 { -x } else { x })
}

fn meme_script(publie: &[u8], attendu: &[u8]) -> bool {
    publie == attendu || (publie.len() == attendu.len() + 2 && &publie[2..] == attendu)
}

fn adresse_coffre(owner_pk: &[u8], agent: &Keypair, e: &Etat) -> Res<(String, Vec<u8>, Vec<u8>)> {
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let art = compile_params(&p)?;
    let spk = crate::vault_spk(&art);
    let addr = kaspa_txscript::extract_script_pub_key_address(&spk, kaspa_addresses::Prefix::Testnet).map_err(|_| "adresse de coffre invalide")?;
    Ok((addr.to_string(), spk.script().to_vec(), bytecode(&art)))
}

/// Un mouvement vérifié de la lignée (historique de la console du propriétaire).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Mouvement {
    pub txid: String,
    /// « achat » (paiement de l'agent), « ajout » (recharge du propriétaire) ou « gel »
    pub genre: &'static str,
    pub montant_sompi: i64,
    pub frais_sompi: i64,
    /// instant annoncé (score DAA) pour un achat
    pub instant_daa: Option<i64>,
    /// script du destinataire (hex) pour un achat
    pub destinataire: Option<String>,
}

/// Suit la lignée depuis l'origine jusqu'au coffre courant. Chaque saut est vérifié.
#[allow(dead_code)] // utilisé par les tests
pub fn retrouver(src: &dyn Source, owner_pk: &[u8], agent: &Keypair, origine: &Etat) -> Res<(Issue, usize)> {
    retrouver_avec_historique(src, owner_pk, agent, origine).map(|(i, n, _)| (i, n))
}

/// Comme `retrouver`, en renvoyant aussi l'historique vérifié des mouvements.
pub fn retrouver_avec_historique(src: &dyn Source, owner_pk: &[u8], agent: &Keypair, origine: &Etat) -> Res<(Issue, usize, Vec<Mouvement>)> {
    let mut historique = vec![];
    let mut cur = origine.clone();
    for sauts in 0..20_000 {
        let (addr, spk, redeem) = adresse_coffre(owner_pk, agent, &cur)?;
        let depense = src
            .transactions_adresse(&addr)?
            .into_iter()
            .filter(|t| t.acceptee) // seules les transactions acceptées par le consensus comptent
            .find_map(|t| {
                let e = t.entrees.iter().find(|(h, i, _)| h == &cur.txid && *i == cur.index)?.clone();
                Some((t, e.2))
            });
        let Some((tx, sigscript)) = depense else {
            return Ok((Issue::Courant(cur), sauts, historique));
        };
        let p = pousses(&sigscript).ok_or("script de dépense illisible : chaîne non vérifiable")?;
        if p.last().map(|r| r.as_slice()) != Some(redeem.as_slice()) {
            return Err(format!("la dépense {} ne révèle pas le script attendu du coffre : chaîne non vérifiable", tx.txid).into());
        }
        let total_sorties: u64 = tx.sorties.iter().map(|s| s.1).sum();
        let frais = cur.valeur.checked_sub(total_sorties).ok_or("frais négatifs : transaction incohérente")? as i64;
        // Candidats d'état suivant : paiement de l'agent (signature, montant, instant, aiguillage,
        // script) ou recharge du propriétaire (état inchangé). Seul celui qui retombe EXACTEMENT
        // sur un script de sortie est retenu.
        let mut candidats: Vec<(i64, i64)> = vec![(cur.tokens, cur.last_daa)];
        let mut achat: Option<(i64, i64)> = None;
        if p.len() == 5 {
            let amount = nombre(&p[1]).ok_or("montant illisible")?;
            let now = nombre(&p[2]).ok_or("instant illisible")?;
            let bloc = src.transaction(&cur.txid)?.bloc_acceptant.ok_or("bloc d'acceptation inconnu")?;
            let creation = src.daa_bloc(&bloc)?;
            let dispo = VaultParams::pour(owner_pk, agent, cur.tokens, cur.last_daa).available(now, creation);
            candidats.insert(0, (dispo - amount - frais, now));
            achat = Some((amount, now));
        }
        let mut suivant = None;
        for (tokens, last) in candidats {
            if tokens < 0 { continue; }
            let essai = Etat { txid: tx.txid.clone(), index: 0, valeur: 0, tokens, last_daa: last, cov_id: cur.cov_id.clone() };
            let (_, spk_suivant, _) = adresse_coffre(owner_pk, agent, &essai)?;
            // Un agent peut payer un LEURRE portant le même script que la continuation : on
            // retient la sortie qui porte la lignée du coffre (contrôlée ensuite auprès du nœud).
            let porte = |s: &(u32, u64, Vec<u8>, Option<String>), strict: bool| match s.3.as_deref() {
                Some(c) => c.eq_ignore_ascii_case(&cur.cov_id),
                None => !strict,
            };
            // Pour un paiement de l'agent, le contrat impose que la continuation soit la SORTIE 1 :
            // un leurre au même script (sortie 0) est écarté même si l'indexeur ne donne pas la
            // lignée. Pour une recharge (signée par le propriétaire), toute sortie peut convenir.
            let paiement = p.len() == 5;
            let candidates: Vec<&(u32, u64, Vec<u8>, Option<String>)> =
                tx.sorties.iter().filter(|s| meme_script(&s.2, &spk_suivant) && (!paiement || s.0 == 1)).collect();
            let choisie = candidates.iter().copied().find(|s| porte(s, true)).or_else(|| candidates.iter().copied().find(|s| porte(s, false)));
            if let Some(s) = choisie {
                suivant = Some(Etat { index: s.0, valeur: s.1, ..essai });
                break;
            }
        }
        let destinataire = tx.sorties.iter().find(|s| s.0 == 0).map(|s| hex::encode(&s.2));
        match suivant {
            Some(e) => {
                historique.push(match achat {
                    // un paiement de l'agent (5 poussées : signature, montant, instant, aiguillage, script)
                    Some((m, now)) => {
                        Mouvement { txid: tx.txid.clone(), genre: "achat", montant_sompi: m, frais_sompi: frais, instant_daa: Some(now), destinataire }
                    }
                    _ => Mouvement { txid: tx.txid.clone(), genre: "ajout", montant_sompi: e.valeur as i64 - cur.valeur as i64, frais_sompi: 0, instant_daa: None, destinataire: None },
                });
                cur = e
            }
            None if p.len() == 3 => {
                historique.push(Mouvement { txid: tx.txid.clone(), genre: "gel", montant_sompi: total_sorties as i64, frais_sompi: frais, instant_daa: None, destinataire: None });
                return Ok((Issue::Ferme { txid: tx.txid }, sauts + 1, historique));
            }
            None => return Err(format!("aucune sortie de {} ne correspond à l'état recalculé : chaîne non vérifiable", tx.txid).into()),
        }
        let _ = spk;
    }
    Err("lignée trop longue".into())
}

/// Indexeur public : API REST officielle de Kaspa (api-tn10.kaspa.org par défaut, KASPA_REST sinon).
pub struct Rest {
    base: String,
    http: ureq::Agent,
}

impl Rest {
    pub fn depuis_env() -> Self {
        let base = std::env::var("KASPA_REST").unwrap_or_else(|_| "https://api-tn10.kaspa.org".into());
        Rest { base: base.trim_end_matches('/').into(), http: ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build() }
    }
    fn get(&self, chemin: &str) -> Res<serde_json::Value> {
        let r = self.http.get(&format!("{}{}", self.base, chemin)).call()?;
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::Read::take(r.into_reader(), 32 * 1024 * 1024), &mut buf)?;
        Ok(serde_json::from_str(&buf)?)
    }
}

fn hexa(v: &serde_json::Value) -> Vec<u8> {
    v.as_str().and_then(|s| hex::decode(s).ok()).unwrap_or_default()
}

fn tx_depuis_json(t: &serde_json::Value) -> TxInfo {
    let s = |k: &str| t.get(k).and_then(|v| v.as_str()).map(String::from);
    TxInfo {
        txid: s("transaction_id").unwrap_or_default(),
        acceptee: t.get("is_accepted").and_then(|v| v.as_bool()).unwrap_or(false),
        bloc_acceptant: s("accepting_block_hash"),
        entrees: t.get("inputs").and_then(|v| v.as_array()).map(|a| a.iter().map(|i| {
            let idx = i.get("previous_outpoint_index").and_then(|v| v.as_str().and_then(|x| x.parse().ok()).or(v.as_u64().map(|x| x as u32))).unwrap_or(u32::MAX);
            (i.get("previous_outpoint_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(), idx, hexa(&i["signature_script"]))
        }).collect()).unwrap_or_default(),
        sorties: t.get("outputs").and_then(|v| v.as_array()).map(|a| a.iter().map(|o| {
            (o["index"].as_u64().unwrap_or(u64::MAX) as u32, o["amount"].as_u64().unwrap_or(0), hexa(&o["script_public_key"]), o["covenant_id"].as_str().map(String::from))
        }).collect()).unwrap_or_default(),
    }
}

impl Source for Rest {
    fn transactions_adresse(&self, adresse: &str) -> Res<Vec<TxInfo>> {
        // Pagination : quelqu'un peut envoyer de nombreuses transactions à l'adresse pour cacher la
        // dépense du coffre ; on parcourt jusqu'à 40 pages de 500.
        let mut tout = vec![];
        for page in 0..40 {
            let v = self.get(&format!("/addresses/{adresse}/full-transactions?limit=500&offset={}&resolve_previous_outpoints=no", page * 500))?;
            let lot: Vec<TxInfo> = v.as_array().map(|a| a.iter().map(tx_depuis_json).collect()).unwrap_or_default();
            let fin = lot.len() < 500;
            tout.extend(lot);
            if fin {
                return Ok(tout);
            }
        }
        Err("adresse inondée de transactions (plus de 20 000) : retrouver par un nœud".into())
    }
    fn transaction(&self, txid: &str) -> Res<TxInfo> {
        Ok(tx_depuis_json(&self.get(&format!("/transactions/{txid}?inputs=false&outputs=false"))?))
    }
    fn daa_bloc(&self, hash: &str) -> Res<i64> {
        let v = self.get(&format!("/blocks/{hash}?includeTransactions=false"))?;
        let d = &v["header"]["daaScore"];
        Ok(d.as_str().and_then(|s| s.parse().ok()).or(d.as_i64()).ok_or("score DAA du bloc absent")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address, build_pay, payee, xonly};
    use kaspa_txscript::pay_to_address_script;
    use std::collections::HashMap;

    fn kp(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }

    #[derive(Default)]
    struct Faux {
        par_adresse: HashMap<String, Vec<TxInfo>>,
        par_id: HashMap<String, TxInfo>,
        daa: HashMap<String, i64>,
    }
    impl Source for Faux {
        fn transactions_adresse(&self, a: &str) -> Res<Vec<TxInfo>> { Ok(self.par_adresse.get(a).cloned().unwrap_or_default()) }
        fn transaction(&self, id: &str) -> Res<TxInfo> { Ok(self.par_id.get(id).cloned().ok_or("inconnue")?) }
        fn daa_bloc(&self, h: &str) -> Res<i64> { Ok(*self.daa.get(h).ok_or("bloc inconnu")?) }
    }

    /// Chaîne de 4 paiements réels (construits et signés comme sur le testnet), indexée par un faux
    /// indexeur. Retourne (source, origine, état final attendu, adresse du coffre final).
    fn chaine(owner: &Keypair, agent: &Keypair) -> (Faux, Etat, Etat) {
        let mut f = Faux::default();
        let origine = Etat { txid: "aa".repeat(32), index: 0, valeur: 500_000_000, tokens: 200_000_000, last_daa: 1_000, cov_id: "cc".repeat(32) };
        let mut info0 = TxInfo { txid: origine.txid.clone(), acceptee: true, bloc_acceptant: Some("b0".into()), entrees: vec![], sorties: vec![] };
        f.daa.insert("b0".into(), 1_000);
        f.par_id.insert(origine.txid.clone(), info0.clone());
        info0.sorties.clear();
        let mut cur = origine.clone();
        let mut creation = 1_000i64;
        for k in 0..4i64 {
            let now = creation + 50_000 * (k + 1);
            let (tx, next) = build_pay(owner, agent, &cur, 10_000_000, pay_to_address_script(&address(&payee(owner))), now, creation).unwrap();
            let id = tx.id().to_string();
            let bloc = format!("b{}", k + 1);
            let inclusion = now + 10;
            f.daa.insert(bloc.clone(), inclusion);
            let info = TxInfo {
                txid: id.clone(),
                acceptee: true,
                bloc_acceptant: Some(bloc),
                entrees: tx.inputs.iter().map(|i| (i.previous_outpoint.transaction_id.to_string(), i.previous_outpoint.index, i.signature_script.clone())).collect(),
                sorties: tx.outputs.iter().enumerate().map(|(n, o)| (n as u32, o.value, o.script_public_key.script().to_vec(), o.covenant.map(|b| b.covenant_id.to_string()))).collect(),
            };
            let (addr, _, _) = adresse_coffre(&xonly(owner), agent, &cur).unwrap();
            // une tentative rejetée dans l'historique ne doit pas être suivie
            let mut rejetee = info.clone();
            rejetee.acceptee = false;
            rejetee.txid = "dd".repeat(32);
            rejetee.sorties[1].2 = vec![0x51];
            f.par_adresse.entry(addr).or_default().extend([rejetee, info.clone()]);
            f.par_id.insert(id.clone(), info);
            cur = Etat { txid: id, ..next };
            creation = inclusion;
        }
        (f, origine, cur)
    }

    #[test]
    fn retrouve_le_coffre_courant_sans_fichier_d_etat() {
        let (owner, agent) = (kp(1), kp(2));
        let (f, origine, attendu) = chaine(&owner, &agent);
        let (issue, sauts) = retrouver(&f, &xonly(&owner), &agent, &origine).unwrap();
        assert_eq!(sauts, 4);
        assert_eq!(issue, Issue::Courant(attendu));
    }

    #[test]
    fn indexeur_menteur_detecte() {
        let (owner, agent) = (kp(1), kp(2));
        let (mut f, origine, _) = chaine(&owner, &agent);
        // l'indexeur remplace la continuation du 2e paiement par un autre script
        for v in f.par_adresse.values_mut() {
            for t in v.iter_mut().filter(|t| t.acceptee) {
                if let Some(s) = t.sorties.get_mut(1) { s.2 = vec![0xaa, 0x20].into_iter().chain([7u8; 32]).chain([0x87]).collect(); }
            }
        }
        let r = retrouver(&f, &xonly(&owner), &agent, &origine);
        assert!(r.is_err(), "un indexeur menteur doit faire échouer la vérification : {r:?}");
    }

    #[test]
    fn mauvais_score_d_inscription_detecte() {
        let (owner, agent) = (kp(1), kp(2));
        let (mut f, origine, _) = chaine(&owner, &agent);
        f.daa.insert("b2".into(), 999_999); // l'indexeur ment sur l'inscription
        assert!(retrouver(&f, &xonly(&owner), &agent, &origine).is_err());
    }

    /// Constat n° 1 du relecteur : l'agent paie un LEURRE portant exactement le script de la
    /// continuation (sortie 0, sans lignée). `retrouver` doit suivre la vraie continuation.
    #[test]
    fn leurre_au_meme_script_ignore() {
        let (owner, agent) = (kp(1), kp(2));
        let mut f = Faux::default();
        let origine = Etat { txid: "aa".repeat(32), index: 0, valeur: 500_000_000, tokens: 200_000_000, last_daa: 1_000, cov_id: "cc".repeat(32) };
        f.daa.insert("b0".into(), 1_000);
        f.par_id.insert(origine.txid.clone(), TxInfo { txid: origine.txid.clone(), acceptee: true, bloc_acceptant: Some("b0".into()), entrees: vec![], sorties: vec![] });
        // paiement dont le destinataire est le script de la continuation elle-même
        let now = 51_000;
        let (essai, suivant) = build_pay(&owner, &agent, &origine, 10_000_000, pay_to_address_script(&address(&payee(&owner))), now, 1_000).unwrap();
        let spk_cont = essai.outputs[1].script_public_key.clone();
        let (tx, suivant2) = build_pay(&owner, &agent, &origine, 10_000_000, spk_cont, now, 1_000).unwrap();
        assert_eq!(suivant.tokens, suivant2.tokens);
        let id = tx.id().to_string();
        let info = TxInfo {
            txid: id.clone(),
            acceptee: true,
            bloc_acceptant: Some("b1".into()),
            entrees: tx.inputs.iter().map(|i| (i.previous_outpoint.transaction_id.to_string(), i.previous_outpoint.index, i.signature_script.clone())).collect(),
            sorties: tx.outputs.iter().enumerate().map(|(n, o)| (n as u32, o.value, o.script_public_key.script().to_vec(), o.covenant.map(|b| b.covenant_id.to_string()))).collect(),
        };
        assert_eq!(info.sorties[0].2, info.sorties[1].2, "le leurre a bien le même script");
        let (addr, _, _) = adresse_coffre(&xonly(&owner), &agent, &origine).unwrap();
        f.par_adresse.insert(addr, vec![info.clone()]);
        f.par_id.insert(id, info);
        f.daa.insert("b1".into(), now + 10);
        match retrouver(&f, &xonly(&owner), &agent, &origine).unwrap().0 {
            Issue::Courant(e) => assert_eq!(e.index, 1, "retrouver a suivi le leurre"),
            autre => panic!("{autre:?}"),
        }
        // seconde passe du relecteur : même attaque avec un indexeur qui ne donne PAS la lignée
        for v in f.par_adresse.values_mut() {
            for t in v.iter_mut() {
                for s in t.sorties.iter_mut() { s.3 = None; }
            }
        }
        match retrouver(&f, &xonly(&owner), &agent, &origine).unwrap().0 {
            Issue::Courant(e) => assert_eq!(e.index, 1, "retrouver a suivi le leurre (indexeur sans lignée)"),
            autre => panic!("{autre:?}"),
        }
    }

    #[test]
    fn nombres_de_script() {
        assert_eq!(nombre(&[]), Some(0));
        assert_eq!(nombre(&[0x01]), Some(1));
        assert_eq!(nombre(&[0x81]), Some(-1));
        assert_eq!(nombre(&[0x00, 0x80]), Some(-0));
        assert_eq!(nombre(&[0xff, 0x00]), Some(255));
        assert_eq!(nombre(&627_000_000i64.to_le_bytes()[..4]), Some(627_000_000));
    }
}

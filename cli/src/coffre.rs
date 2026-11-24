//! Le coffre Plafond (cœur v0.6) sur le réseau : création, paiement, rechargement, gel, état.
//!
//! Un coffre = une adresse (le script ne change jamais) et les pièces qu'elle contient. Il n'y a
//! pas d'état à suivre sur la chaîne : on lit les pièces de l'adresse sur le nœud, avec leur score
//! d'inscription, et le réseau fait respecter le rythme (verrou relatif). Le fichier local ne garde
//! que les réglages et les apports du propriétaire, pour tracer la courbe de perte promise.

use crate::coeur::{self, Coeur};
use crate::*;

pub const VERSION: &str = "coeur-v0.6";
/// Marge (unités DAA, ≈ 2 s) entre l'âge lu et l'âge exigé : le bloc qui accepte le paiement est
/// toujours un peu plus tard que la lecture.
const MARGE: u64 = 20;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Apport {
    pub txid: String,
    pub sompi: u64,
    pub daa: u64,
}

/// Fichier local d'un coffre v0.6 : réglages et apports du propriétaire. Rien de secret, rien
/// d'indispensable : sans lui, le coffre se retrouve depuis les clés et les réglages.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EtatCoeur {
    pub version: String,
    pub capacite: i64,
    pub periode: i64,
    pub agent: String,
    pub cree_daa: u64,
    #[serde(default)]
    pub apports: Vec<Apport>,
}

pub fn charger() -> Option<EtatCoeur> {
    let e: EtatCoeur = serde_json::from_str(&fs::read_to_string(state_path()).ok()?).ok()?;
    (e.version == VERSION).then_some(e)
}

fn enregistrer(e: &EtatCoeur) -> Res<()> {
    let p = state_path();
    if let Some(dir) = std::path::Path::new(&p).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, serde_json::to_string_pretty(e)?)?;
    Ok(())
}

/// Le contrat du coffre : réglages du fichier s'il existe (ils font foi), sinon règles courantes.
pub fn coeur_de(owner_pk: &[u8], agent_pk: &[u8]) -> Coeur {
    let (capacite, periode) = match charger() {
        Some(e) => (e.capacite, e.periode),
        None => (regles().capacite, regles().recharge_daa),
    };
    Coeur { owner: owner_pk.to_vec(), agent: agent_pk.to_vec(), capacite, periode }
}

pub fn adresse(art: &SilAbiArtifact) -> Res<Address> {
    Ok(extract_script_pub_key_address(&vault_spk(art), Prefix::Testnet).map_err(|_| "adresse de coffre invalide")?)
}

#[derive(Clone, Debug)]
pub struct Piece {
    pub outpoint: TransactionOutpoint,
    pub valeur: u64,
    /// Score DAA du bloc qui a inscrit la pièce ; `None` : pas encore confirmée.
    pub creation: Option<u64>,
}

/// Pièces de l'adresse du coffre, lues sur le nœud (le nœud fait foi).
pub async fn pieces(c: &KaspaRpcClient, art: &SilAbiArtifact) -> Res<Vec<Piece>> {
    let spk = vault_spk(art);
    Ok(c.get_utxos_by_addresses(vec![adresse(art)?])
        .await?
        .into_iter()
        .filter(|u| u.utxo_entry.script_public_key == spk)
        .map(|u| Piece {
            outpoint: u.outpoint.clone().into(),
            valeur: u.utxo_entry.amount,
            creation: (u.utxo_entry.block_daa_score != u64::MAX).then_some(u.utxo_entry.block_daa_score),
        })
        .collect())
}

/// Pièces du propriétaire choisies pour couvrir `montant` + frais.
async fn financer(c: &KaspaRpcClient, owner: &Keypair, montant: u64) -> Res<(Vec<UtxoEntry>, Vec<TransactionInput>, u64)> {
    let utxos = c.get_utxos_by_addresses(vec![address(owner)]).await?;
    let (mut entries, mut inputs, mut total) = (vec![], vec![], 0u64);
    for u in utxos.into_iter().filter(|u| u.utxo_entry.block_daa_score != u64::MAX).take(20) {
        total += u.utxo_entry.amount;
        entries.push(u.utxo_entry.clone().into());
        inputs.push(TransactionInput::new_with_compute_budget(u.outpoint.clone().into(), vec![], 0, CB_P2PK));
        if total >= montant + FEE * (inputs.len() as u64 + 1) {
            break;
        }
    }
    if total < montant + FEE * inputs.len().max(1) as u64 {
        return Err(format!("solde du propriétaire insuffisant : {} TKAS, il en faut {}", total as f64 / 1e8, (montant + FEE) as f64 / 1e8).into());
    }
    Ok((entries, inputs, total))
}

/// Envoie `montant` du propriétaire vers l'adresse du coffre (création ou rechargement).
async fn verser(c: &KaspaRpcClient, owner: &Keypair, art: &SilAbiArtifact, montant: u64) -> Res<String> {
    let (entries, inputs, total) = financer(c, owner, montant).await?;
    let fee = FEE * inputs.len() as u64;
    let mut outputs = vec![TransactionOutput::new(montant, vault_spk(art))];
    let rendu = total - montant - fee;
    if rendu > 0 {
        outputs.push(TransactionOutput::new(rendu, pay_to_address_script(&address(owner))));
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..tx.inputs.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = ScriptBuilder::new().add_data(&s)?.drain();
    }
    tx.finalize();
    Ok(c.submit_transaction(garde_diffusion(&tx)?, false).await?.to_string())
}

/// Crée le coffre de l'agent : une pièce à l'adresse du contrat. Pas de genèse, pas de lignée.
pub async fn deployer(owner: &Keypair, agent: &Keypair) -> Res<String> {
    if charger().is_some() || load_state().is_ok() {
        return Err("un coffre est déjà déployé".into());
    }
    let r = regles();
    let coeur = Coeur { owner: xonly(owner), agent: agent_pk(agent), capacite: r.capacite, periode: r.recharge_daa };
    let art = coeur.artifact()?;
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let txid = verser(&c, owner, &art, r.depot).await?;
    let e = EtatCoeur {
        version: VERSION.into(),
        capacite: coeur.capacite,
        periode: coeur.periode,
        agent: hex::encode(&coeur.agent),
        cree_daa: daa,
        apports: vec![Apport { txid: txid.clone(), sompi: r.depot, daa }],
    };
    enregistrer(&e)?;
    println!("Coffre créé (cœur v0.6) : {} TKAS à l'adresse {}", r.depot as f64 / 1e8, adresse(&art)?);
    println!("Transaction : {}", explorer(&txid));
    liberer(&c).await?;
    Ok(txid)
}

/// Le propriétaire ajoute une pièce au coffre. C'est une nouvelle racine : la courbe s'allonge
/// d'autant, sans rafale (une pièce neuve n'a pas d'âge).
pub async fn recharger(owner: &Keypair, agent: &Keypair, montant: u64) -> Res<String> {
    let mut e = charger().ok_or("aucun coffre v0.6 déployé")?;
    let art = coeur_de(&xonly(owner), &agent_pk(agent)).artifact()?;
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let txid = verser(&c, owner, &art, montant).await?;
    e.apports.push(Apport { txid: txid.clone(), sompi: montant, daa });
    enregistrer(&e)?;
    println!("Coffre rechargé de {} TKAS (nouvelle pièce) : {}", montant as f64 / 1e8, explorer(&txid));
    liberer(&c).await?;
    Ok(txid)
}

/// Délai (unités DAA) avant que `spent` soit payable depuis la meilleure pièce ; 0 = maintenant.
pub fn delai(coeur: &Coeur, pieces: &[Piece], now: u64, spent: u64) -> Option<u64> {
    pieces
        .iter()
        .filter(|p| p.valeur > spent)
        .filter_map(|p| p.creation.map(|cr| (cr + coeur.attente(spent as i64) + MARGE).saturating_sub(now)))
        .min()
}

/// Paiement de l'agent. Choisit la plus grosse pièce prête ; si aucune ne l'est, renvoie le délai
/// d'attente, ou attend jusqu'à `attente_max` secondes. `forcer` : démonstration du refus, la
/// transaction annonce tout l'âge réel de la pièce et le réseau tranche.
pub async fn payer(owner_pk: &[u8], agent: &Keypair, montant: u64, dest: ScriptPublicKey, forcer: bool, attente_max: u64) -> Res<String> {
    let coeur = coeur_de(owner_pk, &xonly(agent));
    let art = coeur.artifact()?;
    let spent = montant + FEE;
    if spent as i64 > coeur.capacite && !forcer {
        return Err(format!("refusé localement : {} TKAS (frais compris) dépasse le plafond par achat de {} TKAS", spent as f64 / 1e8, coeur.capacite as f64 / 1e8).into());
    }
    let c = connect_silencieux().await?;
    let debut = std::time::Instant::now();
    let (piece, now) = loop {
        let now = virtual_daa(&c).await?;
        let ps = pieces(&c, &art).await?;
        if forcer {
            let p = ps.iter().filter(|p| p.creation.is_some()).max_by_key(|p| p.valeur).cloned().ok_or("aucune pièce confirmée dans le coffre")?;
            break (p, now);
        }
        let pretes: Vec<&Piece> =
            ps.iter().filter(|p| p.valeur > spent && p.creation.is_some_and(|cr| cr + coeur.attente(spent as i64) + MARGE <= now)).collect();
        if let Some(p) = pretes.into_iter().max_by_key(|p| p.valeur) {
            break (p.clone(), now);
        }
        let Some(d) = delai(&coeur, &ps, now, spent) else {
            liberer(&c).await?;
            return Err("refusé localement : aucune pièce du coffre ne couvre ce montant (coffre vide ou gelé)".into());
        };
        if debut.elapsed().as_secs() + d / 10 > attente_max {
            liberer(&c).await?;
            return Err(format!("budget pas encore disponible : prochain paiement de ce montant possible dans {} s", d / 10 + 1).into());
        }
        tokio::time::sleep(Duration::from_secs((d / 10 + 1).min(30))).await;
    };
    let sequence = forcer.then(|| (now.saturating_sub(piece.creation.unwrap_or(now))).min(u32::MAX as u64));
    // Agent compromis simulé : l'outil ne bride rien (capacité levée côté construction), la
    // transaction part telle quelle et c'est le script, exécuté par le réseau, qui tranche.
    let permissif = Coeur { capacite: i64::MAX / coeur.periode.max(1), ..coeur.clone() };
    let tx = coeur::build_pay(if forcer { &permissif } else { &coeur }, &art, piece.outpoint, piece.valeur, dest, montant, FEE, agent, sequence)?;
    let entree = UtxoEntry::new(piece.valeur, vault_spk(&art), piece.creation.unwrap_or(0), false, None);
    if let Some(m) = masse::masses(&tx, std::slice::from_ref(&entree)) {
        if !m.standard() && !masse::FORCER.load(std::sync::atomic::Ordering::Relaxed) {
            liberer(&c).await?;
            return Err(format!(
                "paiement non diffusable : masse de stockage {} g > {} g (KIP-9). Paiement minimal ≈ 0,02 KAS ; une pièce sous ≈ 0,08 KAS ne peut plus payer.",
                m.storage,
                masse::MAX_STANDARD_MASS
            )
            .into());
        }
    }
    let r = c.submit_transaction(garde_diffusion(&tx)?, false).await;
    liberer(&c).await?;
    match r {
        Ok(id) => Ok(id.to_string()),
        Err(err) => Err(format!("REFUSÉ par le réseau : {err}").into()),
    }
}

/// Gel prioritaire : le propriétaire rapatrie TOUTES les pièces de l'adresse (`ownerControl`).
/// Un paiement de l'agent en attente sur une pièce est remplacé (frais plus élevés) ; s'il passe
/// quand même, sa continuation est une nouvelle pièce, rapatriée au tour suivant.
pub async fn geler(owner: &Keypair, agent: &Keypair) -> Res<String> {
    let coeur = coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact()?;
    let c = connect().await?;
    let proprio = address(owner);
    let mut ids = vec![];
    for tentative in 1..=8u64 {
        let ps = pieces(&c, &art).await?;
        let confirmees: Vec<&Piece> = ps.iter().filter(|p| p.creation.is_some()).collect();
        if confirmees.is_empty() {
            if ps.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await; // continuation pas encore confirmée
            continue;
        }
        let total: u64 = confirmees.iter().map(|p| p.valeur).sum();
        let frais = (2 * FEE * confirmees.len() as u64 * tentative).min(total / 2);
        let entries: Vec<UtxoEntry> = confirmees.iter().map(|p| UtxoEntry::new(p.valeur, vault_spk(&art), p.creation.unwrap_or(0), false, None)).collect();
        let inputs = confirmees.iter().map(|p| TransactionInput::new_with_compute_budget(p.outpoint, vec![], 0, coeur::CB_OWNER)).collect();
        let mut tx = Transaction::new(1, inputs, vec![TransactionOutput::new(total - frais, pay_to_address_script(&proprio))], 0, Default::default(), 0, vec![]);
        for i in 0..tx.inputs.len() {
            let s = sign(&tx, &entries, i, owner);
            tx.inputs[i].signature_script = vault_sigscript(&art, "ownerControl", &[s.into()])?;
        }
        tx.finalize();
        let id = tx.id();
        let envoi = match c.submit_transaction(garde_diffusion(&tx)?, false).await {
            Ok(_) => Ok(()),
            Err(err) => {
                println!("tentative {tentative} : {err} ; remplacement du paiement en attente");
                c.submit_transaction_replacement(garde_diffusion(&tx)?).await.map(|_| ()).map_err(|e| e.to_string())
            }
        };
        if let Err(err) = envoi {
            println!("tentative {tentative} refusée : {err}");
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        for _ in 0..30 {
            if c.get_utxos_by_addresses(vec![proprio.clone()]).await?.iter().any(|u| u.outpoint.transaction_id == id) {
                println!("{} pièce(s) rapatriée(s) : {} TKAS, {}", confirmees.len(), (total - frais) as f64 / 1e8, explorer(&id.to_string()));
                ids.push(id.to_string());
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    let reste = pieces(&c, &art).await?;
    liberer(&c).await?;
    if !reste.is_empty() {
        return Err(format!("gel incomplet : {} pièce(s) encore dans le coffre, relancer", reste.len()).into());
    }
    if ids.is_empty() {
        return Err("coffre déjà vide".into());
    }
    let _ = fs::remove_file(state_path());
    Ok(ids.join(","))
}

/// Ce que le moteur de risque et la console lisent : les pièces et l'instant, sur le nœud.
pub struct Vue {
    pub coeur: Coeur,
    pub adresse: String,
    pub pieces: Vec<Piece>,
    pub now: u64,
    pub etat: Option<EtatCoeur>,
}

impl Vue {
    pub fn solde(&self) -> u64 {
        self.pieces.iter().map(|p| p.valeur).sum()
    }
    /// Pièce non confirmée : prudence, on la compte comme si elle était prête dès maintenant.
    fn age(&self, p: &Piece) -> u64 {
        p.creation.map(|cr| self.now.saturating_sub(cr)).unwrap_or(0)
    }
    pub fn immediate(&self) -> u64 {
        self.pieces.iter().map(|p| self.coeur.immediate(p.valeur, self.age(p))).sum()
    }
    pub fn fenetre(&self, d: u64) -> u64 {
        self.pieces.iter().map(|p| self.coeur.fenetre(p.valeur, self.age(p), d)).sum()
    }
    /// Apports du propriétaire depuis la création, et perte nette depuis la création.
    pub fn apports(&self) -> u64 {
        self.etat.as_ref().map(|e| e.apports.iter().map(|a| a.sompi).sum()).unwrap_or(0)
    }
    /// Courbe promise à la création : perte nette maximale à l'instant `t` (spec v0.6, §1b).
    pub fn courbe(&self, t: u64) -> u64 {
        let Some(e) = &self.etat else { return 0 };
        e.apports.iter().filter(|a| a.daa <= t).map(|a| self.coeur.fenetre(a.sompi, 0, t - a.daa)).sum()
    }
}

pub async fn vue(c: &KaspaRpcClient, owner_pk: &[u8], agent_pk: &[u8]) -> Res<Vue> {
    let coeur = coeur_de(owner_pk, agent_pk);
    let art = coeur.artifact()?;
    let pieces = pieces(c, &art).await?;
    let now = virtual_daa(c).await?;
    Ok(Vue { adresse: adresse(&art)?.to_string(), coeur, pieces, now, etat: charger() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coeur(c: i64, r: i64) -> Coeur {
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        Coeur { owner: xonly(&k(1)), agent: xonly(&k(2)), capacite: c, periode: r }
    }

    #[test]
    fn delai_avant_paiement() {
        let c = coeur(50_000_000, 288_000);
        let op = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
        let ps = vec![
            Piece { outpoint: op, valeur: 1_000_000_000, creation: Some(1_000) },
            Piece { outpoint: op, valeur: 10_000, creation: Some(0) }, // trop petite
            Piece { outpoint: op, valeur: 1_000_000_000, creation: None }, // non confirmée
        ];
        let spent = 5_000_000;
        let attente = c.attente(spent as i64);
        assert_eq!(delai(&c, &ps, 1_000, spent), Some(attente + MARGE));
        assert_eq!(delai(&c, &ps, 1_000 + attente + MARGE, spent), Some(0));
        assert_eq!(delai(&c, &ps[1..], 5_000_000, spent), None, "aucune pièce utilisable");
    }

    #[test]
    fn vue_courbe_et_risque() {
        let c = coeur(50_000_000, 288_000);
        let op = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
        let etat = EtatCoeur { version: VERSION.into(), capacite: c.capacite, periode: c.periode, agent: String::new(), cree_daa: 0,
            apports: vec![Apport { txid: String::new(), sompi: 2_000_000_000, daa: 0 }] };
        let v = Vue { coeur: c, adresse: String::new(), pieces: vec![Piece { outpoint: op, valeur: 2_000_000_000, creation: Some(0) }], now: 0, etat: Some(etat) };
        assert_eq!(v.immediate(), 0, "un mandat neuf démarre à zéro");
        assert_eq!(v.courbe(0), 0);
        assert_eq!(v.courbe(288_000), 50_000_000, "une capacité au bout d'une période");
        assert_eq!(v.courbe(crate::JOUR_DAA as u64), 150_000_000);
        assert_eq!(v.courbe(u64::MAX / 2), 2_000_000_000, "jamais plus que le capital");
        assert_eq!(v.fenetre(crate::JOUR_DAA as u64), 150_000_000);
    }
}

//! Le coffre Plafond (cœur v0.6) sur le réseau : création, paiement, rechargement, gel, état.
//!
//! Un coffre = une adresse (le script ne change jamais) et les pièces qu'elle contient. Il n'y a
//! pas d'état à suivre sur la chaîne : on lit les pièces de l'adresse sur le nœud, avec leur score
//! d'inscription, et le réseau fait respecter le rythme (verrou relatif). Le fichier local ne garde
//! que les réglages et les apports du propriétaire, pour tracer la courbe de perte promise.

use crate::coeur::{self, Coeur};
use crate::*;

pub const VERSION: &str = "coeur-v0.7";
/// Coffres créés avant l'adresse de retour : retrouvés et gelables, plus créés.
pub const VERSION_V06: &str = "coeur-v0.6";
/// Marge (unités DAA, ≈ 2 s) entre l'âge lu et l'âge exigé : le bloc qui accepte le paiement est
/// toujours un peu plus tard que la lecture.
pub const MARGE: u64 = 20;

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
    /// Adresse de retour du coffre (v0.7) : seule destination possible du gel et du retrait.
    /// Absente : coffre v0.6 (le gel rend au propriétaire).
    #[serde(default)]
    pub retour: Option<String>,
    pub capacite: i64,
    pub periode: i64,
    pub agent: String,
    pub cree_daa: u64,
    #[serde(default)]
    pub apports: Vec<Apport>,
    /// Pièces vues à la dernière lecture (outpoint, valeur) : sert à reconnaître les achats.
    #[serde(default)]
    pub vues: Vec<(String, u64)>,
    /// Achats reconnus (les 50 derniers), plus récents en dernier.
    #[serde(default)]
    pub achats: Vec<AchatVu>,
}

/// Un achat de l'agent, reconnu sur la chaîne : une pièce a disparu et sa continuation est apparue.
/// La dépense comprend les frais ; le bénéficiaire n'est pas lisible sans index des transactions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AchatVu {
    pub txid: String,
    pub sompi: u64,
    pub daa: u64,
}

fn cle(p: &Piece) -> String {
    format!("{}:{}", p.outpoint.transaction_id, p.outpoint.index)
}

/// R57 : la date d'un apport est notée avant l'envoi (score virtuel lu sur le nœud). Si la pièce
/// est en réalité inscrite à un score plus petit (mineur en retard sur notre nœud, réorganisation),
/// son âge court depuis plus tôt que la courbe affichée. On recale donc l'apport sur l'inscription
/// lue sur le nœud, uniquement vers le passé : la courbe promise ne peut que s'élargir, jamais se
/// resserrer à tort. Renvoie vrai si une date a changé.
pub fn recaler_apports(e: &mut EtatCoeur, pieces: &[Piece]) -> bool {
    let mut change = false;
    for p in pieces {
        let Some(inscrit) = p.creation else { continue };
        let txid = p.outpoint.transaction_id.to_string();
        for a in e.apports.iter_mut().filter(|a| a.txid == txid && a.daa > inscrit) {
            a.daa = inscrit;
            change = true;
        }
    }
    if let Some(premier) = e.apports.iter().map(|a| a.daa).min().filter(|d| *d < e.cree_daa) {
        e.cree_daa = premier;
        change = true;
    }
    change
}

/// Compare les pièces lues aux pièces vues la dernière fois et enregistre les achats.
/// Une pièce nouvelle qui n'est pas un apport du propriétaire est une continuation ; la dépense est
/// ce qui a disparu moins ce qui est réapparu. Renvoie vrai si l'état a changé.
pub fn suivre(e: &mut EtatCoeur, pieces: &[Piece], now: u64) -> bool {
    let recale = recaler_apports(e, pieces);
    let actuelles: Vec<(String, u64)> = pieces.iter().filter(|p| p.creation.is_some()).map(|p| (cle(p), p.valeur)).collect();
    if actuelles == e.vues {
        return recale;
    }
    if !e.vues.is_empty() {
        let apports: std::collections::HashSet<&str> = e.apports.iter().map(|a| a.txid.as_str()).collect();
        let disparues: u64 = e.vues.iter().filter(|v| !actuelles.contains(v)).map(|v| v.1).sum();
        let nouvelles: Vec<&(String, u64)> = actuelles.iter().filter(|a| !e.vues.contains(a)).collect();
        let continuations: Vec<&&(String, u64)> = nouvelles.iter().filter(|n| !apports.contains(n.0.split(':').next().unwrap_or(""))).collect();
        // Pièces d'un apport : ce qui dépasse l'apport vient d'une pièce du coffre regonflée (R62),
        // ce n'est pas une dépense.
        let mut par_apport: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        for n in nouvelles.iter().filter(|n| apports.contains(n.0.split(':').next().unwrap_or(""))) {
            *par_apport.entry(n.0.split(':').next().unwrap_or("")).or_default() += n.1;
        }
        let recycle: u64 = par_apport
            .iter()
            .map(|(t, v)| v.saturating_sub(e.apports.iter().filter(|a| a.txid == *t).map(|a| a.sompi).sum()))
            .sum();
        let revenu: u64 = continuations.iter().map(|n| n.1).sum::<u64>() + recycle;
        if let (Some(dernier), true) = (continuations.last(), disparues > revenu) {
            e.achats.push(AchatVu { txid: dernier.0.split(':').next().unwrap_or("").to_string(), sompi: disparues - revenu, daa: now });
            let n = e.achats.len();
            if n > 50 {
                e.achats.drain(..n - 50);
            }
        }
    }
    e.vues = actuelles;
    true
}

/// Enregistre l'état suivi (achats reconnus) ; erreur ignorée : ce n'est qu'un affichage.
pub fn memoriser(e: &EtatCoeur) {
    let _ = enregistrer(e);
}

pub fn charger() -> Option<EtatCoeur> {
    let e: EtatCoeur = serde_json::from_str(&fs::read_to_string(state_path()).ok()?).ok()?;
    (e.version == VERSION || e.version == VERSION_V06).then_some(e)
}

/// Adresse de retour d'un coffre : celle fixée à la création, sinon l'adresse du propriétaire
/// (valeur par défaut, et seule destination possible d'un coffre v0.6).
pub fn adresse_retour(e: Option<&EtatCoeur>, owner_pk: &[u8]) -> Res<Address> {
    match e.and_then(|e| e.retour.as_deref()) {
        Some(a) => valider_retour(a),
        None => Ok(Address::new(Prefix::Testnet, Version::PubKey, owner_pk)),
    }
}

/// Adresse de retour saisie par l'utilisateur : une adresse du réseau de test, valide.
pub fn valider_retour(a: &str) -> Res<Address> {
    let adr = Address::try_from(a.trim()).map_err(|_| format!("adresse de retour invalide : {a}"))?;
    if adr.prefix != Prefix::Testnet {
        return Err("adresse de retour : une adresse du réseau de test (kaspatest:…) est attendue".into());
    }
    Ok(adr)
}

/// Empreinte de l'adresse de retour, telle que le contrat la compare (v0.7).
pub fn empreinte_retour(adr: &Address) -> Vec<u8> {
    crate::sequestre::spk_hash(&pay_to_address_script(adr)).to_vec()
}

pub fn enregistrer(e: &EtatCoeur) -> Res<()> {
    let p = state_path();
    if let Some(dir) = std::path::Path::new(&p).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(p, serde_json::to_string_pretty(e)?)?;
    Ok(())
}

/// Le contrat du coffre : réglages du fichier s'il existe (ils font foi), sinon règles courantes.
pub fn coeur_de(owner_pk: &[u8], agent_pk: &[u8]) -> Coeur {
    let e = charger();
    let (capacite, periode) = match &e {
        Some(e) => (e.capacite, e.periode),
        None => (regles().capacite, regles().recharge_daa),
    };
    let retour = match &e {
        Some(e) if e.version == VERSION_V06 => None,
        // Adresse enregistrée invalide (fichier modifié à la main) : repli sur le propriétaire.
        _ => Some(empreinte_retour(
            &adresse_retour(e.as_ref(), owner_pk).unwrap_or_else(|_| Address::new(Prefix::Testnet, Version::PubKey, owner_pk)),
        )),
    };
    Coeur { owner: owner_pk.to_vec(), agent: agent_pk.to_vec(), capacite, periode, retour }
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
pub async fn financer(c: &KaspaRpcClient, owner: &Keypair, montant: u64) -> Res<(Vec<UtxoEntry>, Vec<TransactionInput>, u64)> {
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

/// Découpe un dépôt en `k` pièces presque égales (la dernière prend le reste).
pub fn decouper(montant: u64, k: i64) -> Vec<u64> {
    let k = k.max(1) as u64;
    let part = montant / k;
    (0..k).map(|i| if i + 1 == k { montant - part * (k - 1) } else { part }).collect()
}

/// Envoie `montant` du propriétaire vers l'adresse du coffre, en `k` pièces (création ou rechargement).
async fn verser(c: &KaspaRpcClient, owner: &Keypair, art: &SilAbiArtifact, montant: u64, k: i64) -> Res<String> {
    let (entries, inputs, total) = financer(c, owner, montant).await?;
    let fee = FEE * inputs.len() as u64;
    let mut outputs: Vec<TransactionOutput> = decouper(montant, k).into_iter().map(|v| TransactionOutput::new(v, vault_spk(art))).collect();
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
    deployer_vers(owner, agent, std::env::var("PLAFOND_RETOUR").ok().filter(|a| !a.trim().is_empty()).as_deref()).await
}

/// Crée le coffre avec une adresse de retour : `None` = l'adresse du propriétaire (par défaut).
pub async fn deployer_vers(owner: &Keypair, agent: &Keypair, retour: Option<&str>) -> Res<String> {
    if charger().is_some() || load_state().is_ok() {
        return Err("un coffre est déjà déployé".into());
    }
    let r = regles();
    let retour_adr = match retour {
        Some(a) => valider_retour(a)?,
        None => address(owner),
    };
    let coeur = Coeur {
        owner: xonly(owner),
        agent: agent_pk(agent),
        capacite: r.capacite,
        periode: r.recharge_daa,
        retour: Some(empreinte_retour(&retour_adr)),
    };
    let art = coeur.artifact()?;
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let txid = verser(&c, owner, &art, r.depot, r.pieces).await?;
    let e = EtatCoeur {
        version: VERSION.into(),
        // Rien d'enregistré pour l'adresse par défaut : le coffre suit l'adresse du propriétaire.
        retour: retour.map(|_| retour_adr.to_string()),
        capacite: coeur.capacite,
        periode: coeur.periode,
        agent: hex::encode(&coeur.agent),
        cree_daa: daa,
        // Une entrée par pièce : la courbe promise est la somme des courbes des pièces.
        apports: decouper(r.depot, r.pieces).into_iter().map(|sompi| Apport { txid: txid.clone(), sompi, daa }).collect(),
        vues: vec![],
        achats: vec![],
    };
    enregistrer(&e)?;
    println!("Coffre créé (cœur v0.7) : {} TKAS en {} pièce(s) à l'adresse {}", r.depot as f64 / 1e8, r.pieces, adresse(&art)?);
    println!("Adresse de retour (gel, retrait) : {retour_adr}");
    println!("Transaction : {}", explorer(&txid));
    liberer(&c).await?;
    Ok(txid)
}

/// Nombre de pièces du mandat, fixé à la création : les apports de la transaction de création
/// (une entrée par pièce, même identifiant).
pub fn pieces_du_mandat(e: &EtatCoeur) -> usize {
    e.apports.first().map(|a| e.apports.iter().filter(|b| b.txid == a.txid).count()).unwrap_or(1).max(1)
}

/// Ce que fait « Ajouter des fonds ».
#[derive(Debug, Clone, PartialEq)]
pub enum Recharge {
    /// Regonfler cette pièce : elle repart d'un âge nul avec l'apport en plus. Le nombre de pièces,
    /// donc le rythme maximal du mandat, ne change pas (R62).
    Regonfler(TransactionOutpoint, u64),
    /// Il manque des pièces (coffre vidé par les achats) : en recréer une rend au mandat son rythme
    /// d'origine, sans le dépasser.
    Nouvelle,
    /// Toutes les pièces utilisables attendent leur confirmation : réessayer dans quelques secondes.
    Attendre,
}

/// R62 : choisir comment recharger sans ajouter de rythme. Chaque pièce a son propre rythme ; créer
/// une pièce de plus ferait dépasser le budget par période affiché dans les règles du mandat.
/// On regonfle donc la pièce qui a le moins de budget disponible maintenant (la plus jeune) : c'est
/// elle qui perd le moins en repartant d'un âge nul.
pub fn choisir_recharge(coeur: &Coeur, pieces: &[Piece], k: usize, now: u64) -> Recharge {
    let utiles: Vec<&Piece> = pieces.iter().filter(|p| p.valeur >= coeur_plancher()).collect();
    if utiles.len() < k {
        return Recharge::Nouvelle;
    }
    utiles
        .iter()
        .filter_map(|p| p.creation.map(|cr| (coeur.immediate(p.valeur, now.saturating_sub(cr)), *p)))
        .min_by_key(|(dispo, p)| (*dispo, p.valeur))
        .map(|(_, p)| Recharge::Regonfler(p.outpoint, p.valeur))
        .unwrap_or(Recharge::Attendre)
}

/// Transaction de rechargement par regonflement : la pièce du coffre (dépensée par `ownerControl`)
/// et les pièces du propriétaire donnent UNE pièce du coffre (valeur + apport), plus le rendu.
pub fn tx_regonfler(
    art: &SilAbiArtifact,
    piece: (TransactionOutpoint, u64),
    proprio: (Vec<UtxoEntry>, Vec<TransactionInput>, u64),
    montant: u64,
    owner: &Keypair,
) -> Res<(Transaction, Vec<UtxoEntry>)> {
    let (op, valeur) = piece;
    let (entrees_p, inputs_p, total_p) = proprio;
    let mut entries = vec![UtxoEntry::new(valeur, vault_spk(art), 0, false, None)];
    entries.extend(entrees_p);
    let mut inputs = vec![TransactionInput::new_with_compute_budget(op, vec![], 0, coeur::CB_OWNER)];
    inputs.extend(inputs_p);
    let fee = FEE * inputs.len() as u64;
    let rendu = total_p.checked_sub(montant + fee).ok_or("solde du propriétaire insuffisant pour l'apport et les frais")?;
    let mut outputs = vec![TransactionOutput::new(valeur + montant, vault_spk(art))];
    if rendu > 0 {
        outputs.push(TransactionOutput::new(rendu, pay_to_address_script(&address(owner))));
    }
    let mut tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    for i in 0..tx.inputs.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script =
            if i == 0 { vault_sigscript(art, "ownerControl", &[s.into()])? } else { ScriptBuilder::new().add_data(&s)?.drain() };
    }
    tx.finalize();
    Ok((tx, entries))
}

/// « Ajouter des fonds ». Le rythme maximal du mandat reste celui choisi à la création (R62) :
/// on regonfle une pièce existante au lieu d'en ajouter une. L'apport devient dépensable
/// progressivement, au rythme du mandat. La courbe promise reste une borne juste : l'apport est
/// noté comme une racine à sa date, et la pièce regonflée a déjà sa propre courbe.
pub async fn recharger(owner: &Keypair, agent: &Keypair, montant: u64) -> Res<String> {
    let mut e = charger().ok_or("aucun coffre v0.6 déployé")?;
    let coeur = coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact()?;
    let c = connect().await?;
    let daa = virtual_daa(&c).await?;
    let ps = pieces(&c, &art).await?;
    let (txid, quoi) = match choisir_recharge(&coeur, &ps, pieces_du_mandat(&e), daa) {
        Recharge::Nouvelle => (verser(&c, owner, &art, montant, 1).await?, "pièce recréée"),
        Recharge::Attendre => {
            liberer(&c).await?;
            return Err("le coffre attend la confirmation d'une opération : réessayer dans quelques secondes".into());
        }
        Recharge::Regonfler(op, valeur) => {
            // Une entrée de plus que `verser` (la pièce du coffre) : `financer` prévoit ces frais.
            let proprio = financer(&c, owner, montant).await?;
            let (tx, _) = tx_regonfler(&art, (op, valeur), proprio, montant, owner)?;
            match c.submit_transaction(garde_diffusion(&tx)?, false).await {
                Ok(id) => (id.to_string(), "pièce existante regonflée, rythme inchangé"),
                Err(err) => {
                    liberer(&c).await?;
                    return Err(format!("rechargement refusé ({err}) : un achat utilise peut-être cette pièce, réessayer").into());
                }
            }
        }
    };
    e.apports.push(Apport { txid: txid.clone(), sompi: montant, daa });
    enregistrer(&e)?;
    println!("Coffre rechargé de {} TKAS ({quoi}) : {}", montant as f64 / 1e8, explorer(&txid));
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

/// Pièces rapatriées par lot : au-delà, la transaction dépasserait la masse standard (mesuré par
/// `gel_par_lots_sous_la_masse_standard`).
pub const LOT_GEL: usize = 40;

/// Pièces à rapatrier, en lots, plus grosses d'abord. Une pièce sous le plancher KIP-9 ne peut pas
/// servir à un paiement (sa sortie serait trop lourde) : elle est sans danger et n'est pas rapatriée,
/// sinon des centaines de pièces minuscules déposées par un tiers (R53) rendraient le gel impossible.
pub fn lots(pieces: &[Piece]) -> Vec<Vec<Piece>> {
    let mut utiles: Vec<Piece> = pieces.iter().filter(|p| p.creation.is_some() && p.valeur >= coeur_plancher()).cloned().collect();
    utiles.sort_by(|a, b| b.valeur.cmp(&a.valeur));
    utiles.chunks(LOT_GEL).map(|c| c.to_vec()).collect()
}

/// Transaction de gel d'un lot : ses pièces vers l'adresse de retour `dest`.
/// v0.7 : une sortie par pièce (entrée i -> sortie i, exigé par le contrat), au plus `capacite` de
/// frais par pièce. v0.6 (`coeur.retour == None`) : une seule sortie, comme avant.
pub fn tx_gel(coeur: &Coeur, art: &SilAbiArtifact, lot: &[Piece], owner: &Keypair, dest: &Address, frais: u64) -> Res<(Transaction, Vec<UtxoEntry>)> {
    let total: u64 = lot.iter().map(|p| p.valeur).sum();
    let entries: Vec<UtxoEntry> = lot.iter().map(|p| UtxoEntry::new(p.valeur, vault_spk(art), p.creation.unwrap_or(0), false, None)).collect();
    let inputs = lot.iter().map(|p| TransactionInput::new_with_compute_budget(p.outpoint, vec![], 0, coeur::CB_OWNER)).collect();
    let spk = pay_to_address_script(dest);
    let sorties = if coeur.retour.is_some() {
        // Au plus `capacite` par pièce (règle du contrat) et au plus un tiers de la pièce : une
        // sortie trop réduite alourdirait la masse de stockage (KIP-9) plus qu'elle ne paierait.
        let par_piece = frais.div_ceil(lot.len().max(1) as u64);
        lot.iter().map(|p| TransactionOutput::new(p.valeur - par_piece.min(coeur.capacite.max(0) as u64).min(p.valeur / 3), spk.clone())).collect()
    } else {
        vec![TransactionOutput::new(total.checked_sub(frais).ok_or("lot trop petit pour les frais du gel")?, spk)]
    };
    let mut tx = Transaction::new(1, inputs, sorties, 0, Default::default(), 0, vec![]);
    for i in 0..tx.inputs.len() {
        let s = sign(&tx, &entries, i, owner);
        tx.inputs[i].signature_script = vault_sigscript(art, "ownerControl", &[s.into()])?;
    }
    tx.finalize();
    Ok((tx, entries))
}

/// Frais minimaux du réseau : 100 sompi par gramme de la plus grande des trois masses.
const SOMPI_PAR_GRAMME: u64 = 100;

/// Transactions de gel d'un lot, frais ajustés à la masse réelle (v0.7 : une sortie par pièce).
/// `tentative` (1, 2, …) multiplie le minimum du réseau pour passer devant un paiement en attente.
/// Si le lot dépasse la masse standard (sorties proches du plancher KIP-9), il est coupé en deux.
/// Coffre v0.6 : une seule sortie, frais forfaitaires comme avant.
pub fn gel_txs(coeur: &Coeur, art: &SilAbiArtifact, lot: &[Piece], owner: &Keypair, dest: &Address, tentative: u64) -> Res<Vec<Transaction>> {
    if lot.is_empty() {
        return Ok(vec![]);
    }
    if coeur.retour.is_none() {
        let total: u64 = lot.iter().map(|p| p.valeur).sum();
        let frais = (2 * FEE * lot.len() as u64 * tentative).min(total / 2);
        return Ok(vec![tx_gel(coeur, art, lot, owner, dest, frais)?.0]);
    }
    // Point fixe : les frais changent la masse de stockage, qui change les frais.
    let mut frais = 0u64;
    let mut essai = None;
    for _ in 0..4 {
        let (tx, entries) = tx_gel(coeur, art, lot, owner, dest, frais)?;
        let m = masse::masses(&tx, &entries).ok_or("masse du gel incalculable")?;
        let besoin = m.compute.max(m.storage).max(m.transient) * SOMPI_PAR_GRAMME * (1 + tentative);
        essai = Some((tx, m));
        if besoin <= frais {
            break;
        }
        frais = besoin;
    }
    let (tx, m) = essai.expect("au moins un essai");
    if m.standard() {
        return Ok(vec![tx]);
    }
    if lot.len() == 1 {
        return Err("pièce impossible à geler seule : masse au-delà de la limite du réseau".into());
    }
    let (a, b) = lot.split_at(lot.len() / 2);
    let mut txs = gel_txs(coeur, art, a, owner, dest, tentative)?;
    txs.extend(gel_txs(coeur, art, b, owner, dest, tentative)?);
    Ok(txs)
}

/// Durée (unités DAA, ≈ 10 s) pendant laquelle l'adresse du coffre doit rester vide avant que le
/// gel soit annoncé terminé (R58). Les blocs parallèles peuvent être réordonnés pendant quelques
/// secondes : un paiement de l'agent placé dans un bloc concurrent peut finalement passer avant le
/// gel et laisser une continuation dans le coffre.
pub const GEL_STABLE: u64 = 100;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum EtatGel {
    /// Des pièces utilisables sont dans le coffre : il faut les rapatrier.
    ARapatrier,
    /// Rien à rapatrier pour l'instant, mais ce n'est pas encore sûr (continuation non confirmée,
    /// ou adresse vide depuis trop peu de temps).
    EnAttente,
    /// L'adresse est restée vide pendant `GEL_STABLE` : le gel est terminé.
    Stable,
}

/// Décide quand un gel est vraiment terminé, à partir des lectures successives du nœud.
#[derive(Default, Debug)]
pub struct SuiviGel {
    vide_depuis: Option<u64>,
}

impl SuiviGel {
    pub fn observer(&mut self, pieces: &[Piece], now: u64) -> EtatGel {
        if !lots(pieces).is_empty() {
            self.vide_depuis = None;
            return EtatGel::ARapatrier;
        }
        if pieces.iter().any(|p| p.creation.is_none() && p.valeur >= coeur_plancher()) {
            self.vide_depuis = None;
            return EtatGel::EnAttente;
        }
        match self.vide_depuis {
            // Première lecture vide, ou horloge qui recule (réorganisation) : le compte repart.
            None => self.vide_depuis = Some(now),
            Some(d) if now < d => self.vide_depuis = Some(now),
            Some(d) if now - d >= GEL_STABLE => return EtatGel::Stable,
            Some(_) => {}
        }
        EtatGel::EnAttente
    }
}

/// Gel prioritaire : le propriétaire rapatrie TOUTES les pièces de l'adresse (`ownerControl`).
/// Un paiement de l'agent en attente sur une pièce est remplacé (frais plus élevés) ; s'il passe
/// quand même, sa continuation est une nouvelle pièce, rapatriée au tour suivant. Le gel n'est
/// annoncé terminé qu'une fois l'adresse restée vide pendant `GEL_STABLE` (R58).
pub async fn geler(owner: &Keypair, agent: &Keypair) -> Res<String> {
    let coeur = coeur_de(&xonly(owner), &agent_pk(agent));
    let art = coeur.artifact()?;
    let c = connect().await?;
    let proprio = adresse_retour(charger().as_ref(), &xonly(owner))?;
    let mut ids = vec![];
    let mut suivi = SuiviGel::default();
    let mut tentative = 0u64;
    let mut stable = false;
    let debut = std::time::Instant::now();
    while debut.elapsed().as_secs() < 600 {
        let ps = pieces(&c, &art).await?;
        let now = virtual_daa(&c).await?;
        match suivi.observer(&ps, now) {
            EtatGel::Stable => {
                stable = true;
                break;
            }
            EtatGel::EnAttente => {
                // Coffre vide dès la première lecture et rien d'envoyé : inutile d'attendre.
                if ids.is_empty() && tentative == 0 && ps.iter().all(|p| p.valeur < coeur_plancher()) {
                    stable = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            EtatGel::ARapatrier => {}
        }
        if tentative >= 8 {
            break; // huit tentatives : on rend la main, le propriétaire relance
        }
        tentative += 1;
        let txs: Vec<Transaction> =
            lots(&ps).iter().map(|lot| gel_txs(&coeur, &art, lot, owner, &proprio, tentative)).collect::<Res<Vec<_>>>()?.concat();
        for tx in &txs {
            let id = tx.id();
            let envoi = match c.submit_transaction(garde_diffusion(tx)?, false).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    println!("tentative {tentative} : {err} ; remplacement du paiement en attente");
                    c.submit_transaction_replacement(garde_diffusion(tx)?).await.map(|_| ()).map_err(|e| e.to_string())
                }
            };
            if let Err(err) = envoi {
                println!("tentative {tentative} refusée : {err}");
                continue;
            }
            for _ in 0..30 {
                if c.get_utxos_by_addresses(vec![proprio.clone()]).await?.iter().any(|u| u.outpoint.transaction_id == id) {
                    let rendu: u64 = tx.outputs.iter().map(|o| o.value).sum();
                    println!("{} pièce(s) rapatriée(s) vers {proprio} : {} TKAS, {}", tx.inputs.len(), rendu as f64 / 1e8, explorer(&id.to_string()));
                    ids.push(id.to_string());
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    let reste = lots(&pieces(&c, &art).await?).concat();
    liberer(&c).await?;
    if !reste.is_empty() {
        return Err(format!("gel incomplet : {} pièce(s) utilisables encore dans le coffre, relancer", reste.len()).into());
    }
    if !stable {
        return Err("gel envoyé mais pas encore confirmé de façon stable : relancer pour vérifier".into());
    }
    if ids.is_empty() {
        // Rien à rapatrier et coffre stable : déjà gelé (par exemple par un gel précédent qui a
        // gagné une course). L'état local n'a plus rien à suivre ; le garder ferait afficher
        // l'argent rapatrié comme une perte.
        let _ = fs::remove_file(state_path());
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
    /// Pièce non confirmée : âge 0. C'est une borne sûre, pas une approximation : elle ne peut être
    /// dépensée qu'après son inscription, et son âge ne courra qu'à partir de là.
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
        Coeur { owner: xonly(&k(1)), agent: xonly(&k(2)), capacite: c, periode: r, retour: Some(empreinte_retour(&address(&k(11)))) }
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

    /// R53 : un tiers dépose des centaines de pièces minuscules. Le gel les ignore (elles ne peuvent
    /// pas payer) et rapatrie les vraies pièces par lots, chacun sous la masse standard.
    #[test]
    fn gel_par_lots_sous_la_masse_standard() {
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let c = coeur(50_000_000, 288_000);
        let art = c.artifact().unwrap();
        let dest = address(&k(11));
        let p = |i: u32, v: u64| Piece { outpoint: TransactionOutpoint::new(TransactionId::from_bytes([7; 32]), i), valeur: v, creation: Some(1) };
        let mut ps: Vec<Piece> = (0..500).map(|i| p(i, 5_000)).collect(); // poussière
        ps.extend((500..600).map(|i| p(i, coeur_plancher()))); // 100 pièces juste au plancher
        ps.push(p(600, 3_000_000_000));
        let l = lots(&ps);
        assert_eq!(l.iter().map(|x| x.len()).sum::<usize>(), 101, "la poussière est ignorée");
        assert_eq!(l[0][0].valeur, 3_000_000_000, "plus grosses pièces d'abord");
        let entrees = |tx: &Transaction| -> Vec<UtxoEntry> {
            tx.inputs.iter().map(|i| UtxoEntry::new(ps.iter().find(|p| p.outpoint == i.previous_outpoint).unwrap().valeur, vault_spk(&art), 1, false, None)).collect()
        };
        // Toutes les tentatives d'escalade (R58) restent diffusables, quitte à couper le lot.
        for tentative in 1..=8u64 {
            for lot in &l {
                for tx in gel_txs(&c, &art, lot, &k(1), &dest, tentative).unwrap() {
                    let m = masse::masses(&tx, &entrees(&tx)).unwrap();
                    if tentative == 1 {
                        eprintln!("lot de {} pièces : calcul {} g, stockage {} g", tx.inputs.len(), m.compute, m.storage);
                    }
                    assert!(m.standard(), "tentative {tentative} : lot de {} pièces non diffusable", tx.inputs.len());
                    assert_eq!(tx.inputs.len(), tx.outputs.len(), "une sortie par pièce");
                    assert!(tx.outputs.iter().all(|o| o.script_public_key == pay_to_address_script(&dest)), "tout va à l'adresse de retour");
                }
            }
        }
    }

    #[test]
    fn achats_reconnus_sans_lignee() {
        let op = |t: u8, i: u32| TransactionOutpoint::new(TransactionId::from_bytes([t; 32]), i);
        let depot = TransactionId::from_bytes([1; 32]).to_string();
        let mut e = EtatCoeur { version: VERSION.into(), retour: None, capacite: 1, periode: 1, agent: String::new(), cree_daa: 0,
            apports: vec![Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }, Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }], vues: vec![], achats: vec![] };
        let p = |t: u8, i: u32, v: u64| Piece { outpoint: op(t, i), valeur: v, creation: Some(1) };
        assert!(suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10));
        assert!(e.achats.is_empty(), "première lecture : aucun achat");
        assert!(!suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 11), "rien n'a changé");
        // L'agent dépense 300 (frais compris) depuis la pièce 1:1 ; continuation 2:1 de 700.
        assert!(suivre(&mut e, &[p(1, 0, 1_000), p(2, 1, 700)], 20));
        assert_eq!(e.achats, vec![AchatVu { txid: TransactionId::from_bytes([2; 32]).to_string(), sompi: 300, daa: 20 }]);
        // Le propriétaire recharge (txid déclaré comme apport) : pas un achat.
        e.apports.push(Apport { txid: TransactionId::from_bytes([3; 32]).to_string(), sompi: 500, daa: 30 });
        suivre(&mut e, &[p(1, 0, 1_000), p(2, 1, 700), p(3, 0, 500)], 30);
        assert_eq!(e.achats.len(), 1);
    }

    /// R57 : l'outil note la date d'un apport AVANT de l'envoyer (score virtuel lu sur le nœud).
    /// Le bloc qui inscrit la pièce peut porter un score un peu plus petit (mineur en retard de
    /// quelques blocs sur notre nœud, ou réorganisation). L'âge de la pièce court alors depuis
    /// plus tôt que la courbe affichée : l'agent peut dépenser quelques sompi de plus que la
    /// « courbe promise ». La courbe doit partir de la date d'inscription réelle, lue sur le nœud.
    #[test]
    fn r57_courbe_recalee_sur_l_inscription_reelle() {
        let c = coeur(200_000_000, 864_000);
        let depot = TransactionId::from_bytes([1; 32]);
        let (note, inscrit) = (1_000u64, 997u64); // noté par l'outil ; réellement inscrit
        let mut e = EtatCoeur { version: VERSION.into(), retour: None, capacite: c.capacite, periode: c.periode, agent: String::new(), cree_daa: note,
            apports: vec![Apport { txid: depot.to_string(), sompi: 1_000_000_000, daa: note }], vues: vec![], achats: vec![] };
        let pieces = vec![Piece { outpoint: TransactionOutpoint::new(depot, 0), valeur: 1_000_000_000, creation: Some(inscrit) }];
        // L'agent paie 0,5 TKAS dès que le réseau le permet : à inscription + attente.
        let spent = 50_000_000u64;
        let x = inscrit + c.attente(spent as i64);
        assert!(c.immediate(1_000_000_000, x - inscrit) >= spent, "le réseau accepte ce paiement à l'instant x");
        assert!(suivre(&mut e, &pieces, inscrit + 10), "la première lecture recale l'apport");
        assert_eq!((e.apports[0].daa, e.cree_daa), (inscrit, inscrit));
        let v = Vue { coeur: c, adresse: String::new(), pieces, now: x, etat: Some(e.clone()) };
        assert!(v.courbe(x) >= spent, "courbe promise {} < perte possible {spent}", v.courbe(x));
        // Jamais dans l'autre sens : une inscription plus tardive que la note ne resserre pas la courbe.
        let tard = vec![Piece { outpoint: TransactionOutpoint::new(depot, 0), valeur: 1_000_000_000, creation: Some(2_000) }];
        suivre(&mut e, &tard, 2_010);
        assert_eq!(e.apports[0].daa, inscrit);
    }

    /// R58 : le gel ne doit être annoncé « terminé » qu'une fois stable. Les blocs parallèles du
    /// réseau peuvent être réordonnés pendant quelques secondes : un paiement de l'agent sur la
    /// même pièce, placé dans un bloc concurrent, peut finalement passer AVANT le gel et l'annuler.
    /// Sa continuation reste alors dans le coffre. L'ancienne règle (terminé dès que l'adresse
    /// paraît vide, fichier local supprimé) déclarait le coffre gelé alors qu'il ne l'était pas.
    #[test]
    fn r58_gel_confirme_seulement_s_il_est_stable() {
        let op = |t: u8| TransactionOutpoint::new(TransactionId::from_bytes([t; 32]), 1);
        let grosse = Piece { outpoint: op(1), valeur: 1_000_000_000, creation: Some(500) };
        let mut suivi = SuiviGel::default();
        assert_eq!(suivi.observer(std::slice::from_ref(&grosse), 1_000), EtatGel::ARapatrier);
        // Le gel est inscrit (vu du nœud) : l'adresse paraît vide. Pas encore terminé.
        assert_eq!(suivi.observer(&[], 1_003), EtatGel::EnAttente, "l'ancienne règle disait « terminé » ici");
        assert_eq!(suivi.observer(&[], 1_003 + GEL_STABLE - 1), EtatGel::EnAttente);
        // Réordonnancement : le paiement de l'agent l'emporte, sa continuation apparaît.
        let continuation = Piece { outpoint: op(2), valeur: 950_000_000, creation: Some(1_002) };
        assert_eq!(suivi.observer(std::slice::from_ref(&continuation), 1_010), EtatGel::ARapatrier, "le gel reprend");
        // Nouveau gel inscrit ; il faut de nouveau toute la durée de stabilité, à partir de là.
        assert_eq!(suivi.observer(&[], 1_020), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 1_020 + GEL_STABLE - 1), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 1_020 + GEL_STABLE), EtatGel::Stable);

        // Une continuation pas encore confirmée fait attendre, et remet le compteur à zéro.
        let mut suivi = SuiviGel::default();
        let en_vol = Piece { outpoint: op(3), valeur: 950_000_000, creation: None };
        assert_eq!(suivi.observer(&[], 2_000), EtatGel::EnAttente);
        assert_eq!(suivi.observer(std::slice::from_ref(&en_vol), 2_050), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 2_000 + GEL_STABLE), EtatGel::EnAttente, "le compteur est reparti de zéro");
        // L'horloge recule (réorganisation) : le compteur repart aussi.
        let mut suivi = SuiviGel::default();
        assert_eq!(suivi.observer(&[], 3_000), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 2_990), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 2_990 + GEL_STABLE - 1), EtatGel::EnAttente);
        assert_eq!(suivi.observer(&[], 2_990 + GEL_STABLE), EtatGel::Stable);
        // La poussière sous le plancher (R53) n'empêche pas de conclure.
        let poussiere = Piece { outpoint: op(4), valeur: 5_000, creation: Some(1) };
        let mut suivi = SuiviGel::default();
        assert_eq!(suivi.observer(std::slice::from_ref(&poussiere), 10), EtatGel::EnAttente);
        assert_eq!(suivi.observer(std::slice::from_ref(&poussiere), 10 + GEL_STABLE), EtatGel::Stable);
    }

    /// Cible 7 : `suivre` face aux dépôts de tiers et aux continuations simultanées. L'affichage
    /// des achats est une aide, pas une mesure de sécurité : il peut être brouillé par quelqu'un
    /// qui dépose de l'argent dans le coffre au même moment (à ses frais, sompi pour sompi), mais
    /// jamais dans un sens qui cache une perte nette. Comportement constaté, figé ici.
    #[test]
    fn suivre_face_aux_depots_de_tiers() {
        let op = |t: u8, i: u32| TransactionOutpoint::new(TransactionId::from_bytes([t; 32]), i);
        let depot = TransactionId::from_bytes([1; 32]).to_string();
        let neuf = || EtatCoeur { version: VERSION.into(), retour: None, capacite: 1, periode: 1, agent: String::new(), cree_daa: 0,
            apports: vec![Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }, Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }], vues: vec![], achats: vec![] };
        let p = |t: u8, i: u32, v: u64| Piece { outpoint: op(t, i), valeur: v, creation: Some(1) };
        let total = |e: &EtatCoeur| e.achats.iter().map(|a| a.sompi).sum::<u64>();
        let perte_nette = |e: &EtatCoeur, ps: &[Piece]| e.apports.iter().map(|a| a.sompi).sum::<u64>().saturating_sub(ps.iter().map(|p| p.valeur).sum());

        // (a) Dépôt d'un tiers seul : pas un achat.
        let mut e = neuf();
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10);
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000), p(9, 0, 5)], 20);
        assert!(e.achats.is_empty());

        // (b) Deux paiements entre deux lectures (une continuation par pièce) : un seul achat
        // affiché, du bon total.
        let mut e = neuf();
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10);
        let apres = [p(2, 1, 700), p(3, 1, 900)];
        suivre(&mut e, &apres, 20);
        assert_eq!((e.achats.len(), total(&e)), (1, 400));
        assert_eq!(total(&e), perte_nette(&e, &apres));

        // (c) Paiement de 300 et, au même moment, dépôt de 5 par un tiers : l'achat affiché vaut
        // 295 (la perte NETTE, exacte) et peut porter l'identifiant du dépôt au lieu du paiement.
        let mut e = neuf();
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10);
        let apres = [p(1, 0, 1_000), p(2, 1, 700), p(9, 0, 5)];
        suivre(&mut e, &apres, 20);
        assert_eq!((e.achats.len(), total(&e)), (1, 295));
        assert_eq!(total(&e), perte_nette(&e, &apres));
        assert_eq!(e.achats[0].txid, TransactionId::from_bytes([9; 32]).to_string(), "identifiant brouillé (limite connue)");

        // (d) Paiement de 300 masqué par un dépôt simultané de 300 ou plus : aucun achat affiché,
        // mais la perte nette du propriétaire est bien nulle (le tiers a payé à sa place).
        let mut e = neuf();
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10);
        let apres = [p(1, 0, 1_000), p(2, 1, 700), p(9, 0, 300)];
        suivre(&mut e, &apres, 20);
        assert!(e.achats.is_empty());
        assert_eq!(perte_nette(&e, &apres), 0);

        // (e) Dans tous les cas, ce qui compte pour la sécurité ne dépend pas de `suivre` : la
        // perte nette affichée (apports − solde) et l'exposition viennent des pièces lues sur le nœud.
    }

    /// R62 (corrigée) : « Ajouter des fonds » créait une pièce de plus, et chaque pièce a son propre
    /// rythme : après n rechargements, un agent compromis pouvait sortir (k + n)·(C + C·P/R) par
    /// période, plus que le budget affiché dans les règles du mandat. Désormais le rechargement
    /// regonfle la pièce la plus jeune : le nombre de pièces, donc le maximum par période, ne change
    /// pas. Voir spec/red-team/rapport-2026-11-26.md.
    #[test]
    fn r62_budget_par_periode_tenu_apres_rechargement() {
        // 4 TKAS par heure, 0,5 au plus par achat : 4 pièces de 1 TKAS.
        let r = crate::Regles::calculer(400_000_000, 36_000, 50_000_000).unwrap();
        let c = coeur(r.capacite, r.recharge_daa);
        let op = |i: u32| TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), i);
        let now = 10 * r.periode_daa as u64;
        // Pièces d'âges différents ; la 2 a payé récemment (continuation jeune).
        let mut pieces: Vec<Piece> =
            decouper(r.depot, r.pieces).iter().enumerate().map(|(i, v)| Piece { outpoint: op(i as u32), valeur: *v, creation: Some(0) }).collect();
        pieces[2] = Piece { outpoint: op(9), valeur: 60_000_000, creation: Some(now - 100) };
        let vue = |pieces: Vec<Piece>| Vue { coeur: c.clone(), adresse: String::new(), pieces, now, etat: None };
        assert!(vue(pieces.clone()).fenetre(r.periode_daa as u64) <= r.budget as u64, "avant rechargement : le budget tient");

        // Le propriétaire ajoute 4 TKAS : la pièce la plus jeune est regonflée, pas de cinquième pièce.
        let choix = choisir_recharge(&c, &pieces, r.pieces as usize, now);
        assert_eq!(choix, Recharge::Regonfler(op(9), 60_000_000), "la plus jeune est regonflée");
        let Recharge::Regonfler(o, v) = choix else { unreachable!() };
        let mut apres: Vec<Piece> = pieces.iter().filter(|p| p.outpoint != o).cloned().collect();
        apres.push(Piece { outpoint: op(20), valeur: v + 400_000_000, creation: Some(now) });
        assert_eq!(apres.len(), r.pieces as usize);
        // Le maximum sur une période, mesuré à toute date après le rechargement, reste sous le budget.
        for d in [0, 1, 10_000, r.periode_daa as u64, 5 * r.periode_daa as u64] {
            let v = Vue { coeur: c.clone(), adresse: String::new(), pieces: apres.clone(), now: now + d, etat: None };
            let pire = v.fenetre(r.periode_daa as u64);
            assert!(pire <= r.budget as u64, "{d} après : {pire} sompi possibles sur une période, budget {}", r.budget);
        }
        // Recharger encore et encore ne change rien au nombre de pièces.
        let mut ps = apres;
        for n in 0..5u32 {
            let Recharge::Regonfler(o, v) = choisir_recharge(&c, &ps, r.pieces as usize, now + 1 + n as u64) else { panic!("regonfler attendu") };
            ps.retain(|p| p.outpoint != o);
            ps.push(Piece { outpoint: op(30 + n), valeur: v + 100_000_000, creation: Some(now + 1 + n as u64) });
            assert_eq!(ps.len(), r.pieces as usize);
        }
    }

    /// Coffre vidé par les achats (pièces sous le plancher) : le rechargement recrée une pièce,
    /// jusqu'au nombre d'origine seulement. Pièce en attente de confirmation : on attend.
    #[test]
    fn r62_recharge_recree_seulement_les_pieces_manquantes() {
        let c = coeur(50_000_000, 36_000);
        let op = |i: u32| TransactionOutpoint::new(TransactionId::from_bytes([2; 32]), i);
        let p = |i: u32, v: u64, cr: Option<u64>| Piece { outpoint: op(i), valeur: v, creation: cr };
        let poussiere = p(0, 5_000, Some(1));
        assert_eq!(choisir_recharge(&c, &[poussiere.clone()], 4, 100), Recharge::Nouvelle);
        assert_eq!(choisir_recharge(&c, &[], 1, 100), Recharge::Nouvelle);
        let pleines: Vec<Piece> = (1..=4).map(|i| p(i, 100_000_000, Some(i as u64))).collect();
        assert!(matches!(choisir_recharge(&c, &pleines, 4, 100), Recharge::Regonfler(..)));
        let en_vol: Vec<Piece> = (1..=4).map(|i| p(i, 100_000_000, None)).collect();
        assert_eq!(choisir_recharge(&c, &en_vol, 4, 100), Recharge::Attendre);
        // Un tiers qui dépose une grosse pièce n'ouvre pas de place pour une pièce de plus.
        let mut avec_tiers = pleines.clone();
        avec_tiers.push(p(9, 900_000_000, Some(50)));
        assert!(matches!(choisir_recharge(&c, &avec_tiers, 4, 100), Recharge::Regonfler(..)));
    }

    /// La transaction de regonflement est acceptée par le vrai moteur de script (entrée 0 :
    /// `ownerControl`), reste sous la masse standard, et ne crée qu'une pièce du coffre.
    #[test]
    fn r62_regonflement_accepte_par_le_script_et_diffusable() {
        use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
        use kaspa_consensus_core::tx::{PopulatedTransaction, VerifiableTransaction};
        use kaspa_txscript::caches::Cache;
        use kaspa_txscript::covenants::CovenantsContext;
        use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let c = coeur(50_000_000, 36_000);
        let art = c.artifact().unwrap();
        let owner = k(1);
        let piece = (TransactionOutpoint::new(TransactionId::from_bytes([4; 32]), 1), 60_000_000u64);
        let e_p = UtxoEntry::new(1_000_000_000, pay_to_address_script(&address(&owner)), 1, false, None);
        let i_p = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(TransactionId::from_bytes([5; 32]), 0), vec![], 0, CB_P2PK);
        let montant = 400_000_000;
        let (tx, entries) = tx_regonfler(&art, piece, (vec![e_p], vec![i_p], 1_000_000_000), montant, &owner).unwrap();
        assert_eq!(tx.outputs.iter().filter(|o| o.script_public_key == vault_spk(&art)).count(), 1, "une seule pièce du coffre");
        assert_eq!(tx.outputs[0].value, piece.1 + montant);
        assert!(masse::masses(&tx, &entries).unwrap().standard());
        let verifier = |tx: &Transaction| -> bool {
            let populated = PopulatedTransaction::new(tx, entries.clone());
            let cov = CovenantsContext::from_tx(&populated).unwrap();
            let cache = Cache::new(10);
            let reused = SigHashReusedValuesUnsync::new();
            (0..tx.inputs.len()).all(|i| {
                let input = populated.inputs()[i].clone();
                let mut vm = TxScriptEngine::from_transaction_input(
                    &populated,
                    &input,
                    i,
                    populated.utxo(i).unwrap(),
                    EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov),
                    EngineFlags::default(),
                );
                vm.execute().is_ok()
            })
        };
        assert!(verifier(&tx), "regonflement refusé par le script");
        // Signée par l'agent au lieu du propriétaire : refusée.
        let (faux, _) = tx_regonfler(&art, piece, (entries[1..].to_vec(), tx.inputs[1..].iter().map(|i| TransactionInput::new_with_compute_budget(i.previous_outpoint, vec![], 0, CB_P2PK)).collect(), 1_000_000_000), montant, &k(2)).unwrap();
        assert!(!verifier(&faux), "seul le propriétaire peut regonfler");
    }

    /// `suivre` : un regonflement n'est pas un achat (la pièce regonflée disparaît, sa valeur
    /// revient dans la pièce de l'apport).
    #[test]
    fn r62_regonflement_n_est_pas_un_achat() {
        let op = |t: u8, i: u32| TransactionOutpoint::new(TransactionId::from_bytes([t; 32]), i);
        let depot = TransactionId::from_bytes([1; 32]).to_string();
        let mut e = EtatCoeur { version: VERSION.into(), retour: None, capacite: 1, periode: 1, agent: String::new(), cree_daa: 0,
            apports: vec![Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }, Apport { txid: depot.clone(), sompi: 1_000, daa: 0 }], vues: vec![], achats: vec![] };
        assert_eq!(pieces_du_mandat(&e), 2);
        let p = |t: u8, i: u32, v: u64| Piece { outpoint: op(t, i), valeur: v, creation: Some(1) };
        suivre(&mut e, &[p(1, 0, 1_000), p(1, 1, 1_000)], 10);
        // Regonflement de 1:1 avec 500 : nouvelle pièce 3:0 de 1 500.
        e.apports.push(Apport { txid: TransactionId::from_bytes([3; 32]).to_string(), sompi: 500, daa: 20 });
        assert_eq!(pieces_du_mandat(&e), 2, "un apport ne change pas le nombre de pièces du mandat");
        suivre(&mut e, &[p(1, 0, 1_000), p(3, 0, 1_500)], 20);
        assert!(e.achats.is_empty(), "un regonflement n'est pas un achat : {:?}", e.achats);
        // Un vrai achat juste après est toujours reconnu.
        suivre(&mut e, &[p(1, 0, 1_000), p(4, 1, 1_200)], 30);
        assert_eq!(e.achats.iter().map(|a| a.sompi).sum::<u64>(), 300);
        // Regonflement et achat entre deux lectures : seul l'achat compte.
        e.apports.push(Apport { txid: TransactionId::from_bytes([5; 32]).to_string(), sompi: 200, daa: 40 });
        suivre(&mut e, &[p(6, 1, 900), p(5, 0, 1_400)], 40);
        assert_eq!(e.achats.iter().map(|a| a.sompi).sum::<u64>(), 400, "achat de 100 sur 1:0, regonflement ignoré");
    }

    /// La courbe promise (somme des apports) reste une borne de la perte possible après un
    /// regonflement : la pièce regonflée garde sa courbe, l'apport commence la sienne à sa date.
    #[test]
    fn r62_courbe_promise_tenue_apres_regonflement() {
        let c = coeur(50_000_000, 36_000);
        let op = |t: u8| TransactionOutpoint::new(TransactionId::from_bytes([t; 32]), 0);
        let etat = |apports: Vec<Apport>| EtatCoeur { version: VERSION.into(), retour: None, capacite: c.capacite, periode: c.periode, agent: String::new(), cree_daa: 0, apports, vues: vec![], achats: vec![] };
        let v0 = 200_000_000u64;
        let mut apports = vec![Apport { txid: String::new(), sompi: v0, daa: 0 }];
        // L'agent dépense au maximum jusqu'à t_r, puis la pièce est regonflée de m.
        let t_r = 100_000u64;
        let perdu_avant = c.fenetre(v0, 0, t_r);
        let m = 300_000_000u64;
        apports.push(Apport { txid: String::new(), sompi: m, daa: t_r });
        let v = Vue { coeur: c.clone(), adresse: String::new(), pieces: vec![Piece { outpoint: op(1), valeur: v0 - perdu_avant + m, creation: Some(t_r) }], now: t_r, etat: Some(etat(apports)) };
        for d in [0u64, 1, 1_000, 36_000, 500_000, 10_000_000] {
            let possible = perdu_avant + c.fenetre(v0 - perdu_avant + m, 0, d);
            assert!(v.courbe(t_r + d) >= possible, "courbe {} < perte possible {possible} à {d}", v.courbe(t_r + d));
        }
    }

    /// Adresse de retour saisie : une adresse du réseau de test valide ; sinon refus clair.
    #[test]
    fn retour_adresse_saisie_validee() {
        let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap();
        let bonne = address(&k(11)).to_string();
        assert_eq!(valider_retour(&format!("  {bonne} ")).unwrap().to_string(), bonne, "espaces tolérés");
        assert!(valider_retour("kaspatest:pas-une-adresse").is_err());
        assert!(valider_retour("").is_err());
        let principale = Address::new(Prefix::Mainnet, Version::PubKey, &xonly(&k(11))).to_string();
        assert!(valider_retour(&principale).is_err(), "adresse du réseau principal refusée sur le testnet");
        // Par défaut (rien d'enregistré) : l'adresse du propriétaire.
        assert_eq!(adresse_retour(None, &xonly(&k(1))).unwrap(), address(&k(1)));
    }

    /// Plusieurs pièces : k achats d'affilée, et la courbe promise est celle du budget total.
    #[test]
    fn plusieurs_pieces_rafale_et_budget_tenus() {
        let r = crate::Regles::calculer(4_000_000_000, crate::JOUR_DAA, 200_000_000).unwrap(); // 40/jour, 2 par achat
        assert_eq!(r.pieces, crate::PIECES_MAX);
        assert!(r.maximum_sur(r.periode_daa) <= r.budget, "jamais plus que le budget sur la période");
        let c = coeur(r.capacite, r.recharge_daa);
        let op = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
        let parts = decouper(r.depot, r.pieces);
        assert_eq!(parts.iter().sum::<u64>(), r.depot);
        let pieces: Vec<Piece> = parts.iter().map(|v| Piece { outpoint: op, valeur: *v, creation: Some(0) }).collect();
        let etat = EtatCoeur { version: VERSION.into(), retour: None, capacite: c.capacite, periode: c.periode, agent: String::new(), cree_daa: 0,
            apports: parts.iter().map(|v| Apport { txid: String::new(), sompi: *v, daa: 0 }).collect(), vues: vec![], achats: vec![] };
        let v = Vue { coeur: c, adresse: String::new(), pieces, now: r.recharge_daa as u64, etat: Some(etat) };
        // Au bout d'une période de recharge, k achats au plafond sont possibles d'affilée.
        assert_eq!(v.immediate(), r.pieces as u64 * r.capacite as u64);
        // La courbe promise sur la période ne dépasse pas le budget.
        assert!(v.courbe(r.periode_daa as u64) <= r.budget as u64);
    }

    #[test]
    fn vue_courbe_et_risque() {
        let c = coeur(50_000_000, 288_000);
        let op = TransactionOutpoint::new(TransactionId::from_bytes([1; 32]), 0);
        let etat = EtatCoeur { version: VERSION.into(), retour: None, capacite: c.capacite, periode: c.periode, agent: String::new(), cree_daa: 0,
            apports: vec![Apport { txid: String::new(), sompi: 2_000_000_000, daa: 0 }], vues: vec![], achats: vec![] };
        let v = Vue { coeur: c, adresse: String::new(), pieces: vec![Piece { outpoint: op, valeur: 2_000_000_000, creation: Some(0) }], now: 0, etat: Some(etat) };
        assert_eq!(v.immediate(), 0, "un mandat neuf démarre à zéro");
        assert_eq!(v.courbe(0), 0);
        assert_eq!(v.courbe(288_000), 50_000_000, "une capacité au bout d'une période");
        assert_eq!(v.courbe(crate::JOUR_DAA as u64), 150_000_000);
        assert_eq!(v.courbe(u64::MAX / 2), 2_000_000_000, "jamais plus que le capital");
        assert_eq!(v.fenetre(crate::JOUR_DAA as u64), 150_000_000);
    }
}

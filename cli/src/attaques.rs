//! Attaques volontaires d'un agent compromis contre son propre coffre (testnet uniquement).
//!
//! Chaque attaque fabrique une transaction correctement signée par la clé de l'agent, mais qui
//! viole une règle du contrat, et la DIFFUSE sans contrôle local : c'est le réseau Kaspa (le
//! covenant) qui doit la rejeter. Le message de refus du nœud est affiché pour être archivé.

use crate::*;

#[derive(Clone, Copy, Debug)]
pub enum Triche {
    /// Paiement honnête (témoin).
    Aucune,
    /// État suivant avec des jetons gonflés.
    GonflerJetons,
    /// Continuation avec des règles plus lâches (plafond par paiement = capacité).
    ReglesLaches,
    /// Le reste du coffre part vers l'adresse de l'attaquant au lieu de la continuation.
    DetournerLeReste,
    /// Frais au-dessus de `maxFee` (vider le coffre par les frais).
    FraisExcessifs,
    /// Paiement de poussière (sortie minuscule, masse de stockage KIP-9).
    Poussiere,
}

/// Paiement de l'agent avec une triche ; `now` peut être antidaté.
pub fn tx_agent(owner_pk: &[u8], agent: &Keypair, attaquant: &ScriptPublicKey, e: &Etat, amount: i64, payee: ScriptPublicKey, now: i64, creation: i64, triche: Triche) -> Res<(Transaction, Etat)> {
    let p = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa);
    let available = p.available(now, creation);
    let vault = compile_params(&p)?;
    let cov = e.covenant()?;
    let frais: u64 = if matches!(triche, Triche::FraisExcessifs) { 40_000_000 } else { FEE };
    let mut next_tokens = available - amount - frais as i64;
    if matches!(triche, Triche::GonflerJetons) {
        next_tokens = CAPACITY;
    }
    let next = if matches!(triche, Triche::ReglesLaches) {
        let mut q = VaultParams::pour(owner_pk, agent, next_tokens, now);
        q.max_per_payment = q.capacity;
        compile_unchecked(&q)?
    } else {
        // un attaquant encode l'état qu'il veut, même impossible (jetons négatifs) : pas de contrôle
        compile_unchecked(&VaultParams::pour(owner_pk, agent, next_tokens, now))?
    };
    let entry = UtxoEntry::new(e.valeur, vault_spk(&vault), creation as u64, false, Some(cov));
    let txid_in = TransactionId::from_bytes(<[u8; 32]>::try_from(hex::decode(&e.txid)?.as_slice())?);
    let input = TransactionInput::new_with_compute_budget(TransactionOutpoint::new(txid_in, e.index), vec![], 0, CB_VAULT);
    let rest = e.valeur - amount as u64 - frais;
    let continuation = if matches!(triche, Triche::DetournerLeReste) {
        TransactionOutput::new(rest, attaquant.clone())
    } else {
        TransactionOutput { value: rest, script_public_key: vault_spk(&next), covenant: Some(CovenantBinding { authorizing_input: 0, covenant_id: cov }) }
    };
    let outputs = vec![TransactionOutput::new(amount as u64, payee), continuation];
    let mut tx = Transaction::new(1, vec![input], outputs, now as u64, Default::default(), 0, vec![]);
    let s = sign(&tx, &[entry], 0, agent);
    tx.inputs[0].signature_script = vault_sigscript(&vault, "pay", &[s.into(), amount.into(), now.into()])?;
    tx.finalize();
    let suivant = Etat { txid: tx.id().to_string(), index: 1, valeur: rest, tokens: next_tokens, last_daa: now, cov_id: e.cov_id.clone() };
    Ok((tx, suivant))
}

/// Diffuse sans aucun contrôle local et rapporte la réponse exacte du nœud.
pub async fn diffuser(c: &KaspaRpcClient, tx: &Transaction) -> Result<String, String> {
    let rpc: kaspa_rpc_core::RpcTransaction = tx.into();
    c.submit_transaction(rpc, false).await.map(|id| id.to_string()).map_err(|e| e.to_string())
}

fn rapport(nom: &str, attendu_refus: bool, r: &Result<String, String>) -> bool {
    match (r, attendu_refus) {
        (Err(e), true) => { println!("[ATTAQUE] {nom} : REJETÉE par le réseau, comme attendu\n          message du nœud : {e}"); true }
        (Ok(id), false) => { println!("[TÉMOIN] {nom} : acceptée : {}", explorer(id)); true }
        (Ok(id), true) => { println!("[ALERTE] {nom} : ACCEPTÉE alors qu'elle devait être rejetée : {}", explorer(id)); false }
        (Err(e), false) => { println!("[TÉMOIN] {nom} : refusée ({e})"); false }
    }
}

/// Lance la batterie. `temps` : attaque du « temps mis de côté » (le coffre doit avoir été laissé
/// inactif quelques minutes depuis sa création).
pub async fn batterie(owner_pk: &[u8], agent: &Keypair, attaquant: &Keypair, quoi: &str) -> Res<bool> {
    let c = connect().await?;
    let attaquant_spk = pay_to_address_script(&address(attaquant));
    // destinataire : l'adresse du propriétaire (les fonds de test restent chez lui)
    let payee = pay_to_address_script(&Address::new(Prefix::Testnet, Version::PubKey, owner_pk));
    let mut ok = true;
    let mut e = load_state()?;
    if quoi == "regles" || quoi == "tout" {
        for (nom, t) in [
            ("jetons gonflés dans l'état suivant", Triche::GonflerJetons),
            ("règles plus lâches dans la continuation", Triche::ReglesLaches),
            ("reste du coffre détourné vers l'attaquant", Triche::DetournerLeReste),
            ("frais excessifs (vidage par les frais)", Triche::FraisExcessifs),
        ] {
            let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
            let (tx, _) = tx_agent(owner_pk, agent, &attaquant_spk, &e, 10_000_000, payee.clone(), now, creation, t)?;
            ok &= rapport(nom, true, &diffuser(&c, &tx).await);
        }
        let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
        let (tx, _) = tx_agent(owner_pk, agent, &attaquant_spk, &e, 1_000, payee.clone(), now, creation, Triche::Poussiere)?;
        ok &= rapport("paiement de poussière (1 000 sompi, KIP-9)", true, &diffuser(&c, &tx).await);
    }
    if quoi == "temps" || quoi == "tout" {
        // 1. Vider la réserve en ANTIDATANT chaque paiement au dernier instant (aucune recharge
        //    réclamée), comme dans l'attaque de la v0.4.
        let mut vides = 0;
        loop {
            let (_, creation) = instants(&c, owner_pk, agent, &e).await?;
            let now = e.last_daa;
            let dispo = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa).available(now, creation) - FEE as i64;
            let amount = dispo.min(MAX_PER_PAYMENT);
            if amount < 2_000_000 { break; }
            let (tx, suivant) = tx_agent(owner_pk, agent, &attaquant_spk, &e, amount, payee.clone(), now, creation, Triche::Aucune)?;
            if !rapport(&format!("vidage antidaté n°{} ({} TKAS)", vides + 1, amount as f64 / 1e8), false, &diffuser(&c, &tx).await) { ok = false; break; }
            save_state(&suivant)?;
            e = suivant;
            vides += 1;
            // attendre l'inscription de la continuation
            for _ in 0..30 {
                if creation_coffre(&c, owner_pk, agent, &e).await.is_ok() { break; }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        // 2. Réclamer d'un coup le temps écoulé depuis lastDaa (antidaté), qui en v0.4 aurait
        //    rendu de la recharge ; en v0.5 seule compte l'inscription réelle (quelques secondes).
        let (now, creation) = instants(&c, owner_pk, agent, &e).await?;
        let v04 = ((now - e.last_daa).clamp(0, REFILL) * CAPACITY / REFILL + e.tokens).min(CAPACITY);
        let v05 = VaultParams::pour(owner_pk, agent, e.tokens, e.last_daa).available(now, creation);
        let amount = (v04 - FEE as i64).min(MAX_PER_PAYMENT);
        println!("[ATTAQUE] temps mis de côté : en v0.4 l'agent aurait disposé de {} TKAS ; en v0.5 de {} TKAS ; il tente {} TKAS",
            v04 as f64 / 1e8, v05 as f64 / 1e8, amount as f64 / 1e8);
        if amount + (FEE as i64) <= v05 || amount < 2_000_000 {
            println!("[ATTAQUE] temps mis de côté : pas assez de temps écoulé depuis la création pour une démonstration probante (laisser le coffre inactif quelques minutes)");
        } else {
            let (tx, _) = tx_agent(owner_pk, agent, &attaquant_spk, &e, amount, payee.clone(), now, creation, Triche::Aucune)?;
            ok &= rapport("réclamation du temps mis de côté", true, &diffuser(&c, &tx).await);
        }
    }
    c.disconnect().await?;
    Ok(ok)
}


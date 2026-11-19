//! Relais vers le standard Kaspa x402 « exact » (binding `kaspa-exact-v2`, profil `standard-native`).
//!
//! Pourquoi un relais : le profil `exact` de kaspa-x402 n'accepte que des entrées P2PK standard et
//! exclut les covenants. Le coffre AgentBudget ne peut donc pas payer directement un vendeur
//! kaspa-x402. Le relais résout cela sans toucher au standard :
//!
//! ```text
//! coffre AgentBudget ──(paiement du coffre, règles du covenant)──▶ porte-monnaie de l'agent (P2PK)
//! porte-monnaie de l'agent ──(paiement exact standard-native)──▶ vendeur kaspa-x402
//! ```
//!
//! Le porte-monnaie ne reçoit que des fonds sortis du coffre, et jamais plus qu'un plafond
//! (`PLAFOND_PORTE_MONNAIE`, par défaut un paiement maximal du coffre). La dépense totale de l'agent
//! reste donc bornée par le budget du coffre. Ce que le relais perd : la liste blanche des
//! destinataires n'est plus imposée par le réseau sur le paiement final (voir `spec/research/relais-exact.md`).
//!
//! Tout ce module est vérifié octet pour octet contre les vecteurs officiels de kaspa-x402
//! (`cli/vecteurs/kaspa-x402/`).

use kaspa_addresses::Address;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use secp256k1::{Keypair, Message};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::Res;

pub const BINDING: &str = "kaspa-exact-v2";
pub const PROFILE: &str = "standard-native";
pub const ENCODING: &str = "kaspa-sdk-safe-json-v2.0.0";
pub const AUTH_VERSION: &str = "kaspa-x402-exact-request-authorization-v2";
pub const NETWORK: &str = "kaspa:testnet-10";

/// Frais par entrée d'un paiement exact (valeur des vecteurs officiels : 0,003 KAS).
pub const FRAIS_PAR_ENTREE: u64 = 300_000;

/// Politique de financement de l'agent (exigée par la spec avant toute signature non surveillée).
#[derive(Clone, Debug)]
pub struct Politique {
    /// Montant maximal accepté pour une offre (sompi).
    pub montant_max: u64,
    /// Destinataires autorisés (`payTo`). Vide = tout destinataire.
    pub destinataires: Vec<String>,
    /// Origines HTTP autorisées (`https://api.exemple.org`). Vide = toute origine.
    pub origines: Vec<String>,
}

// ---------------------------------------------------------------------------
// JSON canonique et empreintes (spec : « recursive canonical JSON serialization »)
// ---------------------------------------------------------------------------

/// Sérialisation canonique : clés triées (ordre UTF-16, identique à l'ASCII ici), aucun espace.
/// Équivalent de `stableStringify` de la bibliothèque de référence.
pub fn canonique(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut cles: Vec<&String> = m.keys().collect();
            cles.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let corps: Vec<String> = cles.iter().map(|k| format!("{}:{}", Value::String((*k).clone()), canonique(&m[*k]))).collect();
            format!("{{{}}}", corps.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonique).collect::<Vec<_>>().join(",")),
        autre => autre.to_string(),
    }
}

pub fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `paymentRequirementsHash` : SHA-256 du JSON canonique de l'offre choisie.
pub fn hash_offre(accepted: &Value) -> String {
    sha256_hex(&canonique(accepted))
}

/// Empreinte HTTP de la requête, calculée comme le client de référence
/// (`fingerprintHttpRequest`) : méthode, URL, corps, hash de l'offre.
pub fn hash_requete(methode: &str, url: &str, corps: Option<&Value>, accepted: &Value) -> String {
    sha256_hex(&canonique(&json!({
        "method": methode,
        "url": url,
        "body": corps.cloned().unwrap_or(Value::Null),
        "paymentRequirementsHash": hash_offre(accepted),
    })))
}

// ---------------------------------------------------------------------------
// Scripts et transactions au format « safe JSON v2 »
// ---------------------------------------------------------------------------

/// Script public sérialisé : version sur 2 octets (gros-boutiste) puis le script.
pub fn spk_hex(spk: &ScriptPublicKey) -> String {
    let mut b = spk.version().to_be_bytes().to_vec();
    b.extend_from_slice(spk.script());
    hex::encode(b)
}

pub fn spk_depuis_hex(h: &str) -> Res<ScriptPublicKey> {
    let b = hex::decode(h)?;
    if b.len() < 2 {
        return Err("script public trop court".into());
    }
    Ok(ScriptPublicKey::from_vec(u16::from_be_bytes([b[0], b[1]]), b[2..].to_vec()))
}

fn champ<'a>(v: &'a Value, k: &str) -> Res<&'a Value> {
    v.get(k).ok_or_else(|| format!("champ « {k} » absent").into())
}
fn texte<'a>(v: &'a Value, k: &str) -> Res<&'a str> {
    champ(v, k)?.as_str().ok_or_else(|| format!("champ « {k} » : texte attendu").into())
}
fn u64_texte(v: &Value, k: &str) -> Res<u64> {
    let s = texte(v, k)?;
    // uint64 canonique : chiffres décimaux, sans zéro de tête (sauf « 0 »).
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err(format!("champ « {k} » : entier décimal canonique attendu").into());
    }
    Ok(s.parse()?)
}
fn entier(v: &Value, k: &str) -> Res<u64> {
    champ(v, k)?.as_u64().ok_or_else(|| format!("champ « {k} » : entier attendu").into())
}

/// Transaction version 0 + UTXO dépensés → projection `kaspa-sdk-safe-json-v2.0.0`.
pub fn vers_safe_json(tx: &Transaction, utxos: &[UtxoEntry]) -> Value {
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .zip(utxos)
        .map(|(i, u)| {
            json!({
                "previousOutpoint": { "transactionId": i.previous_outpoint.transaction_id.to_string(), "index": i.previous_outpoint.index },
                "sequence": i.sequence.to_string(),
                "sigOpCount": i.compute_commit.sig_op_count().unwrap_or(0),
                "signatureScript": hex::encode(&i.signature_script),
                "utxo": { "amount": u.amount.to_string(), "scriptPublicKey": spk_hex(&u.script_public_key) },
            })
        })
        .collect();
    let outputs: Vec<Value> = tx
        .outputs
        .iter()
        .map(|o| json!({ "value": o.value.to_string(), "scriptPublicKey": spk_hex(&o.script_public_key), "covenant": null }))
        .collect();
    json!({
        "id": tx.id().to_string(),
        "version": tx.version,
        "inputs": inputs,
        "outputs": outputs,
        "lockTime": tx.lock_time.to_string(),
        "subnetworkId": tx.subnetwork_id.to_string(),
        "gas": tx.gas.to_string(),
        "payload": hex::encode(&tx.payload),
        "storageMass": tx.storage_mass().to_string(),
    })
}

/// Lecture inverse (version 0 seulement). L'identifiant est recalculé, jamais repris du JSON.
pub fn depuis_safe_json(v: &Value) -> Res<(Transaction, Vec<UtxoEntry>)> {
    if entier(v, "version")? != 0 {
        return Err("seule la version 0 (standard-native) est prise en charge".into());
    }
    let mut inputs = vec![];
    let mut utxos = vec![];
    for i in champ(v, "inputs")?.as_array().ok_or("inputs : tableau attendu")? {
        let op = champ(i, "previousOutpoint")?;
        let txid: TransactionId = texte(op, "transactionId")?.parse()?;
        let index = u32::try_from(entier(op, "index")?)?;
        let sig = hex::decode(texte(i, "signatureScript")?)?;
        let sigops = u8::try_from(entier(i, "sigOpCount")?)?;
        inputs.push(TransactionInput::new(TransactionOutpoint::new(txid, index), sig, u64_texte(i, "sequence")?, sigops));
        let u = champ(i, "utxo")?;
        utxos.push(UtxoEntry::new(u64_texte(u, "amount")?, spk_depuis_hex(texte(u, "scriptPublicKey")?)?, 0, false, None));
    }
    let mut outputs = vec![];
    for o in champ(v, "outputs")?.as_array().ok_or("outputs : tableau attendu")? {
        if !champ(o, "covenant")?.is_null() {
            return Err("sortie avec covenant interdite dans ce profil".into());
        }
        outputs.push(TransactionOutput::new(u64_texte(o, "value")?, spk_depuis_hex(texte(o, "scriptPublicKey")?)?));
    }
    if texte(v, "subnetworkId")? != SUBNETWORK_ID_NATIVE.to_string() {
        return Err("sous-réseau natif attendu".into());
    }
    let tx = Transaction::new_with_mass(
        0,
        inputs,
        outputs,
        u64_texte(v, "lockTime")?,
        SUBNETWORK_ID_NATIVE,
        u64_texte(v, "gas")?,
        hex::decode(texte(v, "payload")?)?,
        u64_texte(v, "storageMass")?,
    );
    if let Some(id) = v.get("id").and_then(Value::as_str) {
        if id != tx.id().to_string() {
            return Err("identifiant de transaction incohérent".into());
        }
    }
    Ok((tx, utxos))
}

// ---------------------------------------------------------------------------
// Contrôle de l'offre (avant toute signature)
// ---------------------------------------------------------------------------

/// Vérifie qu'une offre `exact` est bien du profil `standard-native` sur testnet-10 et qu'elle
/// respecte la politique de l'agent. Renvoie (montant, script du vendeur).
pub fn controler_offre(accepted: &Value, url: &str, pol: &Politique) -> Res<(u64, ScriptPublicKey)> {
    let extra = champ(accepted, "extra")?;
    let attendu = [
        (texte(accepted, "scheme")?, "exact", "scheme"),
        (texte(accepted, "network")?, NETWORK, "network"),
        (texte(accepted, "asset")?, "KAS", "asset"),
        (texte(extra, "binding")?, BINDING, "extra.binding"),
        (texte(extra, "profile")?, PROFILE, "extra.profile"),
        (texte(extra, "paymentFlow")?, "upfront", "extra.paymentFlow"),
        (texte(extra, "transactionEncoding")?, ENCODING, "extra.transactionEncoding"),
    ];
    for (reel, voulu, nom) in attendu {
        if reel != voulu {
            return Err(format!("offre refusée : {nom} = « {reel} », attendu « {voulu} »").into());
        }
    }
    let finalite = texte(extra, "finality")?;
    if finalite != "accepted" && finalite != "confirmed" {
        return Err(format!("offre refusée : finalité « {finalite} » insuffisante").into());
    }
    for interdit in ["challengeId", "headId", "expectedHeadOutpoint", "headRedeemScript"] {
        if extra.get(interdit).is_some() {
            return Err(format!("offre refusée : champ additif « {interdit} » dans une offre standard-native").into());
        }
    }
    let montant = u64_texte(accepted, "amount")?;
    if montant == 0 || montant > pol.montant_max {
        return Err(format!("offre refusée : {montant} sompi hors politique (max {})", pol.montant_max).into());
    }
    if entier(accepted, "maxTimeoutSeconds")? == 0 {
        return Err("offre refusée : maxTimeoutSeconds nul".into());
    }
    let pay_to = texte(accepted, "payTo")?;
    if !pol.destinataires.is_empty() && !pol.destinataires.iter().any(|d| d == pay_to) {
        return Err(format!("offre refusée : destinataire {pay_to} hors liste").into());
    }
    let adresse = Address::try_from(pay_to).map_err(|e| format!("payTo invalide : {e}"))?;
    if adresse.prefix != kaspa_addresses::Prefix::Testnet {
        return Err("offre refusée : adresse hors testnet".into());
    }
    let spk = pay_to_address_script(&adresse);
    if texte(extra, "payToScriptPublicKey")? != spk_hex(&spk) {
        return Err("offre refusée : payToScriptPublicKey ne correspond pas à payTo".into());
    }
    if !pol.origines.is_empty() {
        let origine = origine_de(url).ok_or("URL sans origine")?;
        if !pol.origines.iter().any(|o| *o == origine) {
            return Err(format!("offre refusée : origine {origine} hors liste").into());
        }
    }
    Ok((montant, spk))
}

/// `https://hote:port/chemin` → `https://hote:port`.
pub fn origine_de(url: &str) -> Option<String> {
    let (schema, reste) = url.split_once("://")?;
    let hote = reste.split(['/', '?', '#']).next()?;
    (!hote.is_empty()).then(|| format!("{}://{}", schema.to_ascii_lowercase(), hote.to_ascii_lowercase()))
}

// ---------------------------------------------------------------------------
// Autorisation de la requête et charge utile de paiement
// ---------------------------------------------------------------------------

/// Horodatage ISO-8601 en UTC avec millisecondes (`2099-01-01T00:00:00.000Z`).
pub fn iso8601(ms: u64) -> String {
    let (secs, milli) = (ms / 1000, ms % 1000);
    let (jours, s) = ((secs / 86_400) as i64, secs % 86_400);
    // Conversion jours → date civile (algorithme de H. Hinnant).
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let doe = z - ere * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let jour = doy - (153 * mp + 2) / 5 + 1;
    let mois = if mp < 10 { mp + 3 } else { mp - 9 };
    let annee = yoe + ere * 400 + i64::from(mois <= 2);
    format!("{annee:04}-{mois:02}-{jour:02}T{:02}:{:02}:{:02}.{milli:03}Z", s / 3600, s % 3600 / 60, s % 60)
}

pub struct Autorisation {
    pub digest: String,
    pub objet: Value,
}

/// Objet et empreinte de l'autorisation (`kaspa-x402-exact-request-authorization-v2`), depuis l'offre.
#[allow(clippy::too_many_arguments)]
pub fn autorisation(
    network: &str,
    profile: &str,
    txid: &str,
    index_sortie: u64,
    accepted: &Value,
    hash_req: &str,
    id_paiement: &str,
    challenge: Option<&str>,
    index_entree: u64,
    expiration: &str,
) -> Res<Autorisation> {
    let termes = Termes {
        montant: texte(accepted, "amount")?.into(),
        pay_to: texte(accepted, "payTo")?.into(),
        spk_vendeur: texte(champ(accepted, "extra")?, "payToScriptPublicKey")?.into(),
        hash_offre: hash_offre(accepted),
        hash_requete: hash_req.into(),
        id_paiement: id_paiement.into(),
        expiration: expiration.into(),
    };
    Ok(autorisation_termes(network, profile, txid, index_sortie, &termes, challenge, index_entree))
}

/// Termes d'un paiement exact, tels que les fixe le client avant la signature.
pub struct Termes {
    pub montant: String,
    pub pay_to: String,
    pub spk_vendeur: String,
    pub hash_offre: String,
    pub hash_requete: String,
    pub id_paiement: String,
    pub expiration: String,
}

pub fn autorisation_termes(
    network: &str,
    profile: &str,
    txid: &str,
    index_sortie: u64,
    t: &Termes,
    challenge: Option<&str>,
    index_entree: u64,
) -> Autorisation {
    let objet = json!({
        "scope": AUTH_VERSION,
        "network": network,
        "profile": profile,
        "transactionId": txid.to_lowercase(),
        "paymentOutputIndex": index_sortie,
        "amount": t.montant,
        "payTo": t.pay_to,
        "payToScriptPublicKey": t.spk_vendeur.to_lowercase(),
        "paymentRequirementsHash": t.hash_offre.to_lowercase(),
        "requestHash": t.hash_requete.to_lowercase(),
        "paymentIdentifier": t.id_paiement,
        "challengeId": challenge.map(|c| Value::String(c.to_lowercase())).unwrap_or(Value::Null),
        "inputIndex": index_entree,
        "expiresAt": t.expiration,
    });
    Autorisation { digest: sha256_hex(&canonique(&objet)), objet }
}

fn signer_empreinte(k: &Keypair, digest_hex: &str) -> Res<String> {
    let d: [u8; 32] = hex::decode(digest_hex)?.try_into().map_err(|_| "empreinte invalide")?;
    Ok(hex::encode(k.sign_schnorr(Message::from_digest(d)).as_ref()))
}

/// Identifiant de paiement conforme au schéma de l'extension (16 à 128 caractères `[A-Za-z0-9_-]`).
pub fn id_paiement_valide(id: &str) -> bool {
    (16..=128).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Signature schnorr de l'entrée `idx` (P2PK, version 0).
fn signer_entree(tx: &Transaction, utxos: &[UtxoEntry], idx: usize, k: &Keypair) -> Res<Vec<u8>> {
    let reused = SigHashReusedValuesUnsync::new();
    let pop = PopulatedTransaction::new(tx, utxos.to_vec());
    let h = calc_schnorr_signature_hash(&pop, idx, SIG_HASH_ALL, &reused);
    let sig = k.sign_schnorr(Message::from_digest_slice(h.as_bytes().as_slice())?);
    let mut s = sig.as_ref().to_vec();
    s.push(SIG_HASH_ALL.to_u8());
    Ok(ScriptBuilder::new().add_data(&s)?.drain())
}

/// Transaction version 0 : pièces P2PK du porte-monnaie → [vendeur (montant exact), monnaie].
pub fn construire_tx(
    porte_monnaie: &Keypair,
    pieces: &[(TransactionOutpoint, UtxoEntry)],
    montant: u64,
    spk_vendeur: ScriptPublicKey,
) -> Res<(Transaction, Vec<UtxoEntry>)> {
    let adresse = crate::address(porte_monnaie);
    let spk_agent = pay_to_address_script(&adresse);

    // Sélection des pièces du porte-monnaie (P2PK de l'agent uniquement).
    let mut choisies = vec![];
    let mut total = 0u64;
    for (op, u) in pieces {
        if u.script_public_key != spk_agent || u.covenant_id.is_some() {
            continue;
        }
        choisies.push((op.clone(), u.clone()));
        total += u.amount;
        if total >= montant + FRAIS_PAR_ENTREE * choisies.len() as u64 {
            break;
        }
    }
    let frais = FRAIS_PAR_ENTREE * choisies.len().max(1) as u64;
    if choisies.is_empty() || total < montant + frais {
        return Err(format!("porte-monnaie insuffisant : {total} sompi pour {} demandés (recharger depuis le coffre)", montant + frais).into());
    }
    let monnaie = total - montant - frais;
    let mut outputs = vec![TransactionOutput::new(montant, spk_vendeur)];
    if monnaie > 0 {
        outputs.push(TransactionOutput::new(monnaie, spk_agent));
    }
    let inputs: Vec<TransactionInput> =
        choisies.iter().map(|(op, _)| TransactionInput::new(op.clone(), vec![], u64::MAX, 1)).collect();
    let utxos: Vec<UtxoEntry> = choisies.iter().map(|(_, u)| u.clone()).collect();
    let mut tx = Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

    // Masse (KIP-9) : engager la masse de stockage et refuser ce que le réseau refuserait.
    let m = crate::masse::masses(&tx, &utxos).ok_or("masse de stockage incalculable (monnaie trop petite ?)")?;
    if !m.standard() {
        return Err(format!("paiement non diffusable : masse de stockage {} g (KIP-9) ; recharger le porte-monnaie", m.storage).into());
    }
    if frais < m.compute {
        return Err("frais inférieurs à la masse de calcul".into());
    }
    tx.set_storage_mass(m.storage);
    for i in 0..tx.inputs.len() {
        tx.inputs[i].signature_script = signer_entree(&tx, &utxos, i, porte_monnaie)?;
    }
    tx.finalize();
    Ok((tx, utxos))
}

pub struct Paiement {
    pub tx: Transaction,
    pub utxos: Vec<UtxoEntry>,
    /// `PaymentPayload` complet, à encoder en base64 dans l'en-tête `PAYMENT-SIGNATURE`.
    pub charge: Value,
}

/// Construit et signe un paiement `exact` standard-native depuis le porte-monnaie de l'agent.
///
/// `requis` : l'objet `PaymentRequired` reçu (pour l'extension payment-identifier) ;
/// `accepted` : l'entrée choisie dans `requis.accepts` ; `maintenant_ms` : horloge du client.
#[allow(clippy::too_many_arguments)]
pub fn construire_paiement(
    porte_monnaie: &Keypair,
    pieces: &[(TransactionOutpoint, UtxoEntry)],
    requis: &Value,
    accepted: &Value,
    methode: &str,
    url: &str,
    corps: Option<&Value>,
    id_paiement: &str,
    maintenant_ms: u64,
    pol: &Politique,
) -> Res<Paiement> {
    // L'offre choisie doit être l'une des offres proposées, à l'identique.
    let proposees = champ(requis, "accepts")?.as_array().ok_or("accepts : tableau attendu")?;
    if !proposees.iter().any(|o| canonique(o) == canonique(accepted)) {
        return Err("l'offre choisie ne figure pas dans la réponse 402".into());
    }
    let (montant, spk_vendeur) = controler_offre(accepted, url, pol)?;
    if !id_paiement_valide(id_paiement) {
        return Err("identifiant de paiement invalide (16 à 128 caractères A-Z a-z 0-9 _ -)".into());
    }
    let adresse = crate::address(porte_monnaie);
    let (tx, utxos) = construire_tx(porte_monnaie, pieces, montant, spk_vendeur)?;

    // Autorisation de la requête, signée par la clé de l'entrée 0.
    let hash_req = hash_requete(methode, url, corps, accepted);
    let delai = entier(accepted, "maxTimeoutSeconds")?;
    let expiration = iso8601(maintenant_ms + delai * 1000);
    let txid = tx.id().to_string();
    let auth = autorisation(NETWORK, PROFILE, &txid, 0, accepted, &hash_req, id_paiement, None, 0, &expiration)?;
    let signature = signer_empreinte(porte_monnaie, &auth.digest)?;

    // Extension payment-identifier : on renvoie l'info et le schéma annoncés, avec notre identifiant.
    let mut extensions = Map::new();
    if let Some(ext) = requis.get("extensions").and_then(|e| e.get("payment-identifier")) {
        let mut info = ext.get("info").and_then(Value::as_object).cloned().unwrap_or_default();
        let requis_bool = info.get("required").and_then(Value::as_bool).unwrap_or(false);
        info.insert("required".into(), Value::Bool(requis_bool));
        info.insert("id".into(), Value::String(id_paiement.into()));
        let mut e = Map::new();
        e.insert("info".into(), Value::Object(info));
        if let Some(schema) = ext.get("schema") {
            e.insert("schema".into(), schema.clone());
        }
        extensions.insert("payment-identifier".into(), Value::Object(e));
    }

    let mut charge = json!({
        "x402Version": 2,
        "accepted": accepted,
        "payload": {
            "type": "exact-transaction",
            "profile": PROFILE,
            "payerAddress": adresse.to_string(),
            "transaction": vers_safe_json(&tx, &utxos).to_string(),
            "transactionEncoding": ENCODING,
            "paymentOutputIndex": 0,
            "requestHash": hash_req,
            "authorization": {
                "version": AUTH_VERSION,
                "digest": auth.digest,
                "inputIndex": 0,
                "expiresAt": expiration,
                "signature": signature,
            },
        },
    });
    if !extensions.is_empty() {
        charge["extensions"] = Value::Object(extensions);
    }
    Ok(Paiement { tx, utxos, charge })
}

/// Fournisseur de fonds pour le client officiel `@kaspa-x402/client` (méthode `payExactTransaction`).
///
/// `req` : un `ExactTransactionPaymentRequest` (termes déjà fixés et vérifiés par le client).
/// Le relais revérifie tout ce qui dépend de lui (réseau, profil, politique, script du vendeur) et
/// renvoie un `ExactTransactionPaymentResult`. La transaction n'est pas diffusée ici.
pub fn payer_pour_le_client(porte_monnaie: &Keypair, pieces: &[(TransactionOutpoint, UtxoEntry)], req: &Value, pol: &Politique) -> Res<Value> {
    if texte(req, "network")? != NETWORK {
        return Err("réseau non pris en charge par le relais".into());
    }
    if texte(req, "profile")? != PROFILE {
        return Err("le relais ne paie qu'en standard-native".into());
    }
    if req.get("head").is_some_and(|h| !h.is_null()) || req.get("hashChainHead").is_some_and(|h| !h.is_null()) {
        return Err("champs additifs inattendus".into());
    }
    if req.get("paymentOutputIndex").and_then(Value::as_u64).unwrap_or(0) != 0 {
        return Err("sortie de paiement attendue à l'index 0".into());
    }
    let montant = u64_texte(req, "amount")?;
    if montant == 0 || montant > pol.montant_max {
        return Err(format!("{montant} sompi hors politique (max {})", pol.montant_max).into());
    }
    let pay_to = texte(req, "payTo")?;
    if !pol.destinataires.is_empty() && !pol.destinataires.iter().any(|d| d == pay_to) {
        return Err(format!("destinataire {pay_to} hors liste").into());
    }
    let adresse_vendeur = Address::try_from(pay_to).map_err(|e| format!("payTo invalide : {e}"))?;
    let spk_vendeur = pay_to_address_script(&adresse_vendeur);
    if texte(req, "payToScriptPublicKey")?.to_lowercase() != spk_hex(&spk_vendeur) {
        return Err("payToScriptPublicKey ne correspond pas à payTo".into());
    }
    let origine = texte(req, "origin")?;
    if !pol.origines.is_empty() && !pol.origines.iter().any(|o| o == origine) {
        return Err(format!("origine {origine} hors liste").into());
    }
    let id = texte(req, "paymentIdentifier")?;
    if !id_paiement_valide(id) {
        return Err("identifiant de paiement invalide".into());
    }
    let (tx, utxos) = construire_tx(porte_monnaie, pieces, montant, spk_vendeur)?;
    let txid = tx.id().to_string();
    let termes = Termes {
        montant: montant.to_string(),
        pay_to: pay_to.into(),
        spk_vendeur: spk_hex(&tx.outputs[0].script_public_key),
        hash_offre: texte(req, "paymentRequirementsHash")?.into(),
        hash_requete: texte(req, "requestHash")?.into(),
        id_paiement: id.into(),
        expiration: texte(req, "authorizationExpiresAt")?.into(),
    };
    let auth = autorisation_termes(NETWORK, PROFILE, &txid, 0, &termes, None, 0);
    let outpoints: Vec<Value> = tx
        .inputs
        .iter()
        .map(|i| json!({ "txid": i.previous_outpoint.transaction_id.to_string(), "index": i.previous_outpoint.index }))
        .collect();
    Ok(json!({
        "transaction": vers_safe_json(&tx, &utxos).to_string(),
        "transactionEncoding": ENCODING,
        "transactionId": txid,
        "paymentOutputIndex": 0,
        "authorization": {
            "version": AUTH_VERSION,
            "inputIndex": 0,
            "expiresAt": termes.expiration,
            "digest": auth.digest,
            "signature": signer_empreinte(porte_monnaie, &auth.digest)?,
        },
        "inputOutpoints": outpoints,
        "payerAddress": crate::address(porte_monnaie).to_string(),
        "fundingSource": "vault-treasury",
    }))
}

/// Pièces au format du client (`FundingProviderUtxo`) → pièces du relais.
pub fn pieces_du_client(v: &Value) -> Res<Vec<(TransactionOutpoint, UtxoEntry)>> {
    let mut r = vec![];
    for u in v.as_array().ok_or("pièces : tableau attendu")? {
        if u.get("covenantId").is_some_and(|c| !c.is_null()) {
            continue; // jamais de pièce sous covenant dans un paiement exact
        }
        let op = champ(u, "outpoint")?;
        let txid: TransactionId = texte(op, "txid")?.parse()?;
        let index = u32::try_from(entier(op, "index")?)?;
        r.push((
            TransactionOutpoint::new(txid, index),
            UtxoEntry::new(u64_texte(u, "amount")?, spk_depuis_hex(texte(u, "scriptPublicKey")?)?, 0, false, None),
        ));
    }
    Ok(r)
}

/// Schéma de l'extension payment-identifier (identique à `PAYMENT_IDENTIFIER_INFO_SCHEMA` de kaspa-x402).
pub fn schema_id_paiement() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://kaspa-x402.org/schemas/payment-identifier.schema.json",
        "title": "Kaspa x402 Payment Identifier Extension Info",
        "type": "object",
        "required": ["required"],
        "properties": {
            "required": { "type": "boolean" },
            "id": { "type": "string", "minLength": 16, "maxLength": 128, "pattern": "^[A-Za-z0-9_-]+$" }
        },
        "additionalProperties": true
    })
}

/// Exemple hors ligne et déterministe (clés de démonstration publiques `[2;32]` agent, `[3;32]` vendeur) :
/// une réponse 402 standard-native et le paiement construit par le relais.
pub fn exemple() -> Res<Value> {
    let k = |b: u8| Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).expect("clé de démonstration");
    let (agent, vendeur) = (k(2), k(3));
    let adr = crate::address(&vendeur);
    let url = "https://api.exemple.test/meteo";
    let accepted = json!({
        "scheme": "exact", "network": NETWORK, "amount": "20000000", "asset": "KAS",
        "payTo": adr.to_string(), "maxTimeoutSeconds": 60,
        "extra": {
            "binding": BINDING, "profile": PROFILE, "paymentFlow": "upfront", "finality": "accepted",
            "transactionEncoding": ENCODING, "payToScriptPublicKey": spk_hex(&pay_to_address_script(&adr)),
        }
    });
    let requis = json!({
        "x402Version": 2,
        "resource": { "url": url, "description": "Météo Kaspa (exemple)", "mimeType": "application/json" },
        "accepts": [accepted.clone()],
        "extensions": { "payment-identifier": { "info": { "required": true }, "schema": schema_id_paiement() } },
    });
    let spk = pay_to_address_script(&crate::address(&agent));
    let pieces = vec![(TransactionOutpoint::new(TransactionId::from_bytes([0x70; 32]), 0), UtxoEntry::new(50_000_000, spk, 0, false, None))];
    let pol = Politique { montant_max: 50_000_000, destinataires: vec![], origines: vec!["https://api.exemple.test".into()] };
    let maintenant = 4_070_908_740_000; // 2098-12-31T23:59:00Z, horloge de référence des vecteurs officiels
    let p = construire_paiement(&agent, &pieces, &requis, &accepted, "GET", url, None, "lamaz_relais_exemple_0001", maintenant, &pol)?;
    Ok(json!({
        "referenceTime": iso8601(maintenant),
        "request": { "method": "GET", "url": url },
        "paymentRequired": requis,
        "paymentPayload": p.charge,
    }))
}

// ---------------------------------------------------------------------------
// Recharge du porte-monnaie depuis le coffre
// ---------------------------------------------------------------------------

/// Montant à verser du coffre vers le porte-monnaie pour pouvoir payer `besoin` (montant + frais).
/// `None` : le solde suffit. Le porte-monnaie est rempli jusqu'au plafond, jamais au-delà, et la
/// recharge ne dépasse jamais `max_par_paiement` du coffre.
pub fn recharge_necessaire(solde: u64, besoin: u64, plafond: u64, max_par_paiement: u64) -> Res<Option<u64>> {
    if solde >= besoin {
        return Ok(None);
    }
    if besoin > plafond {
        return Err(format!("paiement de {besoin} sompi supérieur au plafond du porte-monnaie ({plafond})").into());
    }
    let r = (plafond - solde).min(max_par_paiement);
    if solde + r < besoin {
        return Err("recharge impossible en un seul paiement du coffre".into());
    }
    Ok(Some(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vecteur(nom: &str) -> Value {
        let p = format!("{}/vecteurs/kaspa-x402/{nom}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn identifiant_de_transaction_conforme_au_vecteur() {
        let v = vecteur("interop-v1.json");
        let sn = &v["transactionEncoding"]["profiles"]["standardNative"];
        let (tx, utxos) = depuis_safe_json(&sn["artifact"]).unwrap();
        assert_eq!(tx.id().to_string(), sn["transactionId"].as_str().unwrap());
        // Aller-retour : notre projection est identique (au sens canonique) à celle du vecteur.
        assert_eq!(canonique(&vers_safe_json(&tx, &utxos)), canonique(&sn["artifact"]));
    }

    #[test]
    fn signature_du_vecteur_valide_avec_notre_sighash() {
        let v = vecteur("interop-v1.json");
        let sn = &v["transactionEncoding"]["profiles"]["standardNative"];
        let (tx, utxos) = depuis_safe_json(&sn["artifact"]).unwrap();
        let reused = SigHashReusedValuesUnsync::new();
        let pop = PopulatedTransaction::new(&tx, utxos.clone());
        let h = calc_schnorr_signature_hash(&pop, 0, SIG_HASH_ALL, &reused);
        let ss = &tx.inputs[0].signature_script;
        assert_eq!(ss[0], 65); // push de 65 octets
        let sig = secp256k1::schnorr::Signature::from_slice(&ss[1..65]).unwrap();
        let pk = secp256k1::XOnlyPublicKey::from_slice(&utxos[0].script_public_key.script()[1..33]).unwrap();
        secp256k1::SECP256K1.verify_schnorr(&sig, &Message::from_digest_slice(h.as_bytes().as_slice()).unwrap(), &pk).unwrap();
    }

    #[test]
    fn hash_de_l_offre_et_autorisation_conformes_au_vecteur() {
        let v = vecteur("interop-v1.json");
        let pr = &v["paymentRequirements"];
        assert_eq!(canonique(&pr["value"]), pr["canonicalJsonUtf8"].as_str().unwrap());
        assert_eq!(hash_offre(&pr["value"]), pr["sha256"].as_str().unwrap());

        let ra = &v["requestAuthorization"];
        let i = &ra["input"];
        let a = autorisation(
            i["network"].as_str().unwrap(),
            i["profile"].as_str().unwrap(),
            i["transactionId"].as_str().unwrap(),
            i["paymentOutputIndex"].as_u64().unwrap(),
            &pr["value"],
            i["requestHash"].as_str().unwrap(),
            i["paymentIdentifier"].as_str().unwrap(),
            i["challengeId"].as_str(),
            i["inputIndex"].as_u64().unwrap(),
            i["expiresAt"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(canonique(&a.objet), ra["canonicalJsonUtf8"].as_str().unwrap());
        assert_eq!(a.digest, ra["sha256"].as_str().unwrap());
        // La signature officielle vérifie notre empreinte.
        let sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(ra["signature"].as_str().unwrap()).unwrap()).unwrap();
        let pk = secp256k1::XOnlyPublicKey::from_slice(&hex::decode(ra["signerPublicKey"].as_str().unwrap()).unwrap()).unwrap();
        let d: [u8; 32] = hex::decode(&a.digest).unwrap().try_into().unwrap();
        secp256k1::SECP256K1.verify_schnorr(&sig, &Message::from_digest(d), &pk).unwrap();
    }

    #[test]
    fn date_iso() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(4_070_908_800_000), "2099-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_795_000_000_123), "2026-11-18T11:06:40.123Z");
    }

    // --- Paiement complet construit par nous ---------------------------------------------

    fn cle(b: u8) -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[b; 32]).unwrap()
    }

    fn offre(vendeur: &Keypair, montant: u64) -> (Value, Value) {
        let adr = crate::address(vendeur);
        let accepted = json!({
            "scheme": "exact", "network": NETWORK, "amount": montant.to_string(), "asset": "KAS",
            "payTo": adr.to_string(), "maxTimeoutSeconds": 60,
            "extra": {
                "binding": BINDING, "profile": PROFILE, "paymentFlow": "upfront", "finality": "accepted",
                "transactionEncoding": ENCODING, "payToScriptPublicKey": spk_hex(&pay_to_address_script(&adr)),
            }
        });
        let http = vecteur("exact-transaction.json");
        let requis = json!({
            "x402Version": 2,
            "resource": { "url": "https://api.exemple.test/meteo" },
            "accepts": [accepted.clone()],
            "extensions": http["paymentRequired"]["extensions"].clone(),
        });
        (requis, accepted)
    }

    fn pieces(agent: &Keypair, montants: &[u64]) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        let spk = pay_to_address_script(&crate::address(agent));
        montants
            .iter()
            .enumerate()
            .map(|(i, m)| (TransactionOutpoint::new(TransactionId::from_bytes([i as u8 + 1; 32]), 0), UtxoEntry::new(*m, spk.clone(), 0, false, None)))
            .collect()
    }

    fn politique() -> Politique {
        Politique { montant_max: 50_000_000, destinataires: vec![], origines: vec!["https://api.exemple.test".into()] }
    }

    #[test]
    fn paiement_conforme_au_profil_standard_native() {
        let (agent, vendeur) = (cle(2), cle(3));
        let (requis, accepted) = offre(&vendeur, 20_000_000);
        let p = construire_paiement(
            &agent, &pieces(&agent, &[50_000_000]), &requis, &accepted, "GET", "https://api.exemple.test/meteo", None,
            "lamaz_test_paiement_0001", 1_795_000_000_000, &politique(),
        )
        .unwrap();

        // Forme exigée par la spec (section « Canonical transaction »).
        let tx = &p.tx;
        assert_eq!(tx.version, 0);
        assert_eq!((tx.lock_time, tx.gas), (0, 0));
        assert!(tx.payload.is_empty());
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 20_000_000);
        assert_eq!(spk_hex(&tx.outputs[0].script_public_key), accepted["extra"]["payToScriptPublicKey"].as_str().unwrap());
        assert_eq!(tx.outputs[1].script_public_key, p.utxos[0].script_public_key); // monnaie rendue au payeur
        assert!(tx.outputs.iter().all(|o| o.covenant.is_none()));
        assert!(tx.storage_mass() > 0);

        // Les signatures de la transaction passent le moteur de script de Kaspa.
        crate::relais::tests::verifier_scripts(tx, &p.utxos);

        // La charge utile se relit : identifiant recalculé, autorisation vérifiable.
        let pl = &p.charge["payload"];
        let (relue, _) = depuis_safe_json(&serde_json::from_str(pl["transaction"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(relue.id(), tx.id());
        let auth = &pl["authorization"];
        let a = autorisation(NETWORK, PROFILE, &tx.id().to_string(), 0, &accepted, pl["requestHash"].as_str().unwrap(),
            "lamaz_test_paiement_0001", None, 0, auth["expiresAt"].as_str().unwrap()).unwrap();
        assert_eq!(a.digest, auth["digest"].as_str().unwrap());
        let sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(auth["signature"].as_str().unwrap()).unwrap()).unwrap();
        let d: [u8; 32] = hex::decode(&a.digest).unwrap().try_into().unwrap();
        secp256k1::SECP256K1.verify_schnorr(&sig, &Message::from_digest(d), &agent.x_only_public_key().0).unwrap();
        assert_eq!(auth["expiresAt"], "2026-11-18T11:07:40.000Z"); // maintenant + maxTimeoutSeconds
        assert_eq!(p.charge["extensions"]["payment-identifier"]["info"]["id"], "lamaz_test_paiement_0001");
        assert_eq!(p.charge["extensions"]["payment-identifier"]["info"]["required"], true);
        assert_eq!(pl["requestHash"].as_str().unwrap(), hash_requete("GET", "https://api.exemple.test/meteo", None, &accepted));
    }

    pub(crate) fn verifier_scripts(tx: &Transaction, utxos: &[UtxoEntry]) {
        use kaspa_txscript::caches::Cache;
        use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
        let pop = PopulatedTransaction::new(tx, utxos.to_vec());
        let cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        for i in 0..tx.inputs.len() {
            let input = tx.inputs[i].clone();
            let mut vm = TxScriptEngine::from_transaction_input(
                &pop, &input, i, &utxos[i], EngineCtx::new(&cache).with_reused(&reused), EngineFlags::default(),
            );
            vm.execute().unwrap_or_else(|e| panic!("entrée {i} refusée : {e:?}"));
        }
    }

    #[test]
    fn offres_refusees_avant_signature() {
        let (agent, vendeur) = (cle(2), cle(3));
        let (requis, accepted) = offre(&vendeur, 20_000_000);
        let essai = |acc: &Value, req: &Value, url: &str, pol: &Politique| {
            construire_paiement(&agent, &pieces(&agent, &[50_000_000]), req, acc, "GET", url, None, "lamaz_test_paiement_0001", 0, pol)
        };
        let url = "https://api.exemple.test/meteo";
        // Trop cher pour la politique.
        let pol_basse = Politique { montant_max: 10_000_000, ..politique() };
        assert!(essai(&accepted, &requis, url, &pol_basse).is_err());
        // Origine non autorisée.
        assert!(essai(&accepted, &requis, "https://autre.test/meteo", &politique()).is_err());
        // Offre modifiée après coup (ne figure pas dans la 402).
        let mut changee = accepted.clone();
        changee["amount"] = json!("1000");
        assert!(essai(&changee, &requis, url, &politique()).is_err());
        // Script du vendeur qui ne correspond pas à payTo.
        let mut faux = accepted.clone();
        faux["extra"]["payToScriptPublicKey"] = json!(spk_hex(&pay_to_address_script(&crate::address(&cle(9)))));
        let req_faux = json!({ "accepts": [faux.clone()], "extensions": requis["extensions"].clone() });
        assert!(essai(&faux, &req_faux, url, &politique()).is_err());
        // Profil additif : hors du relais.
        let mut additif = accepted.clone();
        additif["extra"]["profile"] = json!("additive");
        let req_add = json!({ "accepts": [additif.clone()] });
        assert!(essai(&additif, &req_add, url, &politique()).is_err());
        // Identifiant de paiement trop court.
        assert!(construire_paiement(&agent, &pieces(&agent, &[50_000_000]), &requis, &accepted, "GET", url, None, "court", 0, &politique()).is_err());
        // Porte-monnaie vide ou insuffisant.
        assert!(construire_paiement(&agent, &pieces(&agent, &[1_000_000]), &requis, &accepted, "GET", url, None, "lamaz_test_paiement_0001", 0, &politique()).is_err());
        // Pièces d'une autre clé ignorées.
        assert!(construire_paiement(&agent, &pieces(&cle(5), &[50_000_000]), &requis, &accepted, "GET", url, None, "lamaz_test_paiement_0001", 0, &politique()).is_err());
    }

    #[test]
    fn recharge_bornee() {
        let max = 50_000_000;
        assert_eq!(recharge_necessaire(30_000_000, 20_300_000, 50_000_000, max).unwrap(), None);
        assert_eq!(recharge_necessaire(5_000_000, 20_300_000, 50_000_000, max).unwrap(), Some(45_000_000));
        assert!(recharge_necessaire(0, 60_000_000, 50_000_000, max).is_err());
        // Jamais au-delà du plafond, quel que soit le solde de départ.
        for solde in [0u64, 1, 10_000_000, 49_999_999] {
            if let Some(r) = recharge_necessaire(solde, 20_300_000, 50_000_000, max).unwrap() {
                assert!(solde + r <= 50_000_000);
            }
        }
    }
}

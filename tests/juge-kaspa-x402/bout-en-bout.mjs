// Démonstration de bout en bout, hors ligne :
//
//   agent (DirectModeClient de @kaspa-x402/client, inchangé)
//     └─ fournisseur « vault-treasury » (fournisseur-coffre.mjs)
//          ├─ recharge le porte-monnaie depuis le coffre (règles AgentBudget)
//          └─ vault-cli relais-payer (Rust) : transaction exact standard-native signée
//   vendeur (DirectModeServer de @kaspa-x402/server, inchangé)
//     └─ vérificateur : contrôles cryptographiques réels avec les fonctions publiées de kaspa-x402
//
// Simulé ici : la chaîne (ensemble d'UTXO en mémoire) et le coffre (modèle JS des règles AgentBudget,
// dont le comportement réel est prouvé par les essais testnet et le fuzzing du dépôt).
// Le transport HTTP en mémoire et la preuve d'acceptation reprennent le mode simulé de kaspa-x402
// (examples/lib/mock-direct-mode.mjs, licence MIT).
//
// Usage : node bout-en-bout.mjs [chemin vers vault-cli]   (par défaut ../../cli/target/debug/vault-cli)

import { fileURLToPath } from "node:url";
import { DirectModeClient, MemoryChannelStore } from "@kaspa-x402/client";
import { DirectModeServer, MemoryServerChannelStore } from "@kaspa-x402/server";
import * as core from "@kaspa-x402/core";
import * as cov from "@kaspa-x402/covenant";
import { schnorr } from "@noble/curves/secp256k1";
import { FournisseurCoffre, signataireRust, FRAIS_PAR_ENTREE } from "./fournisseur-coffre.mjs";

const RESEAU = "kaspa:testnet-10";
const VAULT_CLI = process.argv[2] ?? fileURLToPath(new URL("../../cli/target/debug/vault-cli", import.meta.url));
const ORIGINE = "https://api.exemple.test";
const PRIX = "20000000"; // 0,2 TKAS par appel

// Clés de démonstration publiques (identiques à `vault-cli relais-payer --demo`) : agent [2;32], vendeur [3;32].
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");
const CLE_AGENT = toHex(schnorr.getPublicKey(new Uint8Array(32).fill(2)));
const CLE_VENDEUR = toHex(schnorr.getPublicKey(new Uint8Array(32).fill(3)));

// ---------------------------------------------------------------- adresses Kaspa (encodage réel)

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function polymod(values) {
  const G = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= G[i];
  }
  return c ^ 1n;
}
const conv = (data, from, to, pad) => {
  let acc = 0, bits = 0; const out = [];
  for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & ((1 << to) - 1)); } }
  if (pad && bits > 0) out.push((acc << (to - bits)) & ((1 << to) - 1));
  return out;
};
function encoderAdresse(prefix, version, payload) {
  const data = conv([version, ...payload], 8, 5, true);
  const pre = [...prefix].map((c) => c.charCodeAt(0) & 31);
  const pm = polymod([...pre, 0, ...data, 0, 0, 0, 0, 0, 0, 0, 0]);
  const chk = Array.from({ length: 8 }, (_, i) => Number((pm >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:${[...data, ...chk].map((v) => CHARSET[v]).join("")}`;
}
function decoderAdresse(adresse) {
  const [prefix, corps] = adresse.split(":");
  const vals = [...corps].map((c) => CHARSET.indexOf(c));
  if (vals.includes(-1)) throw new Error("caractère invalide");
  const pre = [...prefix].map((c) => c.charCodeAt(0) & 31);
  if (polymod([...pre, 0, ...vals]) !== 0n) throw new Error(`somme de contrôle invalide : ${adresse}`);
  const bytes = conv(vals.slice(0, -8), 5, 8, false);
  return { prefix, version: bytes[0], payload: bytes.slice(1) };
}
const codecAdresses = {
  scriptPublicKeyForAddress(adresse, reseau) {
    if (reseau !== RESEAU) throw new Error("réseau non pris en charge");
    const { prefix, version, payload } = decoderAdresse(adresse);
    if (prefix !== "kaspatest" || version !== 0 || payload.length !== 32) throw new Error("adresse P2PK testnet attendue");
    return `000020${toHex(payload)}ac`;
  },
  encodeScriptAddress() { throw new Error("non utilisé (exact uniquement)"); },
};
const ADRESSE_AGENT = encoderAdresse("kaspatest", 0, hex(CLE_AGENT));
const ADRESSE_VENDEUR = encoderAdresse("kaspatest", 0, hex(CLE_VENDEUR));

// ---------------------------------------------------------------- chaîne simulée

const preuveAcceptation = (transactionId) => ({
  status: "accepted",
  transactionId: transactionId.toLowerCase(),
  acceptingBlockHash: core.sha256Hex(`bloc:${transactionId}`),
  acceptingBlockBlueScore: (1000n - BigInt(core.TESTNET_10_CONFIRMATION_THRESHOLD) + 1n).toString(),
  confirmationCount: core.TESTNET_10_CONFIRMATION_THRESHOLD,
  checkpoint: { blockHash: core.sha256Hex("point-de-controle"), blueScore: "1000", daaScore: "1000" },
});

class ChaineSimulee {
  utxos = new Map();
  daa = 1_000_000n;
  #n = 0;
  ajouter(adresse, montant) {
    const outpoint = { txid: core.sha256Hex(`depot:${this.#n++}`), index: 0 };
    const spk = codecAdresses.scriptPublicKeyForAddress(adresse, RESEAU);
    this.utxos.set(`${outpoint.txid}:0`, { outpoint, amount: montant.toString(), scriptPublicKey: spk, address: adresse });
  }
  solde(adresse) {
    return [...this.utxos.values()].filter((u) => u.address === adresse).reduce((s, u) => s + BigInt(u.amount), 0n);
  }
  async getUtxos(adresses) { return [...this.utxos.values()].filter((u) => adresses.includes(u.address)).map((u) => structuredClone(u)); }
  async getUtxo(op) { return structuredClone(this.utxos.get(`${op.txid}:${op.index}`) ?? null); }
  async getVirtualDaaScore() { return this.daa.toString(); }
  async sendTransaction(transaction) {
    if (process.env.TRACE) console.log('  [chaîne] diffusion', transaction.slice(0, 80));
    const tx = JSON.parse(transaction);
    for (const i of tx.inputs) if (!this.utxos.delete(`${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`)) throw new Error("entrée déjà dépensée");
    tx.outputs.forEach((o, index) => {
      const adresse = o.scriptPublicKey === codecAdresses.scriptPublicKeyForAddress(ADRESSE_AGENT, RESEAU) ? ADRESSE_AGENT : ADRESSE_VENDEUR;
      this.utxos.set(`${tx.id}:${index}`, { outpoint: { txid: tx.id, index }, amount: o.value, scriptPublicKey: o.scriptPublicKey, address: adresse });
    });
    return { transactionId: tx.id, evidence: preuveAcceptation(tx.id), finality: "accepted" };
  }
}

// ---------------------------------------------------------------- coffre simulé (règles AgentBudget)

class CoffreSimule {
  constructor(chaine, { capacite, periode, maxParPaiement, frais }) {
    Object.assign(this, { chaine, capacite, periode, maxParPaiement, frais });
    this.jetons = capacite;
    this.dernier = chaine.daa;
    this.verse = 0n;
  }
  disponible() {
    const ecoule = this.chaine.daa - this.dernier < this.periode ? this.chaine.daa - this.dernier : this.periode;
    const d = this.jetons + (ecoule * this.capacite) / this.periode;
    return d > this.capacite ? this.capacite : d;
  }
  async recharger(montant, adresse) {
    // Mêmes contrôles que l'entrée `pay` du covenant : plafond par paiement, budget frais compris.
    const dispo = this.disponible();
    if (montant > this.maxParPaiement) throw new Error(`coffre : ${montant} > plafond par paiement`);
    if (montant + this.frais > dispo) throw new Error(`coffre : budget épuisé (${dispo} sompi disponibles, ${montant + this.frais} demandés)`);
    this.jetons = dispo - montant - this.frais;
    this.dernier = this.chaine.daa;
    this.verse += montant;
    this.chaine.ajouter(adresse, montant);
    console.log(`  coffre → porte-monnaie : ${Number(montant) / 1e8} TKAS (budget restant ${Number(this.jetons) / 1e8} TKAS)`);
  }
}

// ---------------------------------------------------------------- vérificateur du vendeur (contrôles réels)

const ref = (t) => ({
  ...t,
  inputs: t.inputs.map((i) => ({ ...i, previousOutpoint: { txid: i.previousOutpoint.transactionId, index: i.previousOutpoint.index } })),
  outputs: t.outputs.map((o) => ({ amount: o.value, scriptPublicKey: o.scriptPublicKey, covenant: o.covenant })),
});

function verificateur(chaine) {
  return {
    async verifyExactPayment(r) {
      const tx = JSON.parse(r.transaction);
      const echec = (m) => { throw new Error(`vérification refusée : ${m}`); };
      if (r.profile !== "standard-native") echec("profil");
      if (cov.exactV0TransactionId(ref(tx)) !== tx.id) echec("identifiant de transaction");
      if (tx.version !== 0 || tx.payload !== "" || tx.outputs.some((o) => o.covenant !== null)) echec("forme");
      const sortie = tx.outputs[r.paymentOutputIndex];
      if (sortie.value !== r.amount || sortie.scriptPublicKey !== r.payToScriptPublicKey) echec("montant ou destinataire");
      for (const [i, entree] of tx.inputs.entries()) {
        // Nœud de confiance : l'UTXO doit exister, non dépensé, identique à l'indice fourni.
        const u = await chaine.getUtxo({ txid: entree.previousOutpoint.transactionId, index: entree.previousOutpoint.index });
        if (!u || u.amount !== entree.utxo.amount || u.scriptPublicKey !== entree.utxo.scriptPublicKey) echec(`entrée ${i} inconnue de la chaîne`);
        const ev = cov.exactV0SchnorrSignatureEvidence(ref(tx), i);
        if (!schnorr.verify(hex(ev.signature), hex(ev.digest), hex(ev.publicKey))) echec(`signature de l'entrée ${i}`);
      }
      const digest = core.exactRequestAuthorizationDigest({
        network: r.network, profile: r.profile, transactionId: tx.id, paymentOutputIndex: r.paymentOutputIndex,
        amount: r.amount, payTo: r.payTo, payToScriptPublicKey: r.payToScriptPublicKey,
        paymentRequirementsHash: r.paymentRequirementsHash, requestHash: r.requestHash,
        paymentIdentifier: r.paymentIdentifier, inputIndex: r.authorization.inputIndex, expiresAt: r.authorization.expiresAt,
      });
      if (digest !== r.authorization.digest) echec("empreinte d'autorisation");
      const cle = tx.inputs[r.authorization.inputIndex].utxo.scriptPublicKey.slice(6, 70);
      if (!schnorr.verify(hex(r.authorization.signature), hex(digest), hex(cle))) echec("signature d'autorisation");
      return {
        transactionId: tx.id,
        paymentOutput: { amount: sortie.value, scriptPublicKey: sortie.scriptPublicKey },
        payerAddress: ADRESSE_AGENT,
        // Pas de `finality` : la transaction n'est pas encore sur la chaîne, c'est le vendeur qui la diffuse.
        requestAuthorization: { authorizationId: core.exactRequestAuthorizationId(r.authorization), digest, inputIndex: r.authorization.inputIndex, publicKey: cle },
      };
    },
  };
}

// ---------------------------------------------------------------- assemblage

const chaine = new ChaineSimulee();
const FRAIS_COFFRE = 1_500_000n;
const coffre = new CoffreSimule(chaine, { capacite: 100_000_000n, periode: 36_000n, maxParPaiement: 50_000_000n, frais: FRAIS_COFFRE });

const serveur = new DirectModeServer({
  confirmationThreshold: core.TESTNET_10_CONFIRMATION_THRESHOLD,
  network: RESEAU,
  payTo: ADRESSE_VENDEUR,
  amount: PRIX,
  store: new MemoryServerChannelStore(),
  chainProvider: { sendTransaction: (t) => chaine.sendTransaction(t) },
  addressCodec: codecAdresses,
  exactTransactionVerifier: verificateur(chaine),
  exactProfile: "standard-native",
});

const transport = async (input, init = {}) => {
  const url = String(input);
  const rep = await serveur.handlePaidRequest(
    { routeAccess: "public",
      // Identité d'admission fournie par l'hôte (les requêtes anonymes sont plafonnées à 8 par minute).
      admissionKey: core.sha256Hex("appelant:agent-de-demonstration"),
      method: init.method ?? "GET", url, body: init.body ?? null, headers: init.headers,
      resource: { url, description: "Météo Kaspa", mimeType: "application/json" }, paymentAmount: PRIX, paymentScheme: "exact",
      requestHash: init.requestHash },
    async () => ({ status: 200, body: { ville: "Saint-Denis", ciel: "dégagé" } }),
  );
  const entetes = new Map(Object.entries(rep.headers ?? {}).map(([k, v]) => [k.toLowerCase(), String(v)]));
  return { status: rep.status, url, redirected: false, body: rep.body,
    headers: { get: (n) => entetes.get(n.toLowerCase()) ?? null, entries: () => entetes.entries() },
    json: async () => rep.body, text: async () => JSON.stringify(rep.body) };
};
// Transport en mémoire : n'ouvre aucune connexion (même marquage que le mode simulé de kaspa-x402).
Object.defineProperty(transport, Symbol.for("kaspa-x402:bound-paid-fetch:v1"), { value: true });

const fournisseur = new FournisseurCoffre({
  adresse: ADRESSE_AGENT,
  clePublique: CLE_AGENT,
  chaine,
  coffre,
  plafond: 50_000_000n,
  maxParPaiement: 50_000_000n,
  signer: signataireRust({ binaire: VAULT_CLI, args: ["relais-payer", "--demo"], env: { RELAIS_ORIGINES: ORIGINE, RELAIS_DESTINATAIRES: ADRESSE_VENDEUR } }),
});

const client = new DirectModeClient({
  addressCodec: codecAdresses,
  confirmationThreshold: core.TESTNET_10_CONFIRMATION_THRESHOLD,
  fundingProvider: fournisseur,
  store: new MemoryChannelStore(),
  fundingPolicy: {
    requiredSource: "vault-treasury",
    allowedOrigins: [ORIGINE],
    allowedExactProfiles: ["standard-native"],
    allowedPayTo: [ADRESSE_VENDEUR],
    maximumExactAmountSompi: "50000000",
  },
  fetch: transport,
});

// ---------------------------------------------------------------- scénario

console.log(`Agent      ${ADRESSE_AGENT}\nVendeur    ${ADRESSE_VENDEUR}\nCoffre     budget 1 TKAS, 0,5 TKAS max par paiement, frais 0,015 TKAS\n`);
let reussis = 0;
let refuse = null;
for (let n = 1; n <= 8; n++) {
  console.log(`Appel ${n} : GET ${ORIGINE}/meteo (${Number(PRIX) / 1e8} TKAS)`);
  try {
    const r = await client.paidFetch(`${ORIGINE}/meteo`, { paymentIdentifier: `lamaz_bout_en_bout_${String(n).padStart(4, "0")}` });
    const solde = chaine.solde(ADRESSE_AGENT);
    console.log(`  réponse ${r.response.status}, règlement ${r.settlement?.response.success ? "accepté" : "?"}, porte-monnaie ${Number(solde) / 1e8} TKAS`);
    if (r.response.status !== 200) throw new Error(`statut ${r.response.status} ${JSON.stringify(await r.response.json?.() ?? r.response.body)}`);
    if (solde > 50_000_000n) throw new Error("porte-monnaie au-dessus du plafond");
    reussis++;
  } catch (e) {
    refuse = e.message;
    console.log(`  refusé : ${e.message}`);
    break;
  }
}

const recu = chaine.solde(ADRESSE_VENDEUR);
const depense = coffre.verse;
console.log(`\nAppels payés : ${reussis} ; vendeur payé ${Number(recu) / 1e8} TKAS ; sorti du coffre ${Number(depense) / 1e8} TKAS`);
const frais = depense - recu - chaine.solde(ADRESSE_AGENT);
console.log(`Frais de transaction payés par le porte-monnaie : ${Number(frais) / 1e8} TKAS`);
const ok = reussis >= 3 && refuse !== null && /budget épuisé/.test(refuse) && recu === BigInt(PRIX) * BigInt(reussis)
  && frais > 0n && frais % FRAIS_PAR_ENTREE === 0n && frais <= 2n * BigInt(reussis) * FRAIS_PAR_ENTREE;
console.log(ok
  ? "VERDICT : le client et le serveur kaspa-x402 acceptent les paiements du coffre, et le budget du coffre arrête l'agent."
  : "VERDICT : ÉCHEC");
process.exit(ok ? 0 : 1);

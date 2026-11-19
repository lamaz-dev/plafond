// Essai réel sur le testnet-10 : le coffre AgentBudget paie le vendeur de démonstration public de
// Kaspa x402 (https://demo.kaspa-x402.org/exact, 0,2 TKAS, exact standard-native).
//
//   DirectModeClient (@kaspa-x402/client, inchangé) + transport HTTPS borné officiel
//     └─ FournisseurCoffre (vault-treasury)
//          ├─ vault-cli pieces-porte-monnaie       (UTXO du porte-monnaie, lus sur le nœud)
//          ├─ vault-cli recharger-porte-monnaie N  (paiement du coffre, règles du covenant)
//          └─ vault-cli relais-payer               (transaction exact signée, jamais diffusée ici)
//   Vendeur : le serveur complet de Kaspa x402, avec son vérificateur de consensus. C'est lui qui diffuse.
//
// Secret : VAULT_PHRASE (secret GitHub du dépôt lab). Testnet uniquement.
// Usage : node essai-testnet.mjs <chemin vers vault-cli>

import { spawn } from "node:child_process";
import { promises as dns } from "node:dns";
import { DirectModeClient, MemoryChannelStore } from "@kaspa-x402/client";
import { createNodeBoundedFetch } from "@kaspa-x402/client/node";
import * as core from "@kaspa-x402/core";
import { FournisseurCoffre, signataireRust } from "./fournisseur-coffre.mjs";

const VAULT_CLI = process.argv[2];
if (!VAULT_CLI) throw new Error("usage : node essai-testnet.mjs <vault-cli>");
const ORIGINE = "https://demo.kaspa-x402.org";
const RESSOURCE = `${ORIGINE}/exact`;
const PRIX_MAX = 20_000_000n; // prix publié de la démo : 0,2 TKAS
const RESEAU = "kaspa:testnet-10";
// Destinataire épinglé : adresse du vendeur de démonstration, dérivée de son payToScriptPublicKey publié
// (000020bee817…edf9ac, lu le 19 novembre 2026). Toute autre adresse est refusée avant signature.
const VENDEUR = "kaspatest:qzlws9lm7uyt0tftzffshnyeu2zcqk4kf7hw5ghk6v0zh093vnkljcy2fl0fh";

function vaultCli(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(VAULT_CLI, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => { err += d; process.stderr.write(d); });
    p.on("error", reject);
    p.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(`vault-cli ${args[0]} : ${err.trim().split("\n").pop()}`))));
  });
}

// Adresse et clé du porte-monnaie : lues dans la première ligne de pièces, ou via `adresses`.
const adresses = await vaultCli(["adresses"]);
const ADRESSE = adresses.match(/Porte-monnaie du relais \(Kaspa x402\) : (\S+)/)[1];

const chaine = {
  async getUtxos() { return JSON.parse(await vaultCli(["pieces-porte-monnaie"])); },
  async getUtxo() { return null; },
  async getVirtualDaaScore() { return "0"; },
  async sendTransaction() { throw new Error("le vendeur diffuse la transaction (exact standard-native)"); },
};
const coffre = {
  async recharger(montant) {
    const r = JSON.parse(await vaultCli(["recharger-porte-monnaie", montant.toString()]));
    console.log(`Recharge du porte-monnaie depuis le coffre : ${Number(montant) / 1e8} TKAS, transaction ${r.transactionId}`);
    console.log(`  https://tn10.kaspa.stream/transactions/${r.transactionId}`);
  },
};

// Codec d'adresses : script P2PK lu dans l'offre elle-même n'est pas une source de confiance ;
// on dérive le script de l'adresse avec le relais Rust (même code que la vérification de l'offre).
const codec = {
  scriptPublicKeyForAddress(adresse, reseau) {
    if (reseau !== RESEAU) throw new Error("réseau non pris en charge");
    return spkDepuisAdresse(adresse);
  },
  encodeScriptAddress() { throw new Error("non utilisé"); },
};
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function spkDepuisAdresse(adresse) {
  const G = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  const polymod = (v) => { let c = 1n; for (const d of v) { const c0 = c >> 35n; c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d); for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= G[i]; } return c ^ 1n; };
  const [prefix, corps] = adresse.split(":");
  const vals = [...corps].map((c) => CHARSET.indexOf(c));
  if (prefix !== "kaspatest" || vals.includes(-1) || polymod([...[...prefix].map((c) => c.charCodeAt(0) & 31), 0, ...vals]) !== 0n) throw new Error(`adresse invalide : ${adresse}`);
  let acc = 0, bits = 0; const b = [];
  for (const v of vals.slice(0, -8)) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; b.push((acc >> bits) & 255); } }
  if (b[0] === 0 && b.length === 33) return `000020${Buffer.from(b.slice(1)).toString("hex")}ac`; // P2PK schnorr
  if (b[0] === 8 && b.length === 33) return `0000aa20${Buffer.from(b.slice(1)).toString("hex")}87`; // P2SH
  throw new Error("type d'adresse non pris en charge");
}

const pieces = await chaine.getUtxos();
const fournisseur = new FournisseurCoffre({
  adresse: ADRESSE,
  clePublique: pieces[0]?.scriptPublicKey?.slice(6, 70) ?? (await (async () => {
    // Porte-monnaie vide : la clé publique se lit dans le script dérivé de l'adresse.
    return spkDepuisAdresse(ADRESSE).slice(6, 70);
  })()),
  chaine,
  coffre,
  plafond: 50_000_000n,
  maxParPaiement: 50_000_000n,
  signer: signataireRust({ binaire: VAULT_CLI, args: ["relais-payer"], env: { RELAIS_ORIGINES: ORIGINE, RELAIS_DESTINATAIRES: VENDEUR, RELAIS_MAX: PRIX_MAX.toString() } }),
});

// Les runners GitHub reçoivent aussi des adresses IPv6, que le transport borné refuse par principe.
// On ne lui transmet que les adresses IPv4 ; il vérifie toujours qu'elles sont publiques.
const transport = createNodeBoundedFetch({
  allowedOrigins: [ORIGINE],
  lookup: async (hote) => (await dns.resolve4(hote)).map((address) => ({ address, family: 4 })),
});
// Journal de la tentative payée : statut, en-têtes x402 et corps de la réponse du vendeur.
const fetchJournalise = async (input, init = {}) => {
  const r = await transport.fetch(input, init);
  const h = init.headers ?? {};
  const paye = typeof h.get === "function" ? h.get("payment-signature") : Object.entries(h).find(([k]) => k.toLowerCase() === "payment-signature")?.[1];
  if (paye) {
    let corps = "";
    try { corps = await r.clone().text(); } catch {}
    console.log(`Réponse à la tentative payée : HTTP ${r.status}`);
    for (const [k, v] of r.headers.entries()) if (/payment|x402|retry|content-type/i.test(k)) console.log(`  ${k}: ${k === "payment-required" ? Buffer.from(v, "base64").toString().slice(0, 600) : v.slice(0, 300)}`);
    console.log(`  corps : ${corps.slice(0, 800)}`);
  }
  return r;
};
Object.defineProperty(fetchJournalise, Symbol.for("kaspa-x402:bound-paid-fetch:v1"), { value: true });

const client = new DirectModeClient({
  addressCodec: codec,
  confirmationThreshold: core.TESTNET_10_CONFIRMATION_THRESHOLD,
  fundingProvider: fournisseur,
  store: new MemoryChannelStore(),
  supportedSchemes: ["exact"],
  fundingPolicy: {
    requiredSource: "vault-treasury",
    allowedOrigins: [ORIGINE],
    allowedExactProfiles: ["standard-native"],
    allowedPayTo: [VENDEUR],
    maximumExactAmountSompi: PRIX_MAX.toString(),
  },
  fetch: fetchJournalise,
});

console.log(`Porte-monnaie du relais : ${ADRESSE} (${pieces.reduce((s, u) => s + BigInt(u.amount), 0n)} sompi)`);
// Diagnostic sans paiement : le vendeur répond-il, et que propose-t-il ?
for (const chemin of ["/health", "/canary", "/exact"]) {
  try {
    const r = await fetch(`${ORIGINE}${chemin}`, { redirect: "manual" });
    const offre = r.headers.get("payment-required");
    console.log(`Diagnostic ${chemin} : HTTP ${r.status}${offre ? ` (offre 402 : ${Buffer.from(offre, "base64").toString().slice(0, 300)})` : ""}`);
    if (chemin !== "/exact") console.log(`  ${(await r.text()).slice(0, 500)}`);
  } catch (e) {
    console.log(`Diagnostic ${chemin} : ${e.message} (${e.cause?.code ?? e.cause?.message ?? "?"})`);
  }
}
console.log(`GET ${RESSOURCE}`);
let code = 1;
try {
  const id = `lamaz_relais_testnet_${Date.now()}`;
  const r = await client.paidFetch(RESSOURCE, { paymentIdentifier: id });
  const corps = await r.response.text();
  console.log(`Réponse du vendeur : HTTP ${r.response.status}`);
  console.log(`Corps : ${corps.slice(0, 400)}`);
  const s = r.settlement?.response;
  if (s) {
    console.log(`Règlement : success=${s.success}, transaction ${s.transaction}, montant ${s.amount} sompi, réseau ${s.network}`);
    console.log(`  https://tn10.kaspa.stream/transactions/${s.transaction}`);
  }
  code = r.response.status === 200 && s?.success ? 0 : 1;
} catch (e) {
  let c = e, chaine = [];
  while (c) { chaine.push(`${c.code ? c.code + " " : ""}${c.message}`); c = c.cause; }
  console.log(`Échec : ${chaine.join(" ← ")}`);
} finally {
  await transport.close?.();
}
console.log(code === 0 ? "VERDICT : le vendeur public Kaspa x402 a accepté et réglé le paiement du coffre." : "VERDICT : ÉCHEC");
process.exit(code);

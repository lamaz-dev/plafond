// Juge : fait vérifier un paiement du relais par le code publié de kaspa-x402 (npm, v1.0.1).
//
// Entrée : la sortie de `vault-cli relais-exemple` (fichier en argument, ou entrée standard).
// Chaque contrôle utilise une fonction exportée par @kaspa-x402/core ou @kaspa-x402/covenant ;
// seule la vérification schnorr (BIP-340) passe par @noble/curves, la bibliothèque utilisée par kaspa-x402.
//
// Ce que ce juge ne fait pas : interroger un nœud (UTXO réels, finalité). Cette partie est couverte par
// l'essai sur le testnet-10.

import { readFileSync } from "node:fs";
import * as core from "@kaspa-x402/core";
import * as cov from "@kaspa-x402/covenant";
import { schnorr } from "@noble/curves/secp256k1";

const source = process.argv[2] ? readFileSync(process.argv[2], "utf8") : readFileSync(0, "utf8");
const ex = JSON.parse(source);
const required = ex.paymentRequired;
const payment = ex.paymentPayload;
const accepted = payment.accepted;
const pl = payment.payload;
const tx = JSON.parse(pl.transaction);
const nowMs = Date.parse(ex.referenceTime);

let failures = 0;
function check(name, fn) {
  try {
    const r = fn();
    if (r === true) console.log(`ok    ${name}`);
    else { failures++; console.log(`ECHEC ${name}${r === false ? "" : ` : ${JSON.stringify(r)}`}`); }
  } catch (e) {
    failures++;
    console.log(`ECHEC ${name} : ${e.message}`);
  }
}
const valid = (r) => (r.ok ? true : r.error?.message ?? r);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
// Format d'échange (safe JSON v2) → format de référence des fonctions de @kaspa-x402/covenant
// (même conversion que leur adaptateur : `transactionId` → `txid`, `value` → `amount`).
const ref = (t) => ({
  ...t,
  inputs: t.inputs.map((i) => ({ ...i, previousOutpoint: { txid: i.previousOutpoint.transactionId, index: i.previousOutpoint.index } })),
  outputs: t.outputs.map((o) => ({ amount: o.value, scriptPublicKey: o.scriptPublicKey, covenant: o.covenant })),
});

// 1. Formats x402 v2 et Kaspa (schémas JSON officiels).
check("réponse 402 valide (validatePaymentRequired)", () => valid(core.validatePaymentRequired(required)));
check("offre Kaspa valide (validateKaspaPaymentRequirement)", () => valid(core.validateKaspaPaymentRequirement(accepted)));
check("charge de paiement valide (validatePaymentPayload)", () => valid(core.validatePaymentPayload(payment)));
check("charge Kaspa valide (validateKaspaPayload)", () => valid(core.validateKaspaPayload(pl)));
check("nouvelle tentative cohérente avec la 402 (validatePaymentRetry)", () =>
  valid(core.validatePaymentRetry({ paymentRequired: required, paymentPayload: payment })));

// 2. Transaction : identifiant, forme du profil standard-native, masse.
check("identifiant recalculé = identifiant annoncé (exactV0TransactionId)", () => cov.exactV0TransactionId(ref(tx)) === tx.id);
check("sortie 0 = montant exact vers le script du vendeur", () =>
  tx.outputs[0].value === accepted.amount && tx.outputs[0].scriptPublicKey === accepted.extra.payToScriptPublicKey);
check("au plus une autre sortie, rendue au payeur", () =>
  tx.outputs.length <= 2 && (tx.outputs.length === 1 || tx.outputs[1].scriptPublicKey === tx.inputs[0].utxo.scriptPublicKey));
check("aucun covenant, version 0, payload vide, gas et lockTime nuls", () =>
  tx.version === 0 && tx.outputs.every((o) => o.covenant === null) && tx.payload === "" && tx.gas === "0" && tx.lockTime === "0");
check("payToScriptPublicKey de forme P2PK (la dérivation depuis payTo est contrôlée côté Rust)", () => {
  // Script P2PK : 0x20 <clé x-only> 0xac, version 0.
  const script = accepted.extra.payToScriptPublicKey;
  return script.startsWith("000020") && script.endsWith("ac") && script.length === 2 * (2 + 34);
});
check("masse de stockage engagée = calcul KIP-9 (calculateKaspaStorageMass)", () => {
  const m = cov.calculateKaspaStorageMass({
    inputs: tx.inputs.map((i) => ({ amount: i.utxo.amount, scriptPublicKey: i.utxo.scriptPublicKey })),
    outputs: tx.outputs.map((o) => ({ amount: o.value, scriptPublicKey: o.scriptPublicKey })),
  });
  return m.toString() === tx.storageMass || { calcul: m.toString(), engagée: tx.storageMass };
});
check("frais positifs et bornés (≤ 0,05 KAS)", () => {
  const ins = tx.inputs.reduce((s, i) => s + BigInt(i.utxo.amount), 0n);
  const outs = tx.outputs.reduce((s, o) => s + BigInt(o.value), 0n);
  return ins - outs > 0n && ins - outs <= 5_000_000n;
});

// 3. Signatures de la transaction (empreinte Rusty Kaspa recalculée par kaspa-x402).
tx.inputs.forEach((_, i) =>
  check(`signature de l'entrée ${i} (exactV0SchnorrSignatureEvidence)`, () => {
    const ev = cov.exactV0SchnorrSignatureEvidence(ref(tx), i);
    return schnorr.verify(hex(ev.signature), hex(ev.digest), hex(ev.publicKey));
  }));

// 4. Autorisation de la requête.
const auth = pl.authorization;
const digestInput = {
  network: accepted.network,
  profile: pl.profile,
  transactionId: tx.id,
  paymentOutputIndex: pl.paymentOutputIndex,
  amount: accepted.amount,
  payTo: accepted.payTo,
  payToScriptPublicKey: accepted.extra.payToScriptPublicKey,
  paymentRequirementsHash: core.sha256Hex(core.stableStringify(accepted)),
  requestHash: pl.requestHash,
  paymentIdentifier: payment.extensions["payment-identifier"].info.id,
  inputIndex: auth.inputIndex,
  expiresAt: auth.expiresAt,
};
check("empreinte d'autorisation (exactRequestAuthorizationDigest)", () => core.exactRequestAuthorizationDigest(digestInput) === auth.digest);
check("autorisation signée par la clé de l'entrée payeuse", () => {
  const spk = tx.inputs[auth.inputIndex].utxo.scriptPublicKey; // 0000 20 <x-only> ac
  return schnorr.verify(hex(auth.signature), hex(auth.digest), hex(spk.slice(6, 70)));
});
check("expiration valide à l'heure de référence (exactAuthorizationExpiryError)", () => {
  const err = core.exactAuthorizationExpiryError({ maxTimeoutSeconds: accepted.maxTimeoutSeconds, authorizationExpiresAt: auth.expiresAt, nowMs });
  return err === undefined || err;
});
check("empreinte de la requête = calcul du client de référence", () => {
  const expected = core.sha256Hex(core.stableStringify({
    method: ex.request.method,
    url: ex.request.url,
    body: null,
    paymentRequirementsHash: core.sha256Hex(core.stableStringify(accepted)),
  }));
  return expected === pl.requestHash;
});
check("identifiant de paiement conforme (validatePaymentIdentifierInfo)", () =>
  valid(core.validatePaymentIdentifierInfo(payment.extensions["payment-identifier"].info, payment.extensions["payment-identifier"].schema)));

// 5. Contre-épreuve : le juge doit refuser une charge falsifiée.
const forged = structuredClone(payment);
const ftx = JSON.parse(forged.payload.transaction);
ftx.outputs[0].value = String(BigInt(ftx.outputs[0].value) - 1n);
forged.payload.transaction = JSON.stringify(ftx);
check("contre-épreuve : montant falsifié détecté", () => cov.exactV0TransactionId(ref(ftx)) !== ftx.id);
const forgedAuth = { ...digestInput, amount: "1" };
check("contre-épreuve : autorisation falsifiée détectée", () => core.exactRequestAuthorizationDigest(forgedAuth) !== auth.digest);

console.log(failures === 0 ? "\nVERDICT : paiement accepté par les contrôles publiés de kaspa-x402." : `\nVERDICT : ${failures} contrôle(s) en échec.`);
process.exit(failures === 0 ? 0 : 1);

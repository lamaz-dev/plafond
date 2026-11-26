// Tests hors ligne du fournisseur coffre (relecture du relais, 26 nov. 2026) :
// message en double, demandes simultanées, paiement retenu par un vendeur.
// Lancer : node fournisseur-tests.mjs
import assert from "node:assert/strict";
import { FournisseurCoffre } from "./fournisseur-coffre.mjs";

const ADR = "kaspatest:porte-monnaie";
let n = 0;
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

// Chaîne simulée : les pièces du porte-monnaie ; le coffre y ajoute une pièce à chaque recharge.
function monde({ solde = [], plafond = 100_000_000n, maxParPaiement = 60_000_000n } = {}) {
  const pieces = solde.map((a) => ({ outpoint: { txid: `${(++n).toString(16).padStart(64, "0")}`, index: 0 }, amount: a.toString() }));
  const recharges = [];
  const chaine = {
    async getUtxos() { await attendre(5); return pieces.map((p) => ({ ...p })); },
  };
  const coffre = {
    async recharger(sompi) {
      await attendre(20); // le temps que la recharge soit vue : une course, si elle existe, passe ici
      recharges.push(sompi);
      pieces.push({ outpoint: { txid: `${(++n).toString(16).padStart(64, "0")}`, index: 0 }, amount: sompi.toString() });
    },
  };
  // Signataire simulé : prend les pièces dans l'ordre jusqu'au montant ; chaque appel = une transaction neuve.
  let signatures = 0;
  const signer = async (request, utxos) => {
    await attendre(10);
    signatures++;
    let s = 0n;
    const prises = [];
    for (const u of utxos) { if (s >= BigInt(request.amount) + 600_000n) break; prises.push(u.outpoint); s += BigInt(u.amount); }
    if (s < BigInt(request.amount)) throw new Error("pas assez de pièces");
    return { transactionId: `${(++n).toString(16).padStart(64, "0")}`, inputOutpoints: prises, paymentOutputIndex: 0 };
  };
  const f = new FournisseurCoffre({ adresse: ADR, clePublique: "00", chaine, coffre, plafond, maxParPaiement, signer });
  return { f, pieces, recharges, signatures: () => signatures };
}
const demande = (id, amount, intent = "aa") => ({ attemptId: id, intentHash: intent, profile: "standard-native", amount: amount.toString() });
const entrees = (r) => r.inputOutpoints.map((o) => `${o.txid}:${o.index}`);
let ok = 0;
async function test(nom, fn) { await fn(); ok++; console.log(`ok - ${nom}`); }

await test("message en double : la même tentative envoyée deux fois en même temps donne un seul paiement", async () => {
  const m = monde({ solde: [50_000_000n] });
  const [a, b] = await Promise.all([m.f.payExactTransaction(demande("t1", 10_000_000n)), m.f.payExactTransaction(demande("t1", 10_000_000n))]);
  assert.equal(a.transactionId, b.transactionId);
  assert.equal(m.signatures(), 1);
});

await test("même tentative, termes changés : refusé", async () => {
  const m = monde({ solde: [50_000_000n] });
  await m.f.payExactTransaction(demande("t1", 10_000_000n, "aa"));
  await assert.rejects(m.f.payExactTransaction(demande("t1", 10_000_000n, "bb")), /termes/);
});

await test("deux achats simultanés : jamais les mêmes pièces, porte-monnaie jamais au-delà de son plafond", async () => {
  const m = monde({ solde: [], plafond: 100_000_000n, maxParPaiement: 60_000_000n });
  const [a, b] = await Promise.all([m.f.payExactTransaction(demande("t1", 20_000_000n)), m.f.payExactTransaction(demande("t2", 20_000_000n))]);
  assert.equal(entrees(a).filter((e) => entrees(b).includes(e)).length, 0, "pièces partagées");
  const total = m.pieces.reduce((s, p) => s + BigInt(p.amount), 0n);
  assert.ok(total <= 100_000_000n, `porte-monnaie à ${total} (recharges ${m.recharges})`);
});

await test("paiement retenu par un vendeur : il compte dans le plafond, la recharge suivante est réduite", async () => {
  const m = monde({ solde: [], plafond: 100_000_000n, maxParPaiement: 100_000_000n });
  await m.f.payExactTransaction(demande("t1", 90_000_000n)); // recharge 100, paiement 90 remis puis retenu
  await assert.rejects(m.f.payExactTransaction(demande("t2", 90_000_000n)), /pas encore réglés/);
  const total = m.pieces.reduce((s, p) => s + BigInt(p.amount), 0n);
  assert.ok(total <= 100_000_000n, `porte-monnaie à ${total}`);
  // Le client constate l'absence (expiration) : pièces libérées, le paiement suivant les redépense,
  // ce qui rend inutilisable la transaction retenue.
  await m.f.finalizeExactPaymentAttempt({ attemptId: "t1", outcome: "absent" });
  const r = await m.f.payExactTransaction(demande("t3", 90_000_000n));
  assert.ok(entrees(r).length > 0);
  assert.equal(m.recharges.length, 1, "aucune recharge de plus : les pièces libérées suffisent");
});

await test("une erreur ne bloque pas la file", async () => {
  const m = monde({ solde: [50_000_000n] });
  await assert.rejects(m.f.payExactTransaction({ ...demande("t1", 1n), profile: "autre" }));
  const r = await m.f.payExactTransaction(demande("t2", 10_000_000n));
  assert.ok(r.transactionId);
});

console.log(`${ok} tests du fournisseur coffre réussis`);

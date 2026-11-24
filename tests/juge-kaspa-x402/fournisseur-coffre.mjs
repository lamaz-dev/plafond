// Fournisseur de fonds « vault-treasury » pour @kaspa-x402/client.
//
// L'agent paie les vendeurs kaspa-x402 au format standard (`exact`, standard-native) depuis un petit
// porte-monnaie P2PK. Ce porte-monnaie n'est alimenté QUE par le coffre AgentBudget, et jamais au-delà
// d'un plafond : la dépense de l'agent reste bornée par les règles du covenant.
//
// La construction et la signature de la transaction sont faites par `vault-cli relais-payer` (Rust,
// vérifié contre les vecteurs officiels de kaspa-x402). La clé du porte-monnaie ne passe jamais par ce module.

import { spawn } from "node:child_process";

export const RESEAU = "kaspa:testnet-10";
/** Frais par entrée d'un paiement exact (identiques au relais Rust). */
export const FRAIS_PAR_ENTREE = 300_000n;

/** Montant à verser du coffre au porte-monnaie (même règle que `relais::recharge_necessaire`). */
export function rechargeNecessaire(solde, besoin, plafond, maxParPaiement) {
  if (solde >= besoin) return null;
  if (besoin > plafond) throw new Error(`paiement de ${besoin} sompi supérieur au plafond du porte-monnaie (${plafond})`);
  const r = plafond - solde < maxParPaiement ? plafond - solde : maxParPaiement;
  if (solde + r < besoin) throw new Error("recharge impossible en un seul paiement du coffre");
  return r;
}

/** Signataire : appelle `vault-cli relais-payer` et renvoie un ExactTransactionPaymentResult. */
export function signataireRust({ binaire, args = ["relais-payer"], env = {} }) {
  return (request, utxos) =>
    new Promise((resolve, reject) => {
      const p = spawn(binaire, args, { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      let err = "";
      p.stdout.on("data", (d) => (out += d));
      p.stderr.on("data", (d) => (err += d));
      p.on("error", reject);
      p.on("close", (code) => {
        if (code !== 0) return reject(new Error(`relais-payer : ${err.trim() || `code ${code}`}`));
        try { resolve(JSON.parse(out)); } catch (e) { reject(e); }
      });
      p.stdin.end(JSON.stringify({ request, utxos }));
    });
}

const cle = (op) => `${op.txid.toLowerCase()}:${op.index}`;
const nonPrisEnCharge = (quoi) => () => {
  throw new Error(`${quoi} : non pris en charge par le fournisseur coffre (exact standard-native uniquement)`);
};

export class FournisseurCoffre {
  networkId = RESEAU;
  sourceKind = "vault-treasury";
  #tentatives = new Map();
  #reservees = new Map(); // outpoint → attemptId

  /**
   * @param {object} o
   * @param {string} o.adresse       adresse P2PK du porte-monnaie de l'agent
   * @param {string} o.clePublique   clé x-only du porte-monnaie (hex)
   * @param {object} o.chaine        { getUtxos(addresses), getUtxo(outpoint), getVirtualDaaScore(), sendTransaction(tx) }
   * @param {object} o.coffre        { recharger(sompi: bigint, adresse: string): Promise<void> } — paiement du coffre vers le porte-monnaie
   * @param {bigint} o.plafond       solde maximal du porte-monnaie
   * @param {bigint} o.maxParPaiement plafond par paiement du coffre
   * @param {Function} o.signer      (request, utxos) => Promise<ExactTransactionPaymentResult>
   */
  constructor({ adresse, clePublique, chaine, coffre, plafond, maxParPaiement, signer }) {
    Object.assign(this, { adresse, clePublique, chaine, coffre, plafond, maxParPaiement, signer });
  }

  async getPublicIdentity() {
    return { address: this.adresse, publicKey: this.clePublique };
  }

  async #piecesLibres() {
    const toutes = await this.chaine.getUtxos([this.adresse]);
    return toutes.filter((u) => !u.covenantId && !this.#reservees.has(cle(u.outpoint)));
  }

  async payExactTransaction(request) {
    // Une tentative = un seul artefact signé ; un changement de termes est refusé avant toute signature.
    const id = request.attemptId.toLowerCase();
    const deja = this.#tentatives.get(id);
    if (deja) {
      if (deja.intentHash !== request.intentHash.toLowerCase()) throw new Error("termes du paiement modifiés pour une même tentative");
      return structuredClone(deja.resultat);
    }
    if (request.profile !== "standard-native") throw new Error("le relais ne paie qu'en standard-native");

    let pieces = await this.#piecesLibres();
    const solde = pieces.reduce((s, u) => s + BigInt(u.amount), 0n);
    const besoin = BigInt(request.amount) + 2n * FRAIS_PAR_ENTREE; // marge pour deux entrées
    const recharge = rechargeNecessaire(solde, besoin, this.plafond, this.maxParPaiement);
    if (recharge !== null) {
      await this.coffre.recharger(recharge, this.adresse);
      pieces = await this.#piecesLibres();
    }
    const resultat = await this.signer(request, pieces);
    // Traçabilité pour le vendeur : heure UTC, tentative, transaction et pièces dépensées.
    const tx = {};
    console.log(`Transaction de paiement signée ${new Date().toISOString()} : tentative ${id}, transaction ${tx.id ?? resultat.transactionId ?? "?"}, entrées ${resultat.inputOutpoints.map((o) => `${o.txid ?? o.transactionId}:${o.index}`).join(", ")}`);
    for (const op of resultat.inputOutpoints) this.#reservees.set(cle(op), id);
    this.#tentatives.set(id, { intentHash: request.intentHash.toLowerCase(), resultat: structuredClone(resultat) });
    return resultat;
  }

  async finalizeExactPaymentAttempt({ attemptId, outcome }) {
    // Pièces libérées seulement sur preuve d'absence ; acceptées, elles sont dépensées pour de bon.
    const id = attemptId.toLowerCase();
    if (outcome === "absent") for (const [k, v] of this.#reservees) if (v === id) this.#reservees.delete(k);
  }

  getUtxos(addresses) { return this.chaine.getUtxos(addresses); }
  getUtxo(outpoint) { return this.chaine.getUtxo(outpoint); }
  getVirtualDaaScore() { return this.chaine.getVirtualDaaScore(); }
  sendTransaction(transaction) { return this.chaine.sendTransaction(transaction); }
  async estimateFees() { return { feeSompi: FRAIS_PAR_ENTREE.toString() }; }

  prepareEscrowDeposit = nonPrisEnCharge("prepareEscrowDeposit");
  prepareEscrowTopUp = nonPrisEnCharge("prepareEscrowTopUp");
  async verifyCovenantGenesis() { return null; }
  async verifyCovenantTopUp() { return null; }
}

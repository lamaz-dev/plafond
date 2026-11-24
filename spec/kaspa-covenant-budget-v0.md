# Kaspa x402 — `covenant-budget` profile (draft v0)

> **Résumé en français.** Ce profil permet à un agent IA de payer un service x402
> directement depuis un coffre AgentBudget (covenant Kaspa), sans portefeuille
> intermédiaire. Le vendeur vérifie trois choses qu'aucun portefeuille d'agent classique
> ne permet : (1) le coffre est authentique (son script, recompilé à partir de paramètres
> publics, correspond à la sortie sur la chaîne), (2) le coffre est solvable (son budget
> restant, lisible dans son état, couvre le prix) et (3) le paiement est autorisé pour
> cette requête par la clé agent inscrite dans le coffre. Les limites de dépense restent
> imposées par le réseau Kaspa lui-même.

Status: draft, testnet-10 only. Companion to the Kaspa x402 `exact` binding
(`kaspa-exact-v2`). Reference implementation: `cli/src/x402.rs` in this repository.

## 1. Motivation

The `standard-native` profile of `kaspa-exact-v2` accepts only standard Schnorr P2PK
inputs with zero lock time. An agent that pays from a spending-limited covenant must
therefore move funds to a hot wallet first, where the limits no longer apply.

`covenant-budget` lets the payment come straight from an AgentBudget covenant, so the
spending limits (per-payment cap, continuously refilled budget, optional allowlist) are
enforced by consensus on every merchant payment, and adds merchant-side guarantees that
account-based agent wallets cannot offer.

## 2. Identifiers

```json
{
  "scheme": "exact",
  "network": "kaspa:testnet-10",
  "asset": "KAS",
  "extra": {
    "binding": "kaspa-covenant-budget-v0",
    "profile": "covenant-budget",
    "paymentFlow": "upfront",
    "finality": "accepted",
    "vaultTemplate": "plafond-coeur-v0.6"
  }
}
```

`vaultTemplate` names the covenant source the merchant recompiles against
(`contracts/coeur.sil`, the stateless core v0.6). A merchant MAY list several templates by
offering several `accepts` entries. The previous template `agent-budget-v0.5.1`
(`contracts/agent_budget.sil`) remains valid for existing vaults. Merchants MUST NOT offer or
accept `agent-budget-v0.4` or `agent-budget-v0.5`: v0.4 lets an idle agent bank refill time (up
to 3 × capacity in one period, threat model R34) and v0.5 accepts hostile parameters (R33).

## 3. Transport

Unchanged x402 v2 HTTP transport: `402` with `PAYMENT-REQUIRED`, retry with
`PAYMENT-SIGNATURE`, success with `PAYMENT-RESPONSE`, all base64 JSON. Clients MUST NOT
follow redirects.

## 4. PaymentPayload

```json
{
  "x402Version": 2,
  "accepted": { "...": "the selected requirements, unchanged" },
  "payload": {
    "type": "covenant-budget-transaction",
    "profile": "covenant-budget",
    "transaction": "<hex borsh-encoded signed Kaspa transaction>",
    "vault": {
      "params": {
        "owner": "<x-only hex>", "agent": "<x-only hex>",
        "capacite": 50000000, "periode": 5143
      },
      "outpoint": { "txid": "<vault coin txid>", "index": 1 }
    },
    "requestHash": "<hex blake2b-256(personal='x402cov-request', 'GET <url>')>",
    "authorization": {
      "version": "x402cov-auth-v0",
      "expiresAt": 1795012345,
      "signature": "<hex 64-byte Schnorr signature>"
    }
  }
}
```

## 5. Transaction shape

```text
input[0]          = a coin of the vault, named by payload.vault.outpoint (entry `pay`)
input[0].sequence = relative lock ≥ ceil(spent × periode / capacite), spent = price + fee
output[0]         = merchant payTo script, value = accepted.amount
output[1]         = the rest, back to the same vault address (enforced by the covenant)
```

Exactly one input and two outputs; the covenant rejects anything else. The network itself
rejects the transaction until the coin is as old as the announced lock (relative lock,
`check_sequence_lock`), so the agent supplies no time value at all.

## 6. Verification (merchant)

The merchant MUST, in this order, and MUST NOT broadcast before steps 1–4 succeed:

1. **Terms.** `accepted` equals the offered requirements.
2. **Authentic vault.** Recompile the `vaultTemplate` source with `vault.params`;
   derive the P2SH script public key; the outpoint MUST exist, confirmed, under that
   script, and output 1 MUST pay back to it. The script never changes, so the address is
   the vault's identity: no lineage to follow. Any lie about the parameters (larger budget,
   other agent key) yields a different script and fails here.
3. **Solvency.** With `age` = current virtual DAA score − the coin's DAA score and
   `spent` = coin value − output 1: `spent ≤ capacite`, the input's sequence has bit 63 clear
   and `sequence & 0xffffffff ≥ ceil(spent × periode / capacite)`, and that delay ≤ `age`.
4. **Transaction.** One input spending the vault outpoint; two outputs; output 0 pays
   exactly `amount` to `payTo`.
5. **Authorization.** `requestHash` matches the request; `expiresAt` not passed;
   `signature` verifies under the vault's `agent` key over
   `blake2b-256(personal='x402cov-auth-v0', "<txid>|<requestHash>|<payTo>|<amount>|<expiresAt>")`,
   where `txid` is recomputed from the transaction.
6. **Settlement.** Broadcast; serve the resource only once output 0 is accepted by the
   network (`finality: accepted`).

## 7. SettlementResponse

As in `kaspa-exact-v2`, with
`extensions.kaspa = { "binding": "kaspa-covenant-budget-v0", "profile": "covenant-budget",
"finality": "accepted", "paymentOutputIndex": 0 }` and `payer` = the vault address.

## 8. Security notes

- Steps 2–3 run before any broadcast: an insolvent or fake vault costs the merchant no
  on-chain interaction.
- The covenant is the last line of defence: even a merchant that skips step 3 cannot
  receive more than the vault allows.
- Concurrency: one vault coin pays one request, then waits in proportion to what it spent.
  For parallel or frequent requests, the owner deposits several coins, or the agent pays an
  ardoise (off-chain vouchers) from the vault.
- Coins sent to the vault address by anyone are spendable by the agent at the same rate. This
  is harmless for the owner (it is the sender's money) and is counted by the risk engine.
- The core v0.6 covenant is a prototype and has not been audited.

### 8b. Operational notes

Found in the external review of 23 Nov 2026 (threat model R41–R46). None lets anyone take funds
beyond the loss bound; each one makes a correct integration fail or cost more than expected.

- **Retries.** A client that times out MUST resend the *same* signed transaction, never sign a
  new one from the same lane: the second would conflict with the first (one UTXO, one spend) and
  the client could not tell which one paid. Merchants SHOULD treat a repeated `txid` as the same
  payment (idempotent settlement).
- **Lock margin.** The client SHOULD wait until the coin is a little older than the announced
  lock (the tool uses 20 DAA, about 2 s): a node slightly behind would otherwise reject it.
- **Allowlist and escrow.** A vault with a payee allowlist can pay an escrow only if the escrow
  script is in the list. Escrow scripts change with every order, so in practice an allowlisted
  vault cannot use 9c; choose one or the other per lane.
- **Refund destination.** Escrow refunds go to the owner's address (`refundSpkHash`), not back to
  the vault: they leave the budget for good. An owner who wants the money back in the budget
  refills the vault by sending it a new coin. Funds sent by mistake to the vault address are
  spendable by the agent at the vault's rate until the owner sweeps them with `ownerControl`.
- **Fees.** Whoever builds a valid spend chooses the fee. In the core v0.6 the fee is counted in
  `spent`, so it consumes the budget like a payment and the loss bound holds whatever it is.
  Escrow `claim` and `refund` keep their `maxFee`.
- **Small coins.** A vault coin worth less than about 0.08 KAS can no longer pay (KIP-9 storage
  mass, 9b; 0.125 KAS for v0.5.1 lanes); the owner sweeps it.

## 9. Assets

`vault.params.asset` names the budget asset and MUST equal `accepted.asset`.

| Asset | Status |
|---|---|
| `KAS` | Supported (template `plafond-coeur-v0.6`; `agent-budget-v0.5.1` for existing vaults). |
| `KSD` | Reserved for Kaspa Dollar, the proposed KAS-collateralised stablecoin with a miner-voted price feed. A KSD vault template will compose with the KSD token covenant once its standard is published: same token covenant id in and out, budget counted in token units, a separate KAS UTXO for fees. |

Intermediate step under study: a KAS-settled vault whose budget is denominated in dollars,
converted at the miner-attested KAS price once that oracle is live.

## 9b. Physical limits (KIP-9 storage mass)

The vault continuation output carries a P2SH script (35 bytes) **and** a covenant id (32 bytes),
so it occupies 2 storage units (plurality 2) and weighs `C · 4 / value` in the KIP-9 formula,
with `C = 10^12`. Measured with the consensus mass calculator on real vault transactions:

| Quantity | Value |
|---|---|
| Compute mass of a payment (full vault, 3-entry allowlist) | 3 578 g |
| Transient mass | 3 392 g |
| Storage mass, 0.2 KAS payment from a 5 KAS vault | 50 359 g |
| Network limit on storage mass (measured on testnet-10, 2026-11-18) | 500 000 g |
| Smallest payment from a large vault | ≈ 0.02 KAS (`C / amount ≤ 500 000`) |
| Survival floor of a lane (fee 0.015 KAS) | ≈ 0.125 KAS |

Empirical check (testnet-10, run 8): a 0.05 KAS payment (≈ 200 000 g of storage mass) was accepted; a 0.01 KAS payment was rejected with `transaction storage mass of 1000055 is larger than max allowed size of 500000`, exactly the value our calculator gives. The relay fee depends on compute and transient mass only, not on storage mass; under congestion a high-storage transaction may still rank lower in block templates.

Consequences for merchants: offers below 0.02 KAS cannot be settled one-by-one with this profile
(true micro-payments need aggregation, out of scope for v0). Clients MUST compute the mass before
signing and refuse non-standard transactions. A lane below the floor is recovered by the owner
(`ownerControl`, possibly with an extra owner input and a single output).

## 9c. Delivery escrow (pay-on-delivery extension)

A payment MAY target a `DeliveryEscrow` v0.3 script instead of the merchant address: the merchant
claims with a verifier signature over
`blake2b(requestHash || resultHash || escrowTxid || escrowIndex)` (index on 4 bytes,
little-endian), so a proof pays exactly one escrow output and cannot be replayed on a second escrow
for the same order (R40, fixed in v0.3); the owner's refund address recovers the funds after
`timeoutDaa`. The verifier therefore signs after the escrow is funded. Escrows with
`timeoutDaa ≤ 0` or `maxFee < 0` can never pay the merchant (refused by the script).

- Merchants MUST refuse escrows whose `timeoutDaa` is below their minimum (recommended:
  ≥ 36 000 DAA, about one hour at 10 BPS) and MUST claim as soon as the proof is available.
- After the timeout, both `claim` and `refund` are valid: Kaspa scripts can express "after"
  (CSV) but not "before", so the first accepted transaction wins. This race is documented, not
  a bug (threat model R22).
- The escrow output has no covenant id: plurality 1, same mass rules as a plain payment.

## 10. Open questions for the Kaspa x402 maintainers

- Should `vaultTemplate` be identified by a template hash rather than a name?
- Should the transaction use the `kaspa-sdk-safe-json-v2.0.0` encoding instead of borsh?
- Should the authorization digest reuse the `kaspa-exact-v2` digest construction?

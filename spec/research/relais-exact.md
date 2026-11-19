# Research note: paying Kaspa x402 `exact` vendors from an AgentBudget vault (relay)

*Status: implemented in the lab repository, offline. Not yet tried on testnet-10. Not part of the reviewed v0.1.0 contracts.*

## Problem

[Kaspa x402](https://github.com/elldeeone/kaspa-x402) (v1.0.1, MIT) is the payment standard other Kaspa
projects build on. Its `exact` binding (`kaspa-exact-v2`, profile `standard-native`) accepts only standard
Schnorr P2PK inputs and forbids output covenants; KIP-20 covenant payers are listed under *Exclusions*.
A payment spent directly from an AgentBudget vault (a P2SH covenant input with a covenant continuation)
is therefore rejected by every `exact` vendor.

## Design

```text
AgentBudget vault ──(vault `pay` entry, covenant rules)──▶ agent wallet (P2PK, capped balance)
agent wallet ──(exact, standard-native)──▶ Kaspa x402 vendor
```

- The agent wallet is funded **only** by the vault, and never above a cap (default: one maximal vault
  payment). Everything the agent can spend has left the vault under the covenant rules: per-payment cap,
  refilling budget, fees counted against the budget.
- The wallet pays vendors in the unchanged standard format, so any `exact` vendor accepts it.
- Refill rule (`relais::recharge_necessaire`, mirrored in `fournisseur-coffre.mjs`): when the free balance
  cannot cover `amount + fees`, the vault pays `min(cap − balance, maxPerPayment)` to the wallet.

### What the relay keeps and what it loses

| Property | Direct vault payment | Relay |
| --- | --- | --- |
| Total agent spending bounded by the vault budget | yes | yes |
| Per-payment cap | enforced by the network | enforced by the network on refills; on the final payment, bounded by the wallet cap |
| Allowlist of vendors | enforced by the network | **not enforced by the network**, only by the client funding policy |
| Funds at risk if the agent key leaks | the budget rate | the budget rate + the wallet balance (≤ cap) |
| Accepted by existing Kaspa x402 vendors | no | yes |

The missing property (network-enforced allowlist on the final payment) is the argument for a future
*covenant payer* profile in the standard, where the vault pays the vendor directly.

## Implementation

- `cli/src/relais.rs`: canonical JSON, requirements and request hashes, `kaspa-sdk-safe-json-v2.0.0`
  encoding, version-0 transaction, request authorization (`kaspa-x402-exact-request-authorization-v2`),
  offer checks before any signature (network, profile, flow, finality, `payToScriptPublicKey` derived from
  `payTo`, amount cap, origin and vendor allowlists), KIP-9 storage mass commitment.
- `vault-cli relais-payer`: `payExactTransaction` for `@kaspa-x402/client` (reads an
  `ExactTransactionPaymentRequest` and wallet UTXOs, writes an `ExactTransactionPaymentResult`; never broadcasts).
- `tests/juge-kaspa-x402/fournisseur-coffre.mjs`: `FundingProvider` with `sourceKind: "vault-treasury"`
  (a funding source kind the Kaspa x402 client already defines): idempotent attempts, input reservation,
  refill from the vault before signing.

## Evidence

1. **Official vectors** (`cli/vecteurs/kaspa-x402/`, copied unchanged at commit `8d575de`): transaction id,
   requirements hash, authorization preimage and digest, and both signatures match byte for byte
   (`cargo test relais`).
2. **Published validators** (`node juge.mjs`): 18 checks with functions exported by `@kaspa-x402/core`
   and `@kaspa-x402/covenant` 1.0.1 accept a relay payment; two forged variants are detected.
3. **End to end** (`node bout-en-bout.mjs`): the unmodified `DirectModeClient` and `DirectModeServer`
   exchange 402 → signed retry → broadcast → 200 four times; the fifth call is stopped because the vault
   budget is exhausted. The vendor verifier performs real checks (transaction id, every input signature,
   authorization digest and signature, inputs present in the chain state).

## Limits

- The chain and the vault are simulated in step 3 (in-memory UTXO set, JS model of the AgentBudget rules).
  The vault rules themselves are covered by the testnet runs and the fuzzing campaign of the public repository.
- The full consensus verifier of Kaspa x402 (`@kaspa-x402/adapters`, pinned Rust harness) is not published
  on npm and was not run.
- Next step: testnet-10 — refill from the deployed vault, then pay a Kaspa x402 demo vendor.

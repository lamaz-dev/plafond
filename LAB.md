# kaspa-agent-vault-lab (private)

Private workspace for work that must not touch the publicly reviewed contracts while the review and the
bug bounty run.

Base: public repository `lamaz-dev/Kaspa-agent-vault` at v0.1.0 (commit dc005d8).

## Tracks

0. **Relay to Kaspa x402 `exact`** (decided 2026-11-19: become the budget and trust layer of the existing rails),
   see `spec/research/relais-exact.md`.
   - [x] `cli/src/relais.rs` and `vault-cli relais-payer`, checked against the official vectors.
   - [x] Judge with the published validators (`tests/juge-kaspa-x402/juge.mjs`).
   - [x] End to end with the unmodified Kaspa x402 client and server (`tests/juge-kaspa-x402/bout-en-bout.mjs`).
   - [ ] Testnet-10: refill from the deployed vault, pay a Kaspa x402 demo vendor.
   - [ ] Proposal to Kaspa x402: a covenant payer profile (vault pays the vendor directly).
1. **v0.5 micropayments** (on hold: Kaspa x402 already ships additive `exact`; reuse it through the relay): payments added to a vendor's KIP-10 additive UTXO (KIP-9 mutual transaction),
   see `spec/research/micropayments-additive.md`.
   - [ ] `contracts/additive_receiver.sil`: anyone may add at least `minIncrement` to the vendor UTXO; only the vendor key withdraws.
   - [ ] AgentBudget v0.5: `payAdditive` path with exactly two inputs at fixed indexes (vault 0, vendor 1) and two outputs (vendor grown by `amount`, vault continuation).
   - [ ] Tests and fuzzing: wrong vendor UTXO, swapped inputs, increment below threshold, vendor output not matching.
   - [ ] Testnet: a 0.001 TKAS payment accepted.
2. **App prototype**: owner app (create vault, live spending, top up, freeze).
3. **KAPI**: dropped as a separate marketplace and MCP server (k402 and Kaspa x402 cover them); integration instead.

Merging back to the public repository happens only after the bug bounty, through a new audited version.

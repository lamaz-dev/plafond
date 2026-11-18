# kaspa-agent-vault-lab (private)

Private workspace for work that must not touch the publicly reviewed contracts while the review and the
bug bounty run.

Base: public repository `lamaz-dev/Kaspa-agent-vault` at v0.1.0 (commit dc005d8).

## Tracks

1. **v0.5 micropayments**: payments added to a vendor's KIP-10 additive UTXO (KIP-9 mutual transaction),
   see `spec/research/micropayments-additive.md`.
   - [ ] `contracts/additive_receiver.sil`: anyone may add at least `minIncrement` to the vendor UTXO; only the vendor key withdraws.
   - [ ] AgentBudget v0.5: `payAdditive` path with exactly two inputs at fixed indexes (vault 0, vendor 1) and two outputs (vendor grown by `amount`, vault continuation).
   - [ ] Tests and fuzzing: wrong vendor UTXO, swapped inputs, increment below threshold, vendor output not matching.
   - [ ] Testnet: a 0.001 TKAS payment accepted.
2. **App prototype**: owner app (create vault, live spending, top up, freeze).
3. **KAPI**: MCP server and vendor middleware (later).

Merging back to the public repository happens only after the bug bounty, through a new audited version.

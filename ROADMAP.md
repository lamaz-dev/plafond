# Plafond roadmap

Plafond is an unaudited prototype on Kaspa testnet-10. This page says what is done, what comes next,
and where help is welcome. Feedback and test reports are the most useful contribution right now:
open an issue, or report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Done

- Core v0.7: a 289-byte stateless covenant. The agent waits in proportion to what it spends (relative lock),
  the loss over time `t` stays under `C × t / R`, and even the owner key can only send funds back to the vault
  or to a return address fixed at creation ([proof](spec/borne-de-perte-v0.6.md)).
- Enterprise gateway ([GATEWAY.md](GATEWAY.md)): one entry point for many agents, no owner key, API keys
  stored as fingerprints, persistent emergency stop, hash-chained audit log.
- Race tests on testnet-10, agent keys encrypted by the owner key, a real x402 payment through the
  kaspa-x402 relay, and a trial mode in the console (vault and return addresses in one click).
- AgentBudget v0.5.1 (covenant budget: refilling allowance, per-payment cap, fees inside the budget,
  owner kill switch) and DeliveryEscrow v0.3, with the loss bound proven and tested against the real
  Kaspa script engine ([proof](spec/borne-de-perte.md)).
- One-command demo on testnet-10 ([DEMO.md](DEMO.md)): 7 of 7 steps verified on the network, including an
  over-budget payment rejected by the network itself ([report](spec/demo-testnet-2026-11-22.md)).
- Survival mode: the owner finds and freezes a vault from a Kaspa node alone, without any indexer or server.
- Owner console (local web page): treasury, agents, API secrets encrypted per agent, emergency stop.
- Relay to Kaspa x402 `exact`: checked against the official vectors and the published validators.

## Next

1. **Gateway, enterprise track** (security first):
   - pay public kaspa-x402 `exact` vendors through the gateway itself, not only through the relay;
   - anchor the head of the audit chain on Kaspa at regular intervals, so the log is tamper-evident
     without trusting any third party;
   - per-agent spending reports for finance teams, and an export for SIEM tools.
2. **External testers.** Run the demo on other machines and agents; fix what breaks. English messages in the demo script.
3. **Faster console refresh** (it currently re-reads the chain for each older agent).
4. **Human security audit** of the contracts before any mainnet use.
5. **Mainnet deployment** after the audit. Covenants are already live on Kaspa mainnet (Toccata, June 30, 2026); the gate is our own audit, not the network.
6. **Covenant payer profile for Kaspa x402**: the vault pays the vendor directly (proposal to be discussed with
   the Kaspa x402 maintainers).

## On hold

- Micropayments into a vendor's additive UTXO (KIP-9 mutual transaction): Kaspa x402 `exact` already covers
  the need; see [`spec/research/micropayments-additive.md`](spec/research/micropayments-additive.md).

## Help wanted

- Builders running AI agents who want to try Plafond on testnet and tell us what is missing.
- Reviewers of the SilverScript contracts: see [BUG-BOUNTY.md](BUG-BOUNTY.md) and [SECURITY.md](SECURITY.md).

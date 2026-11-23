<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/plafond-logo-transparent.png">
  <img src="docs/assets/plafond-logo-transparent-clair.png" alt="Plafond" width="360">
</picture>
</p>

<h3 align="center">Give your agents a budget, not your whole treasury.</h3>

<p align="center">Even if it's hacked, an agent can't exceed its limit: the Kaspa network enforces it.</p>

<p align="center"><a href="https://lamaz-dev.github.io/plafond/">Website</a> · <a href="DEMO.md">Run the demo</a> · <a href="ROADMAP.md">Roadmap</a> · <a href="SECURITY.md">Security</a></p>

# Plafond

Covenant-enforced spending budgets for AI agents on Kaspa L1, written in SilverScript. *Plafond* is French for "ceiling". The project was previously called `kaspa-agent-vault`.

*English · [Français](README.fr.md)*

**Status**

- ✅ testnet-10
- ✅ loss bound proven on paper and verified by automated tests against the real Kaspa script engine ([proof](spec/borne-de-perte.md))
- ✅ reproducible in one command: `./verify-proof.sh`
- ✅ automated CI on every push, long fuzzing campaign every week
- ⚠️ not independently reviewed, not audited
- ⚠️ no mainnet deployment; do not use with real funds

Security advisories: [v0.4 rate-limit flaw, fixed in v0.5](spec/advisories/2026-11-20-v0.4-temps-mis-de-cote.md) · [findings of the first independent review, fixed in v0.5.1](spec/advisories/2026-11-20-v0.5-relecture-independante.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Overview

An agent pays for its services on its own (HTTP 402 / x402), but it cannot exceed the budget set by its
owner: the limit is enforced by a covenant, so the network rejects an overspend even if the agent's keys
and software are compromised.

The repository contains two contracts and a demo tool:

- [`contracts/agent_budget.sil`](contracts/agent_budget.sil) (AgentBudget v0.5.1): a token-bucket budget
  refilled from the DAA score at which the network recorded the vault, a per-payment cap, fees counted inside the budget, an optional payee allowlist,
  one KIP-20 lineage per vault, single-input spends with an empty payload, and an owner override.
- [`contracts/delivery_escrow.sil`](contracts/delivery_escrow.sil) (DeliveryEscrow v0.2): pay on delivery.
  The vendor claims with a verifier's Schnorr signature over `blake2b(requestHash ‖ resultHash)`; without
  it, anyone can refund the owner after a relative timeout.
- [`cli/`](cli/): deploy, pay, escrow and a demo x402 vendor on testnet-10.

The x402 payment profile used by the vendor is specified in
[`spec/kaspa-covenant-budget-v0.md`](spec/kaspa-covenant-budget-v0.md) (draft).

## Build & Test

The toolchain is pinned in `cli/rust-toolchain.toml`.

```bash
cd cli
cargo test --release --locked
```

This runs the tool tests, including stateful property-based tests (proptest) that execute every
transaction with `kaspa-txscript` and compare the result with a reference model. For a longer run:

```bash
FUZZ_CASES=5000 cargo test --release --locked fuzz
```

Contract tests run against the pinned SilverScript compiler:

```bash
git clone https://github.com/kaspanet/silverscript /tmp/silverscript
git -C /tmp/silverscript checkout 443d519e6688fa03d24c69432763b13e6abe4486
cp tests/*.rs contracts/*.sil /tmp/silverscript/silverscript-lang/tests/
cd /tmp/silverscript
cargo test --release -p silverscript-lang --test agent_budget_tests --test delivery_escrow_tests
```

## Reproducible bytecode

```bash
cd cli
cargo build --release --locked
./target/release/vault-cli empreintes | diff - ../contracts/EMPREINTES.txt
```

CI runs this check on every push.

## Testnet-10

Commands are run by GitHub Actions from [`testnet/commande.txt`](testnet/commande.txt) and logged in
[`testnet/journal.md`](testnet/journal.md). The log includes, among others:

- payments above the per-payment cap ([L83](testnet/journal.md#L83)) and above the remaining budget
  ([L104](testnet/journal.md#L104)) rejected by script verification;
- a forged delivery proof rejected ([L292](testnet/journal.md#L292)), an early refund rejected by the
  sequence lock ([L312](testnet/journal.md#L312)) and accepted after the timeout;
- a 0.01 TKAS payment rejected with a storage mass of 1,000,055 grams, Kaspa's mass unit ([L337](testnet/journal.md#L337)),
  the value computed by `cli/src/masse.rs`. The smallest payment from a vault is about 0.02 KAS.

The CLI prints its messages in French.

## Documentation

- [spec/threat-model.md](spec/threat-model.md): risks, mitigations and the tests covering them.
- [spec/invariants.md](spec/invariants.md): invariants and the property-based tests.
- [spec/pre-audit.md](spec/pre-audit.md): scope, transaction layouts, consensus assumptions, open questions.
- [BUG-BOUNTY.md](BUG-BOUNTY.md): rules for the planned bounty.

## License

ISC, see [LICENSE](LICENSE).

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/plafond-logo-transparent.png">
  <img src="docs/assets/plafond-logo-transparent-clair.png" alt="Plafond" width="360">
</picture>
</p>

<h3 align="center">What is your worst case?</h3>

<p align="center">Plafond tells you how much your AI agents can lose at most, right now and over the next 24 hours, and the Kaspa network enforces it, even if an agent is hacked.</p>

<p align="center"><a href="https://lamaz-dev.github.io/plafond/">Website</a> · <a href="https://github.com/lamaz-dev/plafond/releases/latest">Download</a> · <a href="GATEWAY.md">Gateway</a> · <a href="DEMO.md">Run the demo</a> · <a href="ROADMAP.md">Roadmap</a> · <a href="SECURITY.md">Security</a></p>

# Plafond

A risk engine for AI agents, enforced by Kaspa covenants. *Plafond* is French for "ceiling". The project was previously called `kaspa-agent-vault`.

Agents will only be trusted with money at scale if their financial exposure is measurable, verifiable and guaranteed. Plafond answers one question at all times, in four figures:

| | |
|---|---|
| **Maximum loss now** | what could leave if every agent turned hostile this second |
| **Maximum loss over 24 h** | the same, over the next 24 hours |
| **Covered** | what the network itself enforces |
| **Not covered** | what the guarantee does not reach, said plainly |

The budgets, vaults and payment modes underneath are the means; the guaranteed worst case is the product ([risk engine spec](spec/moteur-de-risque.md)).

*English · [Français](README.fr.md)*

**Status**

- ✅ testnet-10
- ✅ **stateless core v0.7**: 289 bytes, 5 parameters, one rule for the agent (wait in proportion to what you spend), enforced by the network's relative lock ([contract](contracts/archive/coeur-v0.7.sil))
- next: **keyless refill airlock with a vault lineage** (proven and tested offline, not deployed yet): core v0.9.1 (577 bytes) and a 227-byte airlock address. The vault is a KIP-20 lineage of coins whose count is fixed at creation and can never grow, so the cap holds for the whole vault on any window, even under active attack; money sent to the airlock can only top up a coin of that lineage or go back to the return address, and a dust coin sent to the vault address can neither receive a deposit nor be spent by the agent. v0.9.1 adds one entry, a partial withdrawal: the owner takes part of a coin back to the return address without closing the vault, and the fees of that withdrawal are rate-limited like an agent payment, so a stolen owner key cannot burn the vault in fees ([core v0.9.1](contracts/coeur.sil), [airlock](contracts/sas.sil), [proof](spec/borne-de-perte-v0.9.md), red-team notes: [lineage](spec/red-team/lignee-2026-11-27.md), [partial withdrawal](spec/red-team/retrait-2026-11-27.md); [core v0.9](contracts/archive/coeur-v0.9.sil) archived unchanged; previous step without lineage: [core v0.8](contracts/archive/coeur-v0.8.sil), [note](spec/red-team/sas-2026-11-27.md))
- ✅ **return address**: even with the owner's key, vault funds can only go back to the vault or to the return address chosen at creation (by default the owner's treasury; optionally a Ledger, multisig or custodian address)
- ✅ **curve promised at creation**: a mandate's total loss never exceeds `C × t / R`, capped at its capital, whatever the agent does; proven on paper and verified by tests against the real Kaspa script engine ([proof, in French](spec/borne-de-perte-v0.6.md), [comparison with v0.5.1](spec/comparaison-v0.5.1-v0.6.md))
- ✅ reproducible in one command: `./verify-proof.sh`
- ✅ automated CI on every push, long fuzzing campaign every week
- ✅ **enterprise gateway**: one entry point for many agents, no owner key, API keys stored as fingerprints, persistent emergency stop, hash-chained audit log ([GATEWAY.md](GATEWAY.md))
- ⚠️ not independently reviewed, not audited
- ⚠️ no mainnet deployment; do not use with real funds

History: up to v0.5.1 the vault was a stateful token bucket with a KIP-20 lineage ([v0.5.1 proof](spec/borne-de-perte.md)); the tool can still freeze such vaults. Security advisories: [v0.4 rate-limit flaw, fixed in v0.5](spec/advisories/2026-11-20-v0.4-temps-mis-de-cote.md) · [findings of the first independent review, fixed in v0.5.1](spec/advisories/2026-11-20-v0.5-relecture-independante.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Overview

An agent pays for its services on its own (HTTP 402 / x402), but it cannot exceed the budget set by its
owner: the limit is enforced by a covenant, so the network rejects an overspend even if the agent's keys
and software are compromised.

The repository contains the vault contract, payment modes and a demo tool:

- [`contracts/archive/coeur-v0.7.sil`](contracts/archive/coeur-v0.7.sil) (core v0.7, stateless): to spend `s`, the vault coin must be
  at least `ceil(s × R / C)` DAA units old, which the network checks itself (relative lock). No counter, no
  agent-supplied time, no lineage: the address is the vault's identity. Four parameters (owner, agent,
  capacity `C` = cap per purchase, period `R`) plus the return address, single-input spends, one payee;
  the owner can freeze, withdraw or refill, but only to the vault itself or to the return address. A new
  mandate starts at zero and fills up over time; there is no burst beyond one purchase of `C`.
- [`contracts/agent_budget.sil`](contracts/agent_budget.sil) (AgentBudget v0.5.1, previous core): kept so
  existing vaults can be frozen.
- [`contracts/delivery_escrow.sil`](contracts/delivery_escrow.sil) (DeliveryEscrow v0.3): pay on delivery.
  The vendor claims with a verifier's Schnorr signature over `blake2b(requestHash ‖ resultHash ‖ escrow outpoint)`, so one proof pays one escrow; without
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
FUZZ_CASES=5000 cargo test --release --locked coeur::
```

Contract tests run against the pinned SilverScript compiler:

```bash
git clone https://github.com/kaspanet/silverscript /tmp/silverscript
git -C /tmp/silverscript checkout 7eb04634bfbae5350c1808efc7e34c4efa7f93af
cp tests/*.rs contracts/*.sil /tmp/silverscript/silverscript-lang/tests/
cd /tmp/silverscript
cargo test --release -p silverscript-lang --test coeur_tests --test agent_budget_tests --test delivery_escrow_tests --test ardoise_tests
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
- [contracts/ardoise.sil](contracts/ardoise.sil): the tab (prototype): repeated micropayments to one vendor, signed off-chain by the agent and settled in a single transaction; contract and tests done, tool commands to come.
- [spec/moteur-de-risque.md](spec/moteur-de-risque.md): the risk engine (in French): maximum loss now, over 24 h, per agent and per vendor, and what the guarantee does not cover.
- [spec/pre-audit.md](spec/pre-audit.md): scope, transaction layouts, consensus assumptions, open questions.
- [BUG-BOUNTY.md](BUG-BOUNTY.md): rules for the planned bounty.

## Related work

Several Kaspa projects work on the same problem: letting software pay on its own without holding
the keys to everything. Plafond started on 18 Nov 2026, after most of them; it builds on their
ideas and does not claim to be first.

- **PolicyVault** (kenshido): policy-controlled vault for agents, on mainnet since Aug 2026.
- **SompiVault** (elldeeone): covenant vault; Plafond reuses its pattern of counting refill time
  from the DAA score at which the network recorded the vault (`OpTxInputDaaScore`, threat model R34).
- **Kaspa x402** (elldeeone): the x402 payment binding for Kaspa. Plafond's profile extends it and its
  test vectors are reused under MIT (see [PROVENANCE.md](cli/vecteurs/kaspa-x402/PROVENANCE.md)).
- **k402 / kx402** (Kali123411): x402-style payments on Kaspa.
- **Warda**: spending controls for agents.

What Plafond adds: a loss bound proven in [spec/borne-de-perte.md](spec/borne-de-perte.md) and checked
against the real script engine, the budget enforced by the covenant itself (a compromised agent
and a dishonest merchant together cannot exceed it), a survival floor computed from KIP-9 mass (below it, the owner sweeps the lane), and every
source, test and fingerprint public. Corrections and comparisons are welcome in an issue.

## License

ISC, see [LICENSE](LICENSE).

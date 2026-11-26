# Review agents

Plafond is reviewed continuously by automated review agents, each with a narrow role, before any
human review. Their instructions live here, in French:

| File | Role |
|---|---|
| [`SOCLE.md`](SOCLE.md) | Shared ground rules and Kaspa / SilverScript background, loaded by every agent |
| [`SECURITE.md`](SECURITE.md) | Security review of each new commit |
| [`ALLEGEMENT.md`](ALLEGEMENT.md) | Code-size and simplification review |
| [`AUDIT-TESTNET.md`](AUDIT-TESTNET.md) | Proposes testnet-10 runs; never sends anything itself |

Their reports go to [`rapports/`](rapports/). Findings follow the same rule as the rest of the
project: a finding is first a failing test, then a fix. The structured Red Team sessions are in
[`spec/red-team/`](../spec/red-team/).

These agents do not replace an independent audit; see [`SECURITY.md`](../SECURITY.md) for the
project's audit status.

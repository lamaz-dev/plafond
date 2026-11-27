# Plafond Gateway

*English · [Français](GATEWAY.fr.md)*

One place where all of an organization's AI agents pay for APIs, each from its own covenant vault, behind one
address the security team can watch and stop.

The gateway is built on one rule: **a compromised gateway must not cost more than the vaults already allow.**

## What it guarantees

| | |
|---|---|
| **No owner key, ever** | The gateway only loads each agent's key and the *public* key of its owner. It refuses to start if an owner key is in its environment. If the gateway is hacked, the loss stays within each vault's covenant (`C × t / R`), and the funds can still only go back to each vault's return address. |
| **No API key at rest** | The configuration file stores only SHA-256 fingerprints of the API keys. A stolen copy of the file cannot call the gateway. Keys are compared in constant time. |
| **Emergency stop** | A separate administration key stops one agent or all of them, immediately. The stop is written to disk and survives a restart. (This is a local stop: the gateway refuses to pay. Freezing a vault on chain stays with its owner.) |
| **Hash-chained audit log** | Every line carries the SHA-256 of the previous one. A modified, deleted or inserted line breaks the chain: the gateway refuses to start and `passerelle-verifier` names the line. The head of the chain is exposed so it can be copied to a SIEM: that is what prevents rewriting the whole log at once. |
| **Nothing paid without a trace** | The request is logged *before* the payment. If the log cannot be written, the payment is refused. URL query strings are never logged (they can carry secrets). |
| **Deny by default** | Unknown key, stopped agent, vendor outside the agent's list, http, internal or cloud-metadata address, ambiguous URL: refused before any network call. Outside demo mode, every agent must have an explicit vendor list. |
| **Isolation between agents** | Each agent has its own vault, vendor list, per-request cap, rate limit and idempotency cache. One agent cannot pay from, or replay, another's. |

Requests are processed one at a time: two purchases never read the same vault state concurrently.

## Setup

1. Install each agent on the gateway host with the kit from the owner's console:
   `vault-cli agent-installer kit.json` (one folder per agent).
2. Create one key per agent and one administration key. Each key is shown once; only its fingerprint goes in
   the configuration:
   ```bash
   vault-cli passerelle-cle
   ```
3. Write the configuration (`passerelle.json`):
   ```json
   {
     "ecoute": "127.0.0.1:8403",
     "journal": "passerelle-journal.jsonl",
     "arrets": "passerelle-arrets.json",
     "admin_cle_sha256": "<fingerprint of the administration key>",
     "agents": [
       { "nom": "research", "dossier": "agents/research", "cle_api_sha256": "<fingerprint>",
         "origines": ["https://api.example.org"], "max_requete_sompi": 20000000, "debit_par_minute": 30 }
     ]
   }
   ```
4. Start it, behind your TLS proxy:
   ```bash
   vault-cli passerelle passerelle.json
   ```

## API

Agents use the same API as the single-agent router, so the Python SDK (`sdk/python`) works unchanged.

| | |
|---|---|
| `GET /v1/coffre` | budget of the calling agent's vault |
| `POST /v1/fetch {url, max_sompi?}` | buys the resource, pays if the vendor answers 402. `Idempotency-Key` header: the same key never pays twice |
| `GET /admin/etat` | agents, stops, head of the audit chain |
| `POST /admin/arret {agent}` | stops an agent (`"*"`: all agents) |
| `POST /admin/reprise {agent}` | lifts the stop (`"*"` lifts every stop) |

Agents authenticate with `Authorization: Bearer <agent key>`, administrators with the administration key.
An agent key cannot reach `/admin`, and the administration key cannot pay.

## Checking the audit log

```bash
vault-cli passerelle-verifier passerelle-journal.jsonl
```

Compare the printed head with the copy kept elsewhere (`GET /admin/etat` gives the same value while running).

## Current limits

- Testnet-10 only, like the rest of Plafond. Not audited.
- Vendors must speak Plafond's x402 profile (`covenant-budget`). Paying public `exact` vendors through the gateway
  goes through the kaspa-x402 relay today, not yet through the gateway itself.
- The gateway holds agent keys in memory. Running it on a dedicated host, behind TLS, with the agent folders
  readable only by its user, is part of the deployment.

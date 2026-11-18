# Security policy / Politique de sécurité

## Reporting a vulnerability / Signaler une faille

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
**Security** tab of this repository → **Report a vulnerability**.

**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt → **Report a vulnerability**.

Please include / Merci d'indiquer :
- the testnet-10 transaction id (TxID) if the attack was reproduced on chain / l'identifiant de la transaction sur le testnet-10 si l'attaque a été reproduite ;
- step-by-step reproduction / la méthode de reproduction, pas à pas ;
- the affected file and version (contract, vendor verification, tool) / le fichier et la version concernés.

We acknowledge reports within 7 days. Public disclosure: 30 days after the report, or as soon as a fix is published.
Accusé de réception sous 7 jours. Divulgation publique : 30 jours après le signalement, ou dès la correction publiée.

## Scope / Périmètre

Contracts `contracts/agent_budget.sil` (v0.4) and `contracts/delivery_escrow.sil` (v0.2), and the vendor-side
verification of the x402 "covenant-budget" profile (`cli/src/x402.rs`). Testnet only: **this code is a
prototype, not audited, and must not hold mainnet funds.**

Rules, out-of-scope items and the planned bounty: see [`BUG-BOUNTY.md`](BUG-BOUNTY.md).
Threat model: [`spec/threat-model.md`](spec/threat-model.md). Pre-audit package: [`spec/pre-audit.md`](spec/pre-audit.md).

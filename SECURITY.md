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

Contracts `contracts/agent_budget.sil` (v0.5.1) and `contracts/delivery_escrow.sil` (v0.2), and the vendor-side
verification of the x402 "covenant-budget" profile (`cli/src/x402.rs`). Testnet only: **this code is a
prototype, not audited, and must not hold mainnet funds.**

Rules, out-of-scope items and the planned bounty: see [`BUG-BOUNTY.md`](BUG-BOUNTY.md).
Threat model: [`spec/threat-model.md`](spec/threat-model.md). Pre-audit package: [`spec/pre-audit.md`](spec/pre-audit.md).

## What the system guarantees / Ce que le système garantit

Enforced by Kaspa consensus, for each vault (lane), even if the agent key, the agent software,
the router or the server is compromised. Proof: [`spec/borne-de-perte.md`](spec/borne-de-perte.md);
reproduce it locally with `./verify-proof.sh`.

Garanti par le consensus de Kaspa, pour chaque coffre, même si la clé de l'agent, son logiciel,
le routeur ou le serveur sont compromis :

- **Loss bound / Borne de perte.** Over any real duration `D`, the agent moves out at most
  `capacity + capacity × D / refillPeriod` (amounts plus fees), never more than the vault balance.
  With the "strict" setting (`capacity = budget / 2`, `refillPeriod = period`): at most the
  announced budget over any window of one period, and half of it immediately.
- **Per-payment cap / Plafond par achat**, and the optional payee allowlist.
- **Owner control / Contrôle du propriétaire.** Only the owner key opens `ownerControl`
  (freeze and repatriate everything).
- **No hidden outputs, no payload, one lineage** (KIP-20).

## What the system does NOT guarantee / Ce que le système ne garantit pas

- recovery of a lost owner password or key file (there is no custodian; keep a backup) /
  la récupération d'un mot de passe ou d'un fichier de clé perdu (personne ne détient la clé ; faites une sauvegarde) ;
- protection against compromise of the owner's own device / la protection contre la compromission de l'appareil du propriétaire ;
- the KAS exchange rate: budgets are in KAS, fiat amounts are indicative / le cours du KAS : les budgets sont en KAS, les montants en euros sont indicatifs ;
- the honesty or security of third-party vendors (paying does not guarantee delivery, except through the escrow) /
  l'honnêteté ou la sécurité des vendeurs tiers (payer ne garantit pas la livraison, sauf via le séquestre) ;
- availability: a payment can be delayed or refused (network, fees, mass limits); funds stay safe /
  la disponibilité : un paiement peut être retardé ou refusé ; les fonds restent protégés ;
- exact wall-clock time: the network counts DAA scores (target 10 per second, about 864,000 per 24 h) /
  l'heure exacte : le réseau compte des scores DAA (environ 864 000 par 24 h).

## Advisories / Avis de sécurité

- [2026-11-20, AgentBudget v0.4: refill time could be "set aside"](spec/advisories/2026-11-20-v0.4-temps-mis-de-cote.md)
  (fixed in v0.5, found by our own loss-bound test / corrigé en v0.5, trouvé par notre propre test de borne).
- [2026-11-20, first independent review: survival-mode decoy, owner freeze priority, parameter guards](spec/advisories/2026-11-20-v0.5-relecture-independante.md)
  (fixed in v0.5.1 / corrigé en v0.5.1).

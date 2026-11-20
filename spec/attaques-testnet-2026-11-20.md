# Attaques volontaires sur testnet-10 (20 novembre 2026, AgentBudget v0.5)

Un agent compromis attaque son propre coffre. Chaque transaction est **correctement signée par la
clé de l'agent** mais contraire au contrat, et **diffusée sans aucun contrôle local**
(`vault-cli attaque`) : c'est le réseau Kaspa qui tranche. Journal complet : `testnet/journal.md`
(10:15 et 10:26 UTC). Une transaction rejetée n'arrive jamais sur la chaîne : son identifiant n'a
pas de page dans l'explorateur ; la preuve est le message du nœud et l'état du coffre, inchangé.

| Attaque | Résultat | Identifiant calculé | Message du nœud |
|---|---|---|---|
| Jetons gonflés dans l'état suivant | **rejetée** | `c1d2c833…` | `failed to verify the signature script: script ran, but verification failed` |
| Règles plus lâches dans la continuation (plafond = capacité) | **rejetée** | `68ccb423…` | idem |
| Reste du coffre détourné vers l'attaquant | **rejetée** | `c77007a5…` | idem |
| Frais excessifs (vider le coffre par les frais) | **rejetée** | `a8f17aeb…` | idem |
| Paiement de poussière (1 000 sompi) | **rejetée** | `f9b559c9…` | `transaction storage mass of 1000000024 is larger than max allowed size of 500000` (KIP-9) |
| **Temps mis de côté** (faille de la v0.4) : coffre inactif 6 min, réserve vidée par 4 paiements antidatés, puis réclamation du temps écoulé | **rejetée** | `d240a5ba…` | `script ran, but verification failed` |

**Temps mis de côté, en chiffres.** Après les 4 vidages antidatés (acceptés, témoins :
`5a849a0a…`, `864010c3…`, `7180c9af…`, `15b462e7…`), la v0.4 aurait laissé à l'agent
**0,212 TKAS** ; la v0.5 ne lui laisse que la recharge depuis l'inscription réelle, soit **0 TKAS**
à cet instant. La tentative de 0,197 TKAS est rejetée par le réseau.

Le propriétaire a ensuite gelé le coffre (`3dfe0796…`) : 3 TKAS rapatriés.

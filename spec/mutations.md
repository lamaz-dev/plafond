# Tests de mutation du contrat (20 novembre 2026, AgentBudget v0.5.1)

On sabote volontairement une règle du contrat, on vérifie que les tests échouent, puis on remet le
contrat propre (contrôlé par `diff`). Banc : `cargo test --release fuzz::` (13 propriétés contre le
vrai moteur `kaspa-txscript`).

| Mutation | Résultat | Conclusion |
|---|---|---|
| M1 : retirer `require(refillPeriod > 0)` | les tests passent | **Garde redondante, pas un trou** : une période nulle fait échouer la division `MAX / refillPeriod`, une période négative rend ce quotient négatif et `capacity <= quotient` faux. Le comportement est identique ; la garde est conservée pour la lisibilité (défense en profondeur). |
| M1c : retirer les deux gardes de période (`> 0` et la division) | **échec** de `parametres_aberrants_sans_danger_pour_les_fonds` | la protection est bien testée |
| M2 : `require(inputDaa >= lastDaa)` devient `>` | **échec** de 3 tests (`banc_de_test_discriminant`, `coffre_moteur_egal_modele`, `parametres_aberrants…`) | détectée |
| M3 : retirer « la continuation est la sortie 1 » (`OpAuthOutputIdx(…, 0) == 1`) | les tests passaient : **trou dans le banc** | ajout de la tricherie `MoveCovenantToPayment` (lignée déplacée sur le paiement) ; la mutation fait maintenant échouer 2 tests |
| M5 : retirer `require(inputDaa >= lastDaa)` (proposition d'une relecture externe, 22 nov. 2026) | **échec** de `coffre_non_confirme_refuse` et `paiements_enchaines_non_confirmes_ne_rechargent_pas` | contrôle **non redondant** : il refuse les paiements enchaînés non confirmés (score −1), qui sans lui recevraient chacun une recharge complète |

Leçon : une mutation qui survit révèle soit une garde redondante (M1, documentée), soit un test
manquant (M3, corrigé).

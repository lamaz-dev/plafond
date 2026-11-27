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

## Cœur v0.6 (branche `coeur-v0.6`, 24 novembre 2026)

Banc : `tests/coeur_tests.rs` sur le compilateur figé. Chaque mutation est appliquée seule, puis le
contrat propre est remis et contrôlé à l'octet près.

| Mutation | Résultat |
|---|---|
| retirer la signature de l'agent | détectée |
| retirer `period < 2^32` | détectée (`delai_tronque_a_32_bits_impossible`) |
| retirer `capacity ≤ MAX / period` | détectée |
| retirer « une seule entrée » | détectée (`fusion_de_pieces_refusee`) |
| retirer « deux sorties » | détectée (troisième sortie minuscule) |
| retirer « continuation vers la même adresse » | détectée |
| retirer « paiement ≠ propre adresse » | détectée |
| retirer `spent ≤ capacity` | détectée |
| délai arrondi vers le bas | détectée |
| retirer le délai | détectée |
| `ownerControl` signé par la clé de l'agent | détectée |

Premier passage, sur le prototype à 7 paramètres : 4 mutations survivaient (`capacity > 0`,
`period > 0`, `maxFee ≥ 0`, « deux sorties »). Les trois premières étaient des gardes redondantes,
retirées du contrat (raisonnement dans `spec/borne-de-perte-v0.6.md`, §5). La quatrième révélait
un test manquant, ajouté depuis.

Côté outil (`cli/src/coeur.rs`), quatre sabotages du contrat sont tous détectés par le fuzzing de la
borne : délai sans arrondi, délai divisé par deux, capacité ignorée, verrou retiré. Le test
« moteur = modèle » laissait d'abord passer trois d'entre eux, parce que ses âges, tirés au
hasard, tombaient rarement près du délai exigé. Ils sont maintenant concentrés à ±3 de ce délai,
et les quatre sabotages sont détectés.

Deuxième passage (24 nov., soir) : avec le contrôle « moteur = modèle » désactivé, le fuzzing de
la borne **seul** ne voyait pas le délai divisé par deux. L'agent simulé n'était pas assez avide :
il ne demandait jamais plus de 1,2 fois la dépense permise, avec un délai calculé honnêtement.
Il annonce maintenant aussi tout l'âge réel de la pièce et demande jusqu'à 3 fois la dépense
permise. Les quatre sabotages sont alors détectés par les seuls contrôles de borne : fenêtres, et
courbe de perte nette sauf pour l'arrondi, qui ne coûte qu'une unité par paiement.


## Cœur v0.8 (`absorb`) et sas de rechargement (27 nov. 2026)

Sabotages automatisés : `cli/src/sas.rs`, test `chaque_regle_sabotee_est_detectee`. Le source est
modifié, recompilé, et la même liste de 25 attaques est rejouée ; l'attaque attendue doit passer.

| Mutation | Résultat |
|---|---|
| sas : retirer « deux entrées » | détectée (deux dépôts, un seul compté) |
| sas : retirer « une sortie » | détectée (frais détournés vers un tiers) |
| sas : retirer l'empreinte du coffre | détectée (autre coffre) |
| sas : retirer `sortie ≥ v + d − maxFrais` | détectée (dépôt brûlé en frais) |
| sas : retirer « sortie au script de l'entrée 0 » | **survit, attendu** : règle doublée par le script du coffre (preuve §8.5) |
| sas, `retour` : retirer la signature | détectée (retour signé par l'agent) |
| sas, `retour` : retirer l'adresse de retour | détectée (retour vers un tiers) |
| sas, `retour` : retirer la borne de frais | détectée |
| `absorb` : retirer « même script » | détectée (pièce prise) |
| `absorb` : retirer la valeur minimale | détectée (pièce brûlée) |
| `absorb` : `≥ v` au lieu de `≥ v + C` | détectée (gêne gratuite) |
| `absorb` : retirer `capacity > 0` | détectée (`absorb_refuse_avec_une_capacite_aberrante`) |


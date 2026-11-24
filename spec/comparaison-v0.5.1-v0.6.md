# Comparaison : AgentBudget v0.5.1 (`main`) et cœur v0.6 sans mémoire (branche `coeur-v0.6`)

24 novembre 2026. Rien n'est fusionné dans `main` : ce document sert à décider.

## 1. Les chiffres (mesurés, paramètres de référence)

| | v0.5.1 | v0.6 |
|---|---|---|
| Taille compilée | 577 octets | **211 octets** (−63 %) |
| Paramètres | 13 | **4** (propriétaire, agent, capacité, période) |
| Lignes de code du contrat | 66 | **21** |
| État dans le script, date fournie par l'agent | oui (`tokens`, `lastDaa`) | **non** |
| Lignée KIP-20 | obligatoire | **aucune** (le script ne change jamais) |
| Masse de calcul d'un paiement | 3 676 g | **2 467 g** (−33 % de frais) |
| Budget de calcul déclaré | 20 unités | **12** (11 mesurées) |
| Plancher d'un couloir (KIP-9) | 0,125 KAS | **0,079 KAS** |
| Borne sur une fenêtre `D`, pièce ancienne | `C + C·D/R` | **`C + C·D/R`** (la même) |
| Hypothèses de la preuve | 6 | **2 règles du réseau**, vérifiées dans le code de rusty-kaspa |
| Sabotage de chaque règle du contrat | 5 mutations documentées (`spec/mutations.md`) | **11 règles sur 11 détectées** |

## 2. Ce que la v0.6 perd

1. **La rafale.** v0.5.1 permet plusieurs paiements enchaînés, sans attendre de confirmation,
   jusqu'à la capacité. v0.6 permet un paiement d'au plus `C`, puis il faut attendre en
   proportion. Pour un agent x402 qui paie souvent, il faut **plusieurs pièces** (dépôts du
   propriétaire) ou une **ardoise** alimentée par le cœur (R55).
2. **Le crédit non dépensé est perdu à chaque paiement** : le délai repart du paiement.
3. **La liste blanche de vendeurs et le plafond par achat** ne sont plus dans le contrat. La
   capacité joue le rôle du plafond par achat. La liste blanche relève de l'outil, ou d'un
   contrat séparé si un client l'exige.
4. **Le plafond de frais n'est plus une garantie du contrat.** Les frais sont comptés dans la
   dépense, donc la borne tient quels qu'ils soient ; l'outil plafonne les frais qu'il signe.
5. **L'immunité aux coffres frères (R52) et aux dépôts de tiers (R53).** Sans lignée, toute pièce
   à l'adresse est dépensable par l'agent au rythme permis. La borne reste vraie sur les pièces
   présentes, donc les chiffres **en direct** du moteur de risque restent justes. En revanche, le
   chiffre annoncé **à la création** d'un mandat ne vaut plus si l'agent a la clé d'un autre
   coffre du même propriétaire.

## 3. Ce que la v0.6 gagne

1. **Une surface d'attaque presque nulle** : pas d'état à falsifier, pas de date fournie par
   l'agent (les failles R34 de la v0.4 et « temps mis de côté » n'ont plus d'objet), pas de
   lignée à suivre.
2. **Une preuve d'une demi-page**, qu'un relecteur vérifie en lisant deux fonctions de rusty-kaspa.
3. **L'adresse est l'identité** : un coffre se reconnaît sans indexeur, et un tiers peut
   recalculer sa perte maximale depuis l'adresse et ses pièces.
4. **Un tiers de frais en moins**, et des couloirs plus petits possibles.
5. **Le standard est plus facile à reprendre** : 4 paramètres, une règle.

## 4. Deux options à trancher

**Option A — v0.6 + lignée (+11 octets, mesuré : 222 octets).** On ajoute deux lignes : la
continuation doit porter l'identifiant de covenant du coffre.
- Ferme R52 et R53 : une pièce sans lignée (transfert d'un coffre frère, dépôt d'un tiers)
  n'est plus dépensable par l'agent. Le chiffre annoncé à la création redevient une garantie.
- Le coffre reste sans état. Le propriétaire recharge par `ownerControl`, pas par simple envoi.
- Coût : 32 octets de stockage par pièce (pluralité 2), donc le plancher remonte à ~0,125 KAS.
  La création du coffre passe par une genèse KIP-20, que l'outil sait déjà faire.

**Option B — échéance garantie par le consensus (KIP-21, à prototyper).** L'agent présente un bloc
récent, et le script vérifie son engagement avec `OpChainblockSeqCommit` et `OpBlake3WithKey`.
Comme l'opcode ne donne accès qu'aux 12 dernières heures, la règle *bloc + 12 h ≤ échéance* rend
tout paiement après l'échéance invalide.
- La fin d'un mandat devient une garantie, plus une simple commodité.
- Coût estimé : 4 hachages et environ 180 octets de témoin par paiement.
- Activation sur testnet-10 à vérifier.
- À garder hors du cœur, en variante pour les mandats à durée fixe.

## 5. Ce qu'il resterait à faire pour adopter la v0.6

1. Le moteur de risque : un couloir devient « les pièces de l'adresse », avec
   `Coeur::immediate` et `Coeur::fenetre`.
2. Les commandes de l'outil : création, paiement, gel. `build_pay` existe et est testé.
3. Le relais x402 : nouveau `vaultTemplate`.
4. La console et les mandats : capital alloué et pièces multiples.
5. Un essai complet sur testnet-10, puis la mise à jour du README, du site et de la spec.

## 6. Recommandation du chef de projet

Adopter la v0.6 **avec l'option A**. La promesse du produit, « Quel est votre pire scénario ? »,
est un chiffre donné **à la création** du mandat. Seule la lignée la garde vraie dans tous les
cas, pour 11 octets. L'option B est à prototyper ensuite, séparément.

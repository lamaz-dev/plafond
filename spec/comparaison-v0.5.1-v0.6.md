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
5. **La garantie des fenêtres glissantes futures quand l'agent a plusieurs coffres** (R52).
   *Corrigé le 24 nov., soir :* la promesse faite **à la création** n'est **pas** perdue. La perte
   nette depuis la création reste sous la courbe `C·t/R`, plafonnée au capital, quoi que fasse
   l'agent (preuve v0.6, §1b, vérifiée par le fuzzing). Ce qui se perd : une fenêtre de 24 h qui
   commencerait plus tard pourrait dépasser `C + C·D/R` si l'agent a pré-positionné de l'argent
   dans un coffre frère. Les chiffres en direct restent justes.

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

## 5. Adoption (faite le 24 nov. 2026, soir)

La v0.6 est maintenant le cœur de Plafond. Elle est branchée dans :
- l'outil (`cli/src/coffre.rs`) ;
- le moteur de risque, où un couloir est désormais une pièce du coffre ;
- la console, qui affiche la courbe promise et le délai avant le prochain achat ;
- le routeur et le relais x402 (`vaultTemplate` `plafond-coeur-v0.6`) ;
- la démo ;
- le script de preuve `verify-proof.sh`.

Elle a été essayée sur testnet-10 : `spec/essai-testnet-2026-11-24-v0.6.md`. Les anciens coffres
v0.5.1 restent gelables.

## 6. Recommandation du chef de projet (mise à jour)

Adopter la v0.6 **sans lignée**, avec la **courbe de perte** comme promesse :
- à la création, le propriétaire voit la courbe « perte maximale jusqu'à telle date », garantie
  par le seul verrou du réseau ;
- en direct, le moteur affiche les fenêtres à venir, calculées sur les pièces présentes ;
- l'outil donne une clé d'agent par mandat : pour donner plus à un agent, on agrandit son mandat.
  On ne lui en donne pas un second.

L'option A (lignée) reste possible pour un client qui exige aussi les fenêtres glissantes a priori.

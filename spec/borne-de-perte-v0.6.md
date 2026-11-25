# Borne de perte : cœur v0.6, budget sans mémoire (branche `coeur-v0.6`)

Statut : prototype sur branche, à côté de la v0.5.1 (`spec/borne-de-perte.md`), qui reste la
version de `main`. Comparaison et choix : `spec/comparaison-v0.5.1-v0.6.md`.

Contrat : `contracts/coeur.sil` (211 octets avec les paramètres de référence, 4 paramètres).
Tests : `tests/coeur_tests.rs` (compilateur figé), `cli/src/coeur.rs` (moteur + modèle du consensus).

## 1. Ce que l'on promet

Notations : `C` = `capacity` (sompi), `R` = `period` (unités DAA), `D` = durée d'une fenêtre.

**Théorème.** Soit une pièce `u` présente à l'adresse du coffre au score DAA `a`, de valeur `V`
et d'âge `g = a − création(u)`. Sur la fenêtre `[a, a + D]`, tout ce qui quitte durablement le
propriétaire à partir de `u` et de toutes ses descendantes (paiements vers l'extérieur et frais)
vaut au plus

    min( V , min(C, C·g/R) + C·D/R )

Pour une pièce déposée depuis longtemps, cela donne **C + C·D/R**, la même borne que la v0.5.1.
Pour une pièce qui vient d'être créée (`g = 0`), cela donne **C·D/R** : pas de rafale du tout.

La perte maximale du système sur `[a, a + D]` est la somme de ce terme sur les pièces présentes
à l'instant `a`, plus, pour chaque pièce déposée pendant la fenêtre au score `x`, le terme
`min(V, C·(a + D − x)/R)`. C'est exactement ce que calcule `Coeur::fenetre`, et ce que le
fuzzing vérifie fenêtre par fenêtre.

## 1b. La promesse faite à la création : une courbe, jamais dépassée

**Théorème (courbe de perte nette).** Un mandat est créé au score `t₀` avec des pièces de
valeur `Vₖ` et d'âge `gₖ`. À tout instant `t ≥ t₀`, la **perte nette** du propriétaire depuis la
création (tout ce qui est sorti de ses coffres, moins tout ce qui y est revenu) vérifie

    perte_nette(t) ≤ Σₖ min(Vₖ, min(C, C·gₖ/R) + C·(t − t₀)/R)  +  Σ apports du propriétaire après t₀

Pour un mandat neuf (`g = 0`), la courbe est simplement **C·(t − t₀)/R, plafonnée au capital**.

Cette courbe ne dépend d'**aucune hypothèse** sur ce que fait l'agent ensuite : coffres frères,
transferts entre eux, dépôts de tiers, argent volé puis rendu pour être « pré-positionné »
(R52). Démonstration : une pièce déposée par quelqu'un d'autre que le propriétaire ne peut laisser
sortir plus que sa valeur, et cette valeur est comptée comme « revenue ». Ce qu'elle laisse sortir
est donc compensé. Il ne reste que les arbres issus des pièces du propriétaire, bornés par le
théorème du §1 avec `a = t₀`.

**Ce que la courbe garantit, et ce qu'elle ne garantit pas :**
- **Garanti, pour toujours** : tous les chiffres affichés à la création du mandat (perte
  immédiate, perte sur 24 h, perte sur la durée) sont des points de cette courbe, car ce sont des
  fenêtres qui commencent à la création.
- **Garanti à tout instant** : les chiffres recalculés en direct par le moteur de risque, qui
  compte les pièces réellement présentes (§1).
- **Pas garanti a priori** : une fenêtre glissante qui commence plus tard, si l'agent a la clé de
  plusieurs coffres et a pré-positionné de l'argent. La rafale peut alors dépasser `C + C·D/R` sur
  24 h, mais jamais la courbe (`blanchiment_entre_freres_sous_la_courbe` : rafale de 11 C en un
  instant, fenêtre glissante annoncée de 4 C dépassée, courbe tenue). Le moteur en direct voit
  ces pièces avant la rafale.

En v0.5.1, la lignée garantissait aussi les fenêtres glissantes. La v0.6 garantit la courbe sans
lignée. La courbe est la vraie réponse à « Quel est votre pire scénario ? » : la perte totale
jusqu'à telle date.

## 2. Les deux règles du réseau sur lesquelles tout repose

Vérifiées dans le code de rusty-kaspa 2.1.0, pas supposées :

1. **Verrou relatif** (`check_sequence_lock`,
   `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`) : une entrée
   de `sequence` `s` (bit 63 à zéro) n'est valide au point de vue `pov` que si
   `création + (s & 0xffffffff) − 1 < pov`, c'est-à-dire **`s & 0xffffffff ≤ pov − création`**.
2. **Score inscrit sur les pièces créées** (`pipeline/virtual_processor/utxo_validation.rs`,
   `add_transaction(tx, pov_daa_score)`) : une pièce créée par une transaction acceptée au point de
   vue `t` porte le score `t`, le même que celui avec lequel son verrou a été contrôlé.

Plus la règle générale « les sorties ne dépassent pas les entrées ».

Côté script, `OpCheckSequenceVerify` (`kaspa-txscript` 2.1.0, `opcodes/mod.rs`) refuse si le bit 63
de la `sequence` de l'entrée est levé, et compare **les 32 bits bas des deux côtés**. Une `sequence`
géante n'achète donc rien : le script et le réseau lisent la même valeur `s₃₂ = s & 0xffffffff`.

## 3. Démonstration

**Un paiement.** Le paiement `i` dépense la pièce `uᵢ₋₁` créée au score `tᵢ₋₁` et se fait au score
`tᵢ`. Il dépense `sᵢ` (paiement et frais, plus une éventuelle sortie vers un coffre frère) avec
`0 ≤ sᵢ ≤ C`. Le script exige `s₃₂ ≥ ⌈sᵢ·R/C⌉`, le réseau exige `s₃₂ ≤ tᵢ − tᵢ₋₁`. Donc

    sᵢ ≤ C·(tᵢ − tᵢ₋₁)/R      et      sᵢ ≤ C.

Le délai exigé ne dépasse jamais `R < 2^32`, puisque `sᵢ ≤ C`. Il n'est donc jamais tronqué par
le masque 32 bits ; c'est la garde `period < 2^32` du script qui l'assure (§5).

**Une chaîne.** La continuation `uᵢ` revient à la même adresse au score `tᵢ` (règle 2). Les
paiements d'une chaîne commencée à la pièce `u` (création `c`, âge `g` en `a`) tombent dans
`[a, a + D]` aux scores `t₁ < t₂ < … < tₙ`. Le premier vérifie `s₁ ≤ min(C, C·(t₁ − c)/R)`, et
`t₁ − c = g + (t₁ − a)`. Les suivants vérifient `sᵢ ≤ C·(tᵢ − tᵢ₋₁)/R`. En sommant (télescopage) :

    Σ sᵢ ≤ min(C, C·g/R) + C·(t₁ − a)/R + C·(tₙ − t₁)/R ≤ min(C, C·g/R) + C·D/R.

Pour être exact sur le minimum : si `C·(t₁ − c)/R ≥ C`, alors `s₁ ≤ C ≤ min(C, C·g/R) + C·(t₁−a)/R`
dans tous les cas. Et la somme ne peut pas dépasser `V`.

Les scores sont **strictement** croissants : `⌈sᵢ·R/C⌉ ≥ 1` dès que `sᵢ ≥ 1`. Deux paiements d'une
même chaîne ne tiennent donc jamais dans un même bloc (`enchainement_dans_un_meme_bloc_impossible`).

**Un arbre (coffres frères, fragmentation).** Une sortie de paiement peut aller vers un autre
coffre Cœur dont l'agent a aussi la clé (voir R52). Elle crée alors une nouvelle chaîne, avec son
propre rythme. Ce que cette nouvelle chaîne laisse partir vers l'extérieur ne dépasse pas ce
qu'elle a reçu, et ce qu'elle a reçu est déjà compté dans le `sᵢ` de la chaîne d'origine. Par
récurrence sur la profondeur de l'arbre, la perte externe de l'arbre est au plus la dépense de la
chaîne racine sur la fenêtre, d'où le théorème.

L'interdiction de payer vers sa propre adresse (`outputs[0] != moi`) **n'est donc pas porteuse de
la borne**. Elle évite seulement que l'agent fragmente son propre coffre : seules les actions du
propriétaire ajoutent alors des pièces à l'adresse.

**Ce que la borne ne dit pas.** Un dépôt nouveau (propriétaire ou tiers) est une nouvelle racine.
Sa contribution est comptée à part (§1), et sans rafale puisque `g = 0`.

## 4. Comparaison avec la v0.5.1 (borne identique, preuve plus courte)

| | v0.5.1 | v0.6 |
|---|---|---|
| Borne sur une fenêtre `D`, pièce ancienne | `C + C·D/R` | `C + C·D/R` |
| Rafale permise | jusqu'à `C`, en plusieurs paiements enchaînés | un seul paiement de `C` au plus, puis attente |
| Repose sur | état dans le script, `lastDaa` fourni par l'agent et borné, lignée KIP-20 | verrou relatif du réseau, rien d'autre |
| Hypothèses à auditer | 6 (§4 de `borne-de-perte.md`) | 2 règles du réseau (§2 ci-dessus) |

## 5. Règles du script, une par une, et pourquoi elles sont là

Chaque règle a été sabotée tour à tour ; le banc de tests a détecté les 11 sabotages
(détail dans `spec/mutations.md`, section v0.6).

| Règle | Porteuse ? | Sans elle |
|---|---|---|
| signature de l'agent | oui | n'importe qui paie |
| `period < 2^32` | non (doublée par le compilateur, voir `spec/coeur-bytecode.md`) | le compilateur ajoute déjà `délai ∈ [0, 2^32)` avant le verrou ; la garde reste par prudence |
| `capacity ≤ MAX / period` | oui | débordement du calcul du délai |
| une seule entrée | oui | fusion : la valeur d'une pièce part en frais sans être comptée (R26) |
| deux sorties | oui (attribution) | un second bénéficiaire caché dans le même paiement ; le moteur de risque ne peut plus attribuer la dépense à un vendeur (M4) |
| continuation vers la même adresse | oui | le reste du coffre est détourné |
| paiement ≠ propre adresse | non (hygiène) | fragmentation par l'agent ; la borne tient (§3) |
| `spent ≤ capacity` | oui | rafale au-delà de `C` |
| délai `⌈spent·R/C⌉` (arrondi au-dessus) | oui | l'arrondi vers le bas laisse gagner une unité à chaque paiement |
| signature du propriétaire (`ownerControl`) | oui | l'agent récupère tout |

Retirées par rapport au prototype, parce que redondantes (vérifié par mutation, puis raisonné) :
- `capacity > 0` et `period > 0` : une capacité ou une période nulle ou négative rend tout paiement
  impossible, par division par zéro ou par contradiction avec `0 ≤ spent ≤ capacity`.
- le paramètre `maxFee` : les frais sont comptés dans `spent`, donc la borne tient quels qu'ils
  soient. Un plafond de frais est une politique de l'outil, pas une garantie du contrat.
- `spent ≥ amount` et `amount > 0` : déjà garantis par le réseau (sorties ≤ entrées) ; un paiement
  nul est sans danger.
- la longueur du *payload* : sa masse est payée en frais, eux-mêmes comptés.

## 6. Validation automatique

| Test | Ce qu'il vérifie |
|---|---|
| `coeur_tests.rs` (7 tests) | comportement contre le vrai moteur : rythme, cas limites, forme, fusion, paramètres aberrants, délai tronqué |
| `coeur_moteur_et_consensus_egal_modele` | moteur + règles du réseau = modèle d'une ligne, avec 7 familles de `sequence` tricheuses, âges concentrés à ±3 du délai |
| `agent_avide_un_coffre_sous_la_borne` | agent avide ou tricheur, un coffre : la perte de chaque fenêtre reste sous l'annonce |
| `agent_avide_coffres_freres_sous_l_annonce_du_moteur` | deux coffres, transferts entre eux, dépôts en cours de route : idem |
| `borne_simple_atteinte_et_jamais_depassee` | la borne `C + C·D/R` est atteinte à 1 % près : elle est serrée |
| `coffres_freres_pre_positionnement` | démonstration de R52 |
| `blanchiment_entre_freres_sous_la_courbe` | R52 par blanchiment : la fenêtre glissante est dépassée, la courbe tient |
| courbe vérifiée dans les deux fuzzings | perte nette depuis la création sous la courbe, à chaque événement, avec dépôts de tiers et retours d'argent |

Le banc détecte un contrat saboté : l'arrondi vers le bas, un délai divisé par deux, la capacité
ignorée et le verrou retiré font tous échouer le fuzzing. 2 000 cas par propriété passent sans
divergence.

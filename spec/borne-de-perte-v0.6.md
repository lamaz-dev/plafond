# Borne de perte : cœur v0.6, budget sans mémoire (branche `coeur-v0.6`)

Statut : prototype sur branche, à côté de la v0.5.1 (`spec/borne-de-perte.md`), qui reste la
version de `main`. Comparaison et choix : `spec/comparaison-v0.5.1-v0.6.md`.

Contrat déployé par l'outil : cœur v0.7 (`contracts/archive/coeur-v0.7.sil`, 289 octets avec les
paramètres de référence, 5 paramètres) ; la règle de l'agent (`pay`) est identique à la v0.6 (211 octets,
4 paramètres, `contracts/archive/coeur-v0.6.sil`), seule l'entrée du propriétaire change (§7).
Depuis le 27 nov. 2026, `contracts/coeur.sil` est le cœur v0.8 (333 octets) : la v0.7 plus l'entrée
sans clé `absorb`, pour le sas de rechargement `contracts/sas.sil` (190 octets), §8. Pas encore déployé
par l'outil.
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

**Rechargement par regonflement (R62, 26 nov. 2026).** L'outil ne crée plus de pièce pour
« Ajouter des fonds » : le propriétaire dépense une pièce existante (`ownerControl`) et la renvoie
au coffre grossie de l'apport, d'âge nul. La lignée de l'ancienne pièce s'arrête ; elle a perdu au
plus `min(V, C + C·D₁/R)` avant, la nouvelle racine perd au plus `C·D₂/R` après (pas de rafale,
`g = 0`). Sur toute fenêtre, la place de cette pièce perd donc encore au plus `C + C·D/R` :
le nombre de pièces, et donc la borne par période affichée, ne changent pas. La courbe promise
(somme des apports, §1b) reste une borne : l'apport est une racine à sa date, la pièce regonflée
garde sa propre courbe (test `coffre::tests::r62_courbe_promise_tenue_apres_regonflement`).

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

## 7. v0.7 : la clé du propriétaire ne peut renvoyer l'argent que chez lui

Paramètre ajouté : `retourSpkHash` = blake2b du scriptPubKey de l'**adresse de retour**, fixée à la
création (par défaut l'adresse du propriétaire ; au choix, un portefeuille dont la clé n'est pas sur
l'ordinateur de la console : Ledger, multisignature, conservateur).

**Théorème.** Soit une pièce `P` du coffre, de valeur `v`, dépensée par `ownerControl` comme entrée
d'indice `i` d'une transaction `T`. Alors `T` a une sortie d'indice `i`, et cette sortie est
- soit au script du coffre, de valeur `≥ v` (rechargement : rien ne sort) ;
- soit à l'adresse de retour, de valeur `≥ v − C` (gel ou retrait, au plus `C` de frais par pièce).

Ceci vaut quel que soit le signataire, donc même si la clé du propriétaire est volée.

**Démonstration.** Le script exige `i < |outputs|` puis, selon que `outputs[i].scriptPubKey` est égal
au script de l'entrée active, `outputs[i].value ≥ v`, sinon `blake2b(outputs[i].scriptPubKey) ==
retourSpkHash` et `outputs[i].value ≥ v − C` (lecture directe du script ; blake2b est résistante aux
secondes préimages, donc aucun autre script n'a cette empreinte). Deux pièces du coffre ne peuvent pas
se partager une sortie : leurs indices d'entrée diffèrent, donc leurs sorties d'indice aussi. ∎

**Conséquences.**
- La borne côté agent (§3) est inchangée : `pay` n'a pas changé, et un rechargement par le
  propriétaire produit une pièce de valeur `≥ v` d'âge nul (déjà couvert par le §3, R62).
- Vol de la clé du propriétaire : sa perte est au plus `C` par pièce (frais brûlés), et l'argent ne
  peut arriver qu'à l'adresse de retour. Si l'adresse de retour est la trésorerie du propriétaire
  (valeur par défaut), le voleur peut ensuite vider cette trésorerie, qui n'est pas un coffre : la
  protection complète demande une adresse de retour dont la clé est ailleurs.
- Un voleur peut aussi « recharger » sans rien ajouter : la pièce repart d'un âge nul, ce qui retarde
  l'agent sans rien coûter au propriétaire (gêne, pas perte).
- Les sorties autres que celles d'indice des entrées du coffre restent libres : elles ne peuvent
  dépenser que les autres entrées (rendu du propriétaire lors d'un rechargement).

**Tests.** `coeur::tests::retour_cle_proprietaire_volee_ne_peut_rien_detourner` (vrai moteur, chaque
entrée vérifiée), `retour_coffres_v06_toujours_reconnus` (bytecode v0.6 inchangé, adresse identique),
`tests/coeur_tests.rs::le_proprietaire_ne_peut_rien_envoyer_ailleurs` (compilateur figé),
`coffre::tests::gel_par_lots_sous_la_masse_standard` (gel v0.7 : une sortie par pièce, frais à la
masse, lots coupés si nécessaire, toutes les tentatives d'escalade diffusables).

## 8. v0.8 : rechargement sans clé (entrée `absorb` et sas de rechargement)

But : ajouter de l'argent au coffre d'un agent **sans la clé du propriétaire** et sans que Plafond
détienne quoi que ce soit. Celui qui paie (achat par carte, conservateur) envoie des KAS à une adresse,
le **sas** ; cet argent ne peut ensuite que regonfler une pièce existante du coffre, ou revenir à
l'adresse de retour.

Deux scripts : le cœur v0.8 (`contracts/coeur.sil`) = cœur v0.7 + l'entrée `absorb` ; le sas
(`contracts/sas.sil`), paramètres `coffreSpkHash` (blake2b du script du coffre), `retourSpkHash`,
`ownerKey`, `maxFrais`. Notations : `C` capacité, `F` = `maxFrais`.

### 8.1 Ce que disent les scripts (lecture directe)

**Lemme A (`absorb`).** Si une pièce du coffre de valeur `v` est dépensée par `absorb` comme entrée
d'indice `i`, alors `C > 0`, la transaction a une sortie d'indice `i`, au script du coffre, de valeur
`≥ v + C`. Aucune signature n'est demandée.

**Lemme B (`recharger`).** Si un dépôt du sas de valeur `d` est dépensé par `recharger` dans une
transaction `T`, alors `T` a exactement deux entrées et une sortie ; l'entrée 0 est une pièce du coffre
(valeur `v`) ; le dépôt est l'entrée 1 ; la sortie est au script du coffre et vaut `≥ v + d − F`.

*Démonstration.* Le script exige `|inputs| = 2`, `|outputs| = 1`, `blake2b(inputs[0].spk) =
coffreSpkHash`, `outputs[0].spk = inputs[0].spk`, `outputs[0].value ≥ inputs[0].value + inputs[1].value
− F`. Le dépôt ne peut pas être l'entrée 0 : il faudrait `blake2b(spk du sas) = coffreSpkHash`, or le
script du sas contient `coffreSpkHash` : ce serait un point fixe de blake2b (une préimage choisie),
exclu. Le dépôt est donc l'entrée 1 et `inputs[1].value = d`. Par résistance aux secondes préimages,
l'entrée 0 a exactement le script du coffre. ∎

**Lemme C (`retour`).** Si un dépôt de valeur `d` est dépensé par `retour` comme entrée `i`, la
transaction est signée par la clé du propriétaire et sa sortie `i` est à l'adresse de retour, de
valeur `≥ d − F`.

Un script de cœur v0.8 ne change jamais (pas d'état) : l'empreinte inscrite dans le sas désigne ce
coffre (ces clés, cette capacité, cette période, cette adresse de retour) et aucun autre.

### 8.2 Théorème du sas : le dépôt ne va nulle part ailleurs

**Théorème.** Un dépôt `d` au sas ne peut être dépensé que de deux façons :
1. versé dans **une pièce existante** du coffre, qui passe de `v` à `≥ v + d − F` : le nombre de pièces
   du coffre ne change pas (une consommée, une créée), rien ne va à un tiers, au plus `F` part en frais ;
2. renvoyé à l'adresse de retour (`≥ d − F`), avec la signature du propriétaire.

Le dépôt ne peut ni créer une pièce de plus, ni fusionner deux pièces du coffre, ni payer un vendeur,
ni aller à un autre script. Ceci vaut pour tout signataire, y compris l'agent et un voleur de la clé
du propriétaire.

*Démonstration.* Le sas n'a que deux entrées de script (toute autre finit par `OpReturn`) : lemmes B
et C. Dans le cas B, la transaction a une seule sortie : pas de seconde pièce, pas de tiers. Elle a deux
entrées, dont le dépôt : une seule pièce du coffre est consommée, donc pas de fusion. La pièce du
coffre (entrée 0) doit elle-même être dépensée par une entrée de son script : `pay` est exclu
(il exige une seule entrée) ; `absorb` exige en plus `sortie ≥ v + C` ; `ownerControl` exige la
signature du propriétaire et, la sortie étant au coffre, `sortie ≥ v`. ∎

Conséquences pratiques :
- sans clé, un dépôt est versable dès que `d ≥ C + frais réels` (la pièce doit grossir de `C`) ;
- un dépôt plus petit attend le propriétaire (versement cosigné par `ownerControl`, ou `retour`) ;
- les frais sont pris sur le dépôt : celui qui déclenche le versement n'a besoin d'aucun fonds.

### 8.3 La borne de perte tient, et ne dépend pas de l'argent ajouté

**Ce que le propriétaire peut perdre au sas :** au plus `F` par dépôt (frais), d'après 8.2.

**Côté agent.** `pay` est inchangé. Appelons *emplacement* la suite des pièces qui se succèdent par
continuation de `pay`, par `absorb` ou par rechargement `ownerControl` : chaque transaction consomme
la pièce de l'emplacement et en recrée exactement une (lemme A, §7, forme de `pay`), créée au score
de la transaction (§2, règle 2). Soit un emplacement dont la pièce a l'âge `g` au score `a`.

**Théorème (emplacement).** Sur toute fenêtre `[a, a + D]`, ce que `pay` fait sortir d'un emplacement
vaut au plus `min(C, C·g/R) + C·D/R`, **quels que soient le nombre et le montant des regonflements**.

*Démonstration.* Chaque paiement `sᵢ` au score `tᵢ` dépense une pièce créée au score `cᵢ`, avec
`sᵢ ≤ C·(tᵢ − cᵢ)/R` et `sᵢ ≤ C` (§3). La pièce dépensée par le paiement `i` a été créée par
l'événement précédent de l'emplacement (paiement `i − 1` ou regonflement), donc `cᵢ ≥ tᵢ₋₁`. Les
intervalles `(cᵢ, tᵢ]` sont disjoints et, sauf le premier, contenus dans `[a, a + D]` : la somme
télescope comme au §3. Un regonflement ne fait que **raccourcir** un intervalle (il remet l'âge à
zéro) : il ne peut qu'abaisser la somme. ∎

C'est l'argument du regonflement R62 (§3), sans la signature : `absorb` fait strictement moins que le
rechargement par `ownerControl` (il exige `+C` au lieu de `+0`), et aucune des deux entrées ne fait
sortir d'argent. La courbe du §1b tient à l'identique : un dépôt versé est un apport, racine d'âge nul
à la date du versement (pas de rafale).

**Ce qui ne tient PAS par le contrat (limite S3).** Le théorème parle des emplacements, et n'importe qui
peut en créer un en envoyant de l'argent à l'adresse du coffre (c'était déjà vrai en v0.6). Le sas ne
distingue pas une pièce d'origine d'une pièce de tiers : un attaquant actif peut faire verser un
dépôt dans SA pièce. Le dépôt n'ajoute alors pas de pièce, mais l'ancienne pièce du propriétaire
garde son solde et son rythme à côté : pendant qu'il lui reste du solde, le coffre a un emplacement
financé de plus (excès borné par `min(solde restant, C + C·D/R)` par dépôt détourné). La courbe du
§1b, elle, tient toujours. Détail, coût et parades : `spec/red-team/sas-2026-11-27.md`.

### 8.4 La gêne a un prix, versé au propriétaire

Regonfler remet l'âge de la pièce à zéro : l'agent doit attendre de nouveau avant de payer. C'était
déjà possible pour le propriétaire (§7) ; avec `absorb`, n'importe qui peut le faire, mais :

**Proposition.** Pour empêcher un achat de prix `p` (frais compris) sur une pièce, il faut la
regonfler au moins une fois toutes les `⌈p·R/C⌉` unités DAA, et chaque regonflement sans clé ajoute
au moins `C` à la pièce. Bloquer les achats de prix `p` coûte donc au moins `C` par `⌈p·R/C⌉` unités
et par pièce, soit `C²/(p·R)` par unité : **au moins `C/R`, le débit entier du budget de l'agent**,
pour ne bloquer que les achats au plafond, et `C/p` fois plus pour bloquer les achats de prix `p`.
Tout ce qui est versé appartient au propriétaire (il le récupère par le gel).

*Démonstration.* Lemme A pour le prix ; pour le rythme, un paiement `p` passe dès que la pièce
atteint l'âge `⌈p·R/C⌉` (§3.1 du rapport Red Team du 26 nov.). ∎

Exemple (0,5 KAS par achat, période d'une heure) : bloquer les achats de 0,05 KAS coûte 5 KAS par
heure et par pièce, donnés au propriétaire. Le gel n'est pas empêché pour autant : celui qui
regonfle pour doubler un gel paie `C` à chaque bloc gagné, et pendant ce temps la pièce, d'âge nul,
ne laisse rien sortir.

### 8.5 Règles du sas et de `absorb`, une par une

Chaque règle a été sabotée tour à tour (`sas::tests::chaque_regle_sabotee_est_detectee`).

| Règle | Porteuse ? | Sans elle |
|---|---|---|
| sas : deux entrées | oui | un second dépôt dans la même transaction part entièrement en frais |
| sas : une sortie | oui | la marge de frais `F` va dans la poche d'un tiers au lieu d'être seulement brûlable, ou crée une pièce de plus au coffre (d'au plus `F`) |
| sas : entrée 0 = le coffre (empreinte) | oui | le dépôt regonfle n'importe quel script |
| sas : sortie au script de l'entrée 0 | non (doublée par le script du coffre) | rien : `absorb` et `ownerControl` imposent déjà la destination ; gardée pour ne pas dépendre de la lecture du cœur |
| sas : `sortie ≥ v + d − F` | oui | le dépôt part en frais |
| sas, `retour` : signature du propriétaire | oui | n'importe qui renvoie chaque dépôt à l'adresse de retour : le rechargement est empêché pour le prix des frais |
| sas, `retour` : adresse de retour | oui | la clé du propriétaire (volée) détourne les dépôts |
| sas, `retour` : `sortie ≥ d − F` | oui | la clé du propriétaire (volée) brûle les dépôts |
| `absorb` : sortie `i` au même script | oui | n'importe qui prend la pièce |
| `absorb` : `sortie ≥ v + C` | oui | n'importe qui brûle la pièce en frais |
| `absorb` : le `+ C` | oui (prix de la gêne) | la gêne devient gratuite |
| `absorb` : `capacity > 0` | oui pour des réglages aberrants | avec une capacité négative, la pièce fond (R63 : garde explicite) |
| `absorb` : `i < |outputs|` | garde explicite (R63) | la lecture hors bornes est un « comportement indéfini » du compilateur |

### 8.6 Validation automatique

| Test | Ce qu'il vérifie |
|---|---|
| `sas::tests::le_depot_ne_peut_que_regonfler_le_coffre_ou_revenir` | 11 transactions légitimes acceptées, 25 attaques nommées refusées, chaque entrée exécutée par le vrai moteur |
| `sas::tests::chaque_regle_sabotee_est_detectee` | 11 sabotages : chaque règle porteuse retirée laisse passer l'attaque attendue |
| `sas::tests::sas_et_agent_avide_sous_la_borne` | fuzzing : agent avide ou tricheur, rechargements par le sas, gênes ; toujours une pièce, théorème de l'emplacement, frais du sas bornés, valeur expliquée au sompi |
| `sas::tests::rechargement_sans_cle` | transactions de l'outil : acceptées, budgets de calcul, masse standard |
| `sas::tests::gene_payante_et_donnee_au_proprietaire` | la proposition du §8.4, chiffrée |
| `sas::tests::coffres_v07_inchanges_et_sans_absorb` | bytecode et source v0.7 identiques, coffres v0.7 gelables, pas d'entrée sans clé |
| `sas::tests::absorb_refuse_avec_une_capacite_aberrante` | garde `capacity > 0` |
| `sas::tests::limite_depot_verse_dans_la_piece_d_un_tiers` | la limite S3, figée et chiffrée |
| `sas::tests::piece_marquee_par_un_tiers_reste_utilisable` | un identifiant de covenant posé par un tiers ne bloque pas la pièce |
| `tests/coeur_tests.rs::regonflement_sans_cle`, `tests/sas_tests.rs` | les mêmes règles sur le compilateur figé |

Hypothèses : celles du §2 (verrou relatif, score des pièces créées, sorties ≤ entrées) et la résistance
de blake2b aux secondes préimages. Non vérifié : un versement réel sur le testnet (règles de relais
du mempool pour une dépense sans signature).

# Borne de perte du coffre entier : cœur v0.9 à v0.9.2, lignée KIP-20

Statut : contrat écrit, prouvé et testé contre le vrai moteur de script (27 nov. 2026). Cœur v0.9.2
et sas v0.2.1 **essayés sur testnet-10 le 28 nov. 2026**, de la création à la fermeture, attaques
réelles comprises (`spec/essai-testnet-2026-11-28-v0.9.2.md`).

> **v0.9.2 (28 nov. 2026).** `contracts/coeur.sil` est maintenant le cœur v0.9.2 (550 octets avec
> les paramètres de référence) et `contracts/sas.sil` le sas v0.2.1 (264 octets). Par rapport à la
> v0.9 : (1) `ownerControl` gagne une branche, le **retrait partiel** (§9) ; (2) tout ce qui part à
> l'adresse de retour est une **pièce ordinaire, sans aucune lignée** (§10, limite W10 fermée), dans
> le cœur comme dans le sas. `pay` et `absorb` sont ceux de la v0.9, au caractère près (vérifié par
> un test). Les §1 à §8 valent pour toutes ces versions. Archives à l'identique : `coeur-v0.9.sil`,
> `coeur-v0.9.1.sil` (retrait partiel en entrée séparée `ownerWithdraw`, 577 octets, jamais déployé),
> `sas-v0.2.sil`.

- Contrats : `contracts/coeur.sil` (cœur v0.9.2, 550 octets ; la v0.9 archivée fait 376 octets avec
  les paramètres de référence, +43 par rapport à la v0.8) et `contracts/sas.sil` (sas v0.2.1, 264
  octets ; le sas v0.2 archivé en fait 227).
- Ce document s'appuie sur `spec/borne-de-perte-v0.6.md` : §2 (les deux règles du réseau), §3 (un
  paiement, une chaîne), §7 (adresse de retour), §8 (`absorb`, sas, prix de la gêne). Il ne les répète
  pas ; il ajoute la lignée et en tire la borne **du coffre entier**.
- Tests : `cli/src/lignee.rs`, `tests/coeur_tests.rs`, `tests/sas_tests.rs`.
- Analyse d'attaque : `spec/red-team/lignee-2026-11-27.md` ; retrait partiel :
  `spec/red-team/retrait-2026-11-27.md` ; v0.9.2 : `spec/red-team/coeur-v0.9.2-2026-11-28.md`.

Notations : `C` capacité, `R` période, `D` durée d'une fenêtre, `F` = `maxFrais` du sas, `S` le
script du coffre (son adresse), `X` l'identifiant de sa lignée, `k` le nombre de pièces à la création.

## 1. Ce que l'on promet

**Le coffre, c'est la lignée `X`** : l'ensemble des pièces non dépensées qui portent l'identifiant de
covenant `X`. Ce n'est plus « tout ce qui se trouve à l'adresse ».

**Théorème (coffre entier).** Soit un coffre créé avec `k` pièces. Sur **toute** fenêtre de `D`
unités DAA, à n'importe quel moment de sa vie, ce que la clé de l'agent peut faire sortir du coffre
(paiements et frais) vaut au plus

    k × ( C + C·D/R )

et au plus `C + C·D/R` par emplacement. Cela vaut **sans condition** :
- quels que soient le nombre et le montant des dépôts versés par le sas et des rechargements ;
- quelles que soient les pièces que des tiers envoient à l'adresse du coffre, avec ou sans lignée ;
- même si la clé de l'agent est compromise, même si la clé du propriétaire est volée en plus ;
- sans rien supposer de l'outil, d'un service de surveillance ou d'une course gagnée.

Depuis la création (pièces d'âge `g` à la création) : au plus `k × (min(C, C·g/R) + C·t/R)` au bout de
`t` unités, et jamais plus que l'argent présent.

Ce que la v0.8 ne garantissait que « tant que personne n'attaque » (limite S3) est maintenant une
propriété du contrat. Ce que la v0.6 ne garantissait pas a priori (une fenêtre glissante qui commence
plus tard, R52) l'est aussi : le nombre d'emplacements est fixe.

**Théorème (dépôt).** Un dépôt `d` au sas ne peut que (1) grossir **une pièce de la lignée `X`**, qui
passe de `v` à `≥ v + d − F`, sans ajouter de pièce à la lignée, ou (2) revenir à l'adresse de
retour (`≥ d − F`) avec la signature du propriétaire.

**Ce que le théorème ne dit pas** (§6) : une pièce d'une AUTRE lignée à la même adresse est un autre
coffre, financé par celui qui l'a créée ; elle n'entre pas dans la borne parce que ce n'est pas
l'argent du propriétaire ni celui des payeurs.

## 2. Ce que le réseau garantit (KIP-20)

Lu dans le code que le dépôt compile et que la CI exécute (`kaspa-consensus-core` 2.1.0 pour les
règles de lignée, `kaspa-txscript` 2.2.0 pour le moteur de script, figés par `cli/Cargo.lock`), pas supposé.

**N1. Une sortie peut déclarer une lignée** : `covenant = (identifiant, entrée qui l'autorise)`
(`consensus-core/src/tx.rs`, `CovenantBinding`). La pièce créée porte cet identifiant
(`consensus-core/src/utxo/utxo_diff.rs` : `output.covenant.map(|x| x.covenant_id)`).

**N2. Continuation ou genèse** (`txscript/src/covenants.rs`, `CovenantsContext::from_tx`, appelée par
le nœud avant tout script : `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs`,
`check_covenant_info`). Pour chaque sortie qui déclare `(X, i)` :
- si la pièce dépensée par l'entrée `i` porte `X` : **continuation**, acceptée par le réseau ;
- sinon : **genèse**, acceptée seulement si `X = blake2b-256(clé « CovenantID » ; référence de la
  pièce dépensée par l'entrée i ; pour chaque sortie du groupe : indice, valeur, script)`
  (`consensus-core/src/hashing/covenant_id.rs`). Sinon la transaction entière est invalide
  (`WrongGenesisCovenantId`).

**N3. Le réseau ne limite pas le nombre de continuations.** Une entrée qui porte `X` peut autoriser
autant de sorties `X` qu'elle veut, vers n'importe quel script : c'est **le script de cette entrée**
qui doit le restreindre. D'où la règle du cœur (§3). Test : `le_reseau_refuse_une_lignee_usurpee`
(« le réseau, seul, laisserait scinder »).

**N4. Ce que le script peut lire** (`txscript/src/opcodes/mod.rs`) : `OpAuthOutputCount(i)` = nombre
de sorties de continuation autorisées par l'entrée `i` (0 si l'entrée ne porte aucune lignée ; les
genèses ne comptent pas) ; `OpAuthOutputIdx(i, n)` = indice de la n-ième, par indice croissant (échec
s'il n'y en a pas) ; `OpInputCovenantId(i)` = lignée de la pièce de l'entrée `i`, ou 32 octets nuls.

**Lemme N (unicité).** Une sortie ne porte `X` que si (a) l'entrée qui l'autorise dépense une pièce
portant `X`, ou (b) c'est une genèse dont le hachage vaut `X`. La genèse de `X` a dépensé une pièce
précise, qui ne peut être dépensée qu'une fois ; une autre genèse donnant `X` exigerait une collision
de blake2b-256. Donc, après la genèse, **toute pièce portant `X` descend, par continuations, d'une
pièce de la genèse**.

Hypothèses, en plus de celles de la v0.6 (§2 : verrou relatif, score des pièces créées, sorties ≤
entrées) : résistance de blake2b-256 aux collisions et aux secondes préimages ; règles N1 à N4
actives sur le réseau (Toccata : activé sur le réseau principal le 30 juin 2026 ; sur testnet-10, des
genèses et des continuations de coffres v0.5.1 ont été acceptées, `testnet/journal.md`).

## 3. Ce que dit le script du cœur v0.9 (lecture directe)

Une même règle dans chaque entrée : **la pièce a au plus une héritière, et c'est sa propre sortie.**

| Entrée | Règles v0.7 / v0.8 (inchangées) | Règle de lignée (v0.9) |
|---|---|---|
| `pay` (agent) | une entrée, deux sorties, sortie 1 au script `S`, `spent ≤ C`, âge `≥ ⌈spent·R/C⌉` | `OpAuthOutputCount(moi) == 1` et `OpAuthOutputIdx(moi, 0) == 1` : la sortie 1 est la seule héritière |
| `ownerControl`, branche « retour au coffre » | sortie `i` au script `S`, valeur `≥ v` | une seule héritière, la sortie `i` |
| `ownerControl`, branche « adresse de retour » | sortie `i` à l'adresse de retour, valeur `≥ v − C` | `OpAuthOutputCount(i) == 0` : aucune héritière |
| `absorb` (sans clé) | `C > 0`, sortie `i` au script `S`, valeur `≥ v + C` | une seule héritière, la sortie `i` |

**Lemme H (héritière).** Si une pièce portant `X` au script `S` est dépensée, la transaction contient
au plus une sortie portant `X` autorisée par cette entrée ; s'il y en a une, elle est au script `S`.
*Démonstration.* Toute dépense passe par l'une des trois entrées (toute autre finit par `OpReturn`).
Chacune fixe le nombre d'héritières (1, 1, 0 ou 1) et, quand il y en a une, son indice ; à cet indice,
le script exige déjà `S` (colonne du milieu). ∎

**Lemme P (pièce hors lignée).** Une pièce au script `S` qui ne porte aucune lignée ne peut être
dépensée que par `ownerControl`, vers l'adresse de retour.
*Démonstration.* `OpAuthOutputCount` vaut 0 pour une entrée sans lignée (N4) : `pay`, `absorb` et la
branche « retour au coffre » exigent 1. Reste la branche « adresse de retour », qui exige la signature
du propriétaire. ∎

## 4. La lignée ne grandit jamais

**Théorème (invariant de lignée).** Si la genèse de `X` crée `k` pièces, toutes au script `S`, alors à
tout instant : (I1) toute pièce portant `X` est au script `S` ; (I2) il y a au plus `k` pièces portant
`X`.

*Démonstration.* Par récurrence sur les transactions. Après la genèse : vrai par hypothèse. Soit une
transaction `T` acceptée. Par le lemme N, toute sortie de `T` portant `X` est une continuation,
autorisée par une entrée qui dépense une pièce portant `X` ; cette pièce est au script `S` (I1 avant
`T`) ; par le lemme H, elle autorise au plus une sortie `X`, au script `S`. Donc I1 tient après `T`, et
`T` crée au plus autant de pièces `X` qu'elle en consomme : I2 tient. ∎

Ceci ne dépend d'aucune clé : l'agent, un tiers et un voleur de la clé du propriétaire n'ont que ces
trois entrées. Seule la branche « adresse de retour » fait baisser le nombre de pièces, et elle exige
la signature du propriétaire.

**Emplacements.** On numérote les pièces de la genèse de 1 à `k`. L'*emplacement* `e` est la suite
des pièces qui descendent de la pièce `e` : chaque transaction qui consomme la pièce de l'emplacement
en recrée au plus une (lemme H). Un emplacement contient donc **zéro ou une pièce** à tout instant.

**À propos de la genèse.** L'hypothèse « toutes au script `S` » se vérifie sur la transaction de
genèse, publique : l'identifiant `X` engage l'indice, la valeur et le script de chaque pièce créée
(N2). L'outil la construit (`lignee::build_genese`) ; n'importe qui peut recalculer `X` à partir d'elle.
Le sas ne s'en remet pas à cette hypothèse : il vérifie aussi le script (§5).

## 5. La borne du coffre entier

**Théorème (emplacement).** Sur toute fenêtre `[a, a + D]`, ce que `pay` fait sortir d'un emplacement
vaut au plus `min(C, C·g/R) + C·D/R ≤ C + C·D/R`, où `g` est l'âge de sa pièce au score `a`, quels que
soient le nombre et le montant des regonflements.

*Démonstration.* C'est le théorème de l'emplacement de la v0.8 (`spec/borne-de-perte-v0.6.md`, §8.3) :
chaque paiement `sᵢ` au score `tᵢ` dépense une pièce créée au score `cᵢ ≥ tᵢ₋₁` (l'événement précédent
de l'emplacement), avec `sᵢ ≤ C·(tᵢ − cᵢ)/R` et `sᵢ ≤ C` (v0.6, §3) ; les intervalles `(cᵢ, tᵢ]` sont
disjoints et la somme télescope. Un regonflement (`absorb` ou `ownerControl`) remet l'âge à zéro : il
ne peut qu'abaisser la somme. La règle de lignée ne change aucune de ces inégalités. ∎

**Démonstration du théorème du coffre entier (§1).** L'argent du coffre est dans les pièces portant
`X`. La clé de l'agent ne les dépense que par `pay`. Par l'invariant de lignée, ces pièces occupent au
plus `k` emplacements, pour toujours. On somme le théorème de l'emplacement sur les `k` emplacements.
Rien d'autre n'entre dans la somme : un dépôt du sas (théorème du dépôt, ci-dessous), un don direct
(`absorb`) ou un rechargement du propriétaire grossissent une pièce d'un emplacement existant, sans en
créer. ∎

**Démonstration du théorème du dépôt.** Le sas n'a que deux entrées. `retour` : comme en v0.8
(lemme C). `recharger` exige : deux entrées, une sortie ; `blake2b(script de l'entrée 0) =
coffreSpkHash` ; `OpInputCovenantId(0) = lignee` ; sortie au script de l'entrée 0 ; `sortie ≥ v + d −
F`. Le dépôt est l'entrée 1 (lemme B de la v0.8 : il ne peut pas être l'entrée 0). L'entrée 0 est donc
une pièce au script `S` portant `X`, c'est-à-dire une pièce du coffre. Cette pièce obéit à son propre
script : `pay` est exclu (deux entrées) ; `absorb` et `ownerControl` (branche « retour au coffre », la
seule compatible avec « sortie au script de l'entrée 0 ») imposent que l'unique sortie soit son
héritière, dans la lignée. Une pièce consommée, une pièce créée : pas de pièce de plus. ∎

**Corollaire (S3 fermé).** Une pièce de poussière créée par un tiers à l'adresse du coffre ne porte
pas `X` (lemme N : elle ne descend pas de la genèse ; elle porte soit aucune lignée, soit une lignée
`Y ≠ X` née de sa propre genèse). Le sas refuse d'y verser un dépôt (`OpInputCovenantId(0) = lignee`).
Si elle ne porte aucune lignée, l'agent ne peut pas la dépenser et personne ne peut la regonfler
(lemme P).

**Corollaire (S5 fermé par construction).** Après un gel complet, il n'y a plus de pièce portant `X`,
et il n'y en aura plus jamais (lemme N). Un dépôt arrivé au sas après le gel ne peut donc plus être
versé au coffre par personne : seul le propriétaire peut le renvoyer à l'adresse de retour. Voir la
conséquence pour l'usage dans la note Red Team (L2).

**Prix de la gêne, frais.** Inchangés : `spec/borne-de-perte-v0.6.md`, §8.4 (au moins `C` donné au
propriétaire par regonflement sans clé) et §8.2 (au plus `F` de frais par dépôt).

## 6. Limite assumée : une autre lignée à la même adresse

Le script ne contient pas `X` et ne peut pas le contenir : `X` est un hachage qui engage le script
des pièces de la genèse (N2), donc le script ne peut pas engager `X` en retour. Il lit la lignée de la
pièce qu'il dépense, sans la comparer à une valeur fixe.

Conséquence : un tiers peut faire **sa propre genèse** à l'adresse `S`, avec **son** argent. Il crée
une lignée `Y ≠ X`, que l'agent peut dépenser au rythme du contrat. C'est un autre coffre, aux mêmes
réglages :
- aucun dépôt du sas ne peut y entrer (le sas est lié à `X`) ;
- aucune pièce de `X` ne peut y passer, et inversement (lemme N ; test
  `autre_lignee_a_la_meme_adresse_argent_du_tiers_seulement`, cinq passerelles tentées) ;
- l'argent qu'il contient vient de celui qui l'a créé : le dépenser n'est pas une perte du
  propriétaire ni d'un payeur. Le propriétaire peut le rapatrier (`ownerControl`).

Ce que cela impose à l'outil : identifier le coffre par **(adresse, lignée)**, jamais par l'adresse
seule ; ne compter et ne recharger que les pièces portant `X`.

Alternative non retenue : inscrire dans le script la pièce d'origine de la genèse et faire recalculer
`X` par le script (hachage à clé). Le compilateur figé connaît un opcode `OpBlake2bWithKey`, mais cette
voie n'a pas été prototypée ni vérifiée ici ; elle grossirait nettement le contrat (référence de la
pièce, valeurs de la genèse, sérialisation) pour fermer un cas où personne ne perd d'argent.

## 7. Règles de lignée, une par une

Chaque règle a été sabotée tour à tour (`lignee::tests::chaque_regle_sabotee_est_detectee`, 25
sabotages dont les 11 de la v0.8).

| Règle | Porteuse ? | Sans elle |
|---|---|---|
| sas : `OpInputCovenantId(0) == lignee` | oui | S3 : le dépôt est versé dans la pièce d'une autre lignée créée par l'attaquant |
| sas : empreinte du script de l'entrée 0 | oui si la genèse est mal faite | une pièce de la lignée placée sous le script d'un tiers lui livre le dépôt |
| sas : sortie au script de l'entrée 0 | oui (annoncée non porteuse en v0.8 : inexact) | la clé du propriétaire envoie une pièce du coffre et un dépôt, fusionnés, à l'adresse de retour sans passer par `retour` (même clé, même destination : pas de vol) |
| `pay` : `OpAuthOutputIdx(moi, 0) == 1` | oui | la poussière redevient du budget ; l'agent garde la lignée sur le bénéficiaire, ou en sort le reste |
| `pay` : `OpAuthOutputCount(moi) == 1` | non (doublée) | rien : avec exactement deux sorties, « la première héritière est la sortie 1 » implique « une seule » ; gardée pour se lire seule (R63) |
| `absorb` : une seule héritière | oui | n'importe qui ajoute une pièce à la lignée (un rythme de plus), y compris sous le script d'un tiers |
| `absorb` : l'héritière est la sortie `i` | oui | la pièce regonflée sort de la lignée et la lignée part sur une autre sortie |
| `ownerControl` (retour au coffre) : une seule héritière | oui | une clé de propriétaire volée multiplie les pièces du coffre |
| `ownerControl` (retour au coffre) : l'héritière est la sortie `i` | oui | idem, par une autre sortie |
| `ownerControl` (adresse de retour) : aucune héritière | oui | une clé de propriétaire volée garde ou déplace la lignée en gelant ; la lignée survivrait hors du coffre |

Les règles de la v0.8 gardent leur statut (`spec/borne-de-perte-v0.6.md`, §8.5), sauf la troisième
ligne ci-dessus.

## 8. Validation automatique

Tout s'exécute contre `kaspa-txscript` 2.2.0 (figé par `cli/Cargo.lock` ; structures de consensus : `kaspa-consensus-core` 2.1.0), avec le contexte de lignées construit par la fonction
du nœud (`CovenantsContext::from_tx`), le compilateur SilverScript figé (`7eb04634`), et les règles de
consensus copiées dans les tests (verrou relatif, sorties ≤ entrées).

| Test | Ce qu'il vérifie |
|---|---|
| `lignee::tests::coffre_a_lignee_legitimes_acceptees_attaques_refusees` | 15 transactions légitimes acceptées, 61 attaques nommées refusées (les 26 de la v0.8, 9 formes de S3, 7 « la poussière n'est pas du budget », 15 scissions, 4 dépôts détournés), chaque entrée exécutée |
| `lignee::tests::chaque_regle_sabotee_est_detectee` | 25 sabotages : chaque règle porteuse retirée laisse passer l'attaque attendue, et aucune transaction légitime n'est cassée |
| `lignee::tests::coffre_entier_sous_la_borne` | fuzzing d'état sur un registre de pièces tenu comme le réseau : coffre de 1 à 4 pièces né d'une vraie genèse, agent avide ou tricheur, dépôts, versements, gênes, poussières avec ou sans fausse lignée (vraies genèses), détournements, scissions, retraits. À chaque pas : lignée ≤ `k` pièces, toutes à l'adresse, une par emplacement ; **toute fenêtre glissante** sous `k(C + C·D/R)` et sous `C + C·D/R` par emplacement ; borne depuis la création ; valeur expliquée au sompi |
| `lignee::tests::s3_ouvert_en_v08_ferme_en_v09` | la même attaque passe sur la v0.8 archivée et ne passe plus en v0.9, sous 7 présentations |
| `lignee::tests::le_reseau_refuse_une_lignee_usurpee` | les règles N2 et N3 contre la fonction du nœud |
| `lignee::tests::autre_lignee_a_la_meme_adresse_argent_du_tiers_seulement` | la limite du §6, et l'absence de passerelle entre lignées |
| `lignee::tests::transactions_de_l_outil` | genèse, paiement, rechargement, gel, retour : acceptés, budgets de calcul, masse standard, plus petit paiement |
| `lignee::tests::versions_precedentes_archivees_a_l_identique` | sources et bytecodes v0.8, v0.7 et sas v0.1 inchangés |
| `tests/coeur_tests.rs::lignee_une_seule_heritiere`, `tests/sas_tests.rs::le_depot_ne_va_que_dans_la_lignee_du_coffre` | les mêmes règles dans le dépôt du compilateur figé |

**Non vérifié :** tout ce qui demande un nœud. Aucune transaction v0.9 n'a été diffusée. Restent à
observer sur testnet-10 : une genèse à plusieurs pièces, le relais d'une dépense sans signature
portant une lignée, les frais réels (une pièce à lignée pèse deux unités de stockage, KIP-9).

## 9. Retrait partiel (cœur v0.9.2)

Besoin : le propriétaire veut reprendre une partie de l'argent d'une pièce sans fermer le coffre. En
v0.9, `ownerControl` ne connaît que deux gestes : la pièce revient au coffre au moins entière, ou
elle part en entier à l'adresse de retour et quitte la lignée.

Le retrait partiel a d'abord été écrit comme une entrée séparée, `ownerWithdraw` (v0.9.1, archivée).
En v0.9.2 c'est une **branche de `ownerControl`**, avec les mêmes règles : la signature, la clé et la
règle d'héritière ne sont plus répétées (27 octets de moins que la v0.9.1 alors que la v0.9.2 porte
en plus la règle du §10 ; une v0.9.1 portant cette règle aurait fait environ 650 octets, estimation). Seul l'ordre
des deux sorties change, pour suivre la convention « entrée i, sortie i » de `ownerControl`.

### 9.1 Ce que dit `ownerControl` (lecture directe)

Pour une pièce de valeur `v` au script `S`, en entrée `i`, avec la signature du propriétaire :

| Sortie `i` | Geste | Règles |
|---|---|---|
| au script `S`, valeur `≥ v` | rechargement | une seule héritière, la sortie `i` |
| au script `S`, valeur `< v` | **retrait partiel** | une seule héritière, la sortie `i` ; règles 1 à 5 ci-dessous |
| autre script | gel | adresse de retour, valeur `≥ v − C`, aucune héritière, aucune lignée sur la sortie (§10) |

Règles du retrait partiel :

1. la transaction a **une** entrée et **deux** sorties (donc `i = 0` : la sortie 0 est le reste) ;
2. sortie 1 : un script dont l'empreinte blake2b vaut `retourSpkHash` (l'adresse de retour) ;
3. la sortie 1 ne déclare aucune lignée (§10) ;
4. `f = v − sortie 0 − sortie 1` (les frais) vérifie `f ≤ C` ;
5. l'âge de la pièce vaut au moins `⌈f·R/C⌉` (verrou relatif, la règle de `pay`).

C'est la forme de `pay` (une entrée, deux sorties, le reste dans la lignée), avec deux différences :
le signataire est le propriétaire, et le bénéficiaire est obligatoirement l'adresse de retour. En
échange, le montant repris n'est pas limité : seuls les frais le sont. Le réseau garantit `f ≥ 0`
(sorties ≤ entrées, une seule entrée).

**L'aiguillage est sûr.** Une pièce qui revient au coffre plus petite ne peut pas passer pour un
rechargement : la comparaison `sortie i < v` l'envoie dans la branche du retrait, qui exige d'être
seule (attaque « pièce du coffre rognée sous couvert de rechargement »).

### 9.2 Où va la valeur

**Lemme R (retrait).** Si une pièce de valeur `v` portant `X` au script `S` est dépensée par un
retrait partiel, alors `v = a + r + f` où : `a` va à l'adresse de retour dans une pièce **sans
aucune lignée** ; `r < v` reste dans **une** pièce au script `S` portant `X`, dans le même emplacement ;
`f ≤ C` part en frais. Aucune autre pièce n'est consommée ni créée.
*Démonstration.* Une entrée : aucune autre pièce du coffre (pas de fusion), aucun dépôt du sas,
aucune pièce d'un tiers ne participe. Deux sorties : il n'y a pas de troisième destination. La sortie
0 est au script `S` et c'est l'unique héritière : elle porte `X`. La sortie 1 est à l'adresse de
retour (règle 2) et ne déclare aucune lignée (règle 3). ∎

**Les lemmes de la v0.9 tiennent.** Lemme H (au plus une héritière, au script `S`) : la branche du
retrait est sous la même règle d'héritière que le rechargement (une, la sortie `i`, au script `S`).
Lemme P (pièce hors lignée) : le retrait exige une héritière, une pièce sans lignée n'en a pas
(N4) ; elle ne sort toujours que par `ownerControl`, en entier, vers l'adresse de retour.
L'**invariant de lignée** (§4) ne s'appuie que sur les lemmes N et H : il tient sans changement. Le
retrait partiel ne fait ni monter ni baisser le nombre de pièces ; chaque emplacement contient
toujours zéro ou une pièce.

**Une sortie n'est jamais comptée deux fois.** Avec `ownerControl` et `retour` (sas), l'entrée `i`
contrôle la sortie `i` ; si le retrait acceptait d'autres entrées, sa sortie 0 pourrait être aussi
« la sortie d'un gel » ou « le retour d'un dépôt », et une seule sortie satisferait deux règles : le
surplus partirait en frais ou chez un tiers. La règle 1 (une entrée) l'exclut par construction ;
c'est pour cela que le retrait ne se fait pas par lots. Attaques rejouées : « retrait partiel et gel
ensemble », deux formes.

### 9.3 La borne tient, frais des retraits compris

On appelle **fuite** d'un emplacement ce qui en sort sans aller ni au coffre ni à l'adresse de
retour : la dépense d'un `pay` (paiement + frais) et les frais `f` d'un retrait partiel.

**Théorème (emplacement, avec retraits).** Sur toute fenêtre `[a, a + D]`, la fuite d'un emplacement vaut
au plus `min(C, C·g/R) + C·D/R ≤ C + C·D/R`, où `g` est l'âge de sa pièce au score `a`, quels que
soient le nombre, l'ordre et les auteurs des paiements, retraits partiels, regonflements et
versements.

*Démonstration.* Chaque événement de l'emplacement consomme sa pièce et en recrée au plus une, dont
le score de création est celui de l'acceptation (v0.6, §2) : après **tout** événement, y compris un
retrait partiel, la pièce repart d'un âge nul. Soit un événement qui fuit `sᵢ > 0` au score `tᵢ`,
sur une pièce créée au score `cᵢ`. Que ce soit un `pay` (v0.6, §3) ou un retrait partiel (règles 4
et 5, la même inégalité, vérifiée par le même verrou) : `sᵢ ≤ C` et `sᵢ ≤ C·(tᵢ − cᵢ)/R`, avec `cᵢ`
au moins égal au score de l'événement précédent de l'emplacement. Les intervalles `(cᵢ, tᵢ]` sont
disjoints et inclus dans `(a − g, a + D]` ; la somme télescope comme au §5, et le premier terme est
plafonné par `C`. Les événements qui ne fuient rien (regonflement, versement, retrait sans frais)
ne font que raccourcir ces intervalles. ∎

**Corollaire (coffre entier).** Le théorème du §1 tient pour le cœur v0.9.2 en remplaçant « ce que
la clé de l'agent peut faire sortir » par la fuite : paiements de l'agent, leurs frais **et** frais
des retraits partiels, ensemble, valent au plus `k × (C + C·D/R)` sur toute fenêtre, même si les
deux clés sont compromises à la fois. Les retraits ne s'ajoutent pas à la borne : ils la partagent
(un retrait qui prend des frais remet l'âge à zéro, donc retire d'autant à l'agent).

**La pièce ne fait que diminuer** (`r < v`, lemme R) et **l'agent n'y gagne rien** : le reste est une
pièce neuve, d'âge nul ; un retrait fait attendre l'agent comme le ferait un rechargement.

### 9.4 Ce que peut une clé de propriétaire volée

| | v0.9 | v0.9.2 |
|---|---|---|
| Envoyer l'argent ailleurs qu'au coffre ou à l'adresse de retour | impossible | impossible (lemme R) |
| Ajouter une pièce à la lignée, fusionner des pièces | impossible | impossible (§9.2) |
| Détruire de l'argent en frais | au plus `C` par pièce, une fois (gel : la pièce quitte la lignée) | idem pour le gel ; par retrait partiel, au rythme du contrat : dans la borne `k × (C + C·D/R)`, partagée avec l'agent |

**Variante écartée.** Borner les frais du retrait par `C` seulement, comme ceux du gel, aurait été
plus simple (une règle de moins, pas d'attente). Mais un gel ne se répète pas (la pièce est partie),
alors qu'un retrait partiel se répète : une clé de propriétaire volée aurait pu brûler `C` de frais
par transaction, sans attendre, jusqu'à vider le coffre. Personne n'y gagne sauf un mineur, mais la
garantie « une clé volée ne détruit pas plus que le plafond » aurait été perdue. Test témoin :
`lignee::tests::cle_volee_ne_brule_pas_le_coffre_en_frais` (avec la règle : 9,5 KAS de frais en 19
périodes pour `C` = 0,5 KAS, sous la borne de 10,05 ; sans la règle : 9,5 KAS sur 10 sans attendre).

### 9.5 Le sas reste compatible avec le retrait

L'entrée `recharger` du sas ne change pas (seule `retour` gagne une règle, §10). Sa démonstration (§5, théorème du dépôt) énumère ce que la pièce du
coffre en entrée 0 peut faire dans un versement : `pay` est exclu (il exige une entrée), `absorb` et
`ownerControl` gardent la sortie dans la lignée. La branche « retrait partiel » de `ownerControl` est
exclue comme `pay` : elle exige une entrée, `recharger` en exige deux (et une seule sortie, alors que
le retrait en exige deux). De même `retour` ne peut pas partager une transaction avec un
retrait. Un dépôt ne peut donc pas être versé, ni renvoyé, dans la transaction d'un retrait partiel
(attaques « retrait partiel avec un dépôt du sas » et « retrait partiel et retour d'un dépôt sur la
même sortie »). Seule l'**adresse** du sas change, parce qu'elle engage l'empreinte du script du
coffre, qui n'est plus le même.

### 9.6 Limites assumées

- **Attente avant un retrait.** Les frais `f` exigent une pièce âgée de `⌈f·R/C⌉`. Avec les frais de
  l'outil (0,015 KAS) : 1 080 unités DAA (≈ 2 minutes) pour `C` = 0,5 KAS par heure ; 6 480 unités
  (≈ 11 minutes) pour `C` = 2 KAS par jour. Tout événement sur la pièce (paiement, rechargement)
  remet l'attente à zéro : un agent qui paie sans arrêt retarde le retrait partiel. Le propriétaire
  garde toujours la fermeture (`ownerControl`, sans attente, frais ≤ `C`) et l'arrêt de son agent.
- **Rechargement nul (W11).** `ownerControl` accepte que la pièce revienne au coffre « au moins
  entière » : donc aussi exactement entière, les frais étant payés par une autre pièce. Rien ne
  sort, mais l'âge de la pièce repart de zéro. Une clé de propriétaire volée peut le répéter et
  empêcher l'agent de payer (et retarder « Reprendre »), sans rien voler ni rien brûler du coffre.
  Ce n'est pas pire que ce que cette clé peut déjà faire (fermer le coffre). Parade écartée :
  exiger `valeur de sortie > valeur d'entrée` dans le contrat changerait le bytecode pour un gain
  nul (un sompi ajouté suffirait à la contourner). La console signale l'opération
  (`spec/red-team/systeme-2026-11-28.md`, W11) ; la réponse est de fermer le coffre, ce qui reste
  possible sans attente.
- **Une pièce par transaction**, par construction (§9.2).
- **Il doit rester quelque chose** : pour tout reprendre, c'est le gel (la pièce quitte la lignée).
  Le script accepte un reste minuscule ; c'est la masse de stockage du réseau (KIP-9) qui fixe le
  plancher pratique, et l'outil doit refuser un reste sous ce plancher.
- **Pièce hors lignée** (envoyée par un tiers) : pas de retrait partiel, seulement le rapatriement
  entier, comme en v0.9.
- **Réglages aberrants** (capacité ou période nulle ou négative, période ≥ 2³²) : aucun retrait avec
  frais n'est possible ; un retrait sans frais reste possible quand la capacité est positive, sans
  perte pour personne.
- **Taille** : 550 octets (+174 par rapport à la v0.9), dont 33 pour l'identifiant nul du §10 et 33
  pour l'empreinte de l'adresse de retour, lue dans deux branches.

### 9.7 Règles du retrait, une par une

| Règle | Porteuse ? | Sans elle |
|---|---|---|
| signature du propriétaire | oui | l'agent (ou n'importe qui) déplace l'argent vers l'adresse de retour et brûle des frais |
| aiguillage `sortie i < v` | oui | une pièce rognée passe pour un rechargement : la différence part chez un tiers |
| une entrée | oui | un gel et un retrait se partagent la sortie de retour : une pièce entière part en frais ou chez un tiers |
| deux sorties | oui | les « frais » partent chez un tiers par une troisième sortie |
| sortie 1 à l'adresse de retour | oui | la clé du propriétaire volée envoie l'argent où elle veut |
| une seule héritière, la sortie `i` (règle commune au rechargement) | oui | le reste sort de la lignée ; une pièce hors lignée devient retirable ; une pièce de plus dans la lignée |
| aucune lignée sur la sortie 1 | oui | la part reprise naît marquée d'une lignée neuve (§10) |
| `f ≤ C` | oui | une pièce ancienne laisse brûler plus que `C` d'un coup |
| âge `≥ ⌈f·R/C⌉` | oui | le coffre se vide en frais sans attendre (§9.4) |
| garde `period < 2³²`, `C ≤ MAX/period` | non (doublée par le compilateur) | rien avec des réglages sains ; gardée comme dans `pay` |

### 9.8 Validation automatique (v0.9.2)

Les chiffres du §8 deviennent : 20 transactions légitimes, **103 attaques nommées** (les 61 de la
v0.9, 34 sur le retrait partiel, 8 sur les pièces de retour marquées), **41 sabotages**. Le moteur
exécuté est `kaspa-txscript` tel que `cli/Cargo.lock` le fige (2.2.0 ; les structures de consensus
sont celles de `kaspa-consensus-core` 2.1.0).

| Test | Ce qu'il vérifie |
|---|---|
| `lignee::tests::coffre_a_lignee_legitimes_acceptees_attaques_refusees` | 5 retraits légitimes ; attaques : autre destination, signataire, pièce ajoutée à la lignée (2 formes), lignée déplacée ou perdue, fusion, lots, sortie comptée deux fois, dépôt du sas, pièce rognée sous couvert de rechargement, frais excessifs, frais trop tôt, verrou désactivé, pièce hors lignée (3 formes), autre lignée, pièces de retour marquées (8 formes) |
| `lignee::tests::chaque_regle_sabotee_est_detectee` | chaque règle du §9.7 et du §10 retirée ou affaiblie : l'attaque attendue passe, aucune transaction légitime n'est cassée |
| `lignee::tests::coffre_entier_sous_la_borne` | le fuzzing du coffre entier compte les frais des retraits comme une fuite : toute fenêtre glissante reste sous `k(C + C·D/R)` et sous `C + C·D/R` par emplacement, avec un propriétaire qui retire et une clé volée qui brûle le maximum permis puis tente un sompi de plus ; scissions par retrait refusées ; gels et retraits marqués d'une lignée neuve refusés ; valeur expliquée au sompi |
| `lignee::tests::cle_volee_ne_brule_pas_le_coffre_en_frais` | §9.4, avec son témoin |
| `lignee::tests::w10_piece_de_retour_ordinaire` | §10, avec ses témoins sur les versions archivées |
| `lignee::tests::transactions_de_l_outil` | `build_retrait_partiel` : accepté, budget de calcul, masse standard, verrou relatif du réseau, refus de l'outil |
| `lignee::tests::versions_precedentes_archivees_a_l_identique` | sources et bytecodes v0.9 et v0.9.1, source du sas v0.2 : archivés inchangés ; `pay` et `absorb` de la v0.9.2 sont ceux de la v0.9 au caractère près ; `recharger` du sas inchangé, `retour` = v0.2 plus une règle |
| `tests/coeur_tests.rs::retrait_partiel`, `piece_de_retour_sans_lignee`, `tests/sas_tests.rs` | les mêmes règles dans le dépôt du compilateur figé |

**Non vérifié :** tout ce qui demande un nœud, comme au §8. En particulier le relais d'un retrait
partiel et ses frais réels (donc l'attente réelle) sur testnet-10.

## 10. Une pièce de retour est une pièce ordinaire (cœur v0.9.2, sas v0.2.1)

**Le constat (W10).** Le réseau laisse une entrée ouvrir une lignée **neuve** `Z` sur n'importe
laquelle des sorties de sa transaction (genèse, N2), et `OpAuthOutputCount` ne compte que les
continuations (N4). Jusqu'à la v0.9.1, la règle « aucune héritière » du gel n'empêchait donc pas la
pièce envoyée à l'adresse de retour de naître marquée d'une lignée neuve. Sans effet sur la lignée
`X` ni sur la borne ; mais l'adresse de retour peut être celle d'une plateforme ou d'un portefeuille
simple, qui pourrait ne pas afficher une pièce portant un identifiant de covenant (non vérifié).

**La règle.** Partout où une sortie doit aller à l'adresse de retour, le script exige
`OpOutputCovenantId(sortie) == 0…0` : c'est la valeur que le moteur rend pour une sortie qui ne
déclare aucune lignée (`txscript/src/opcodes/mod.rs`, `covenant.map(…).unwrap_or(ZERO_HASH)`).
Trois endroits : `ownerControl` branche gel (sortie `i`), `ownerControl` branche retrait partiel
(sortie 1), `retour` du sas (sortie `i`).

**Lemme O (pièce ordinaire).** Toute pièce créée à l'adresse de retour par le cœur v0.9.2 ou le sas
v0.2.1 ne porte aucune lignée.
*Démonstration.* Les seules sorties que ces scripts envoient à l'adresse de retour sont les trois
ci-dessus ; chacune vérifie que la sortie ne déclare aucun identifiant ; la pièce créée porte
l'identifiant déclaré par sa sortie, ou aucun (N1). Un identifiant déclaré vaut-il jamais `0…0` ?
Une continuation exigerait une entrée portant l'identifiant nul, une genèse un hachage blake2b nul :
dans les deux cas la règle serait satisfaite par une pièce « marquée zéro », ce qui supposerait une
préimage de zéro. ∎

**Ce que la règle ne couvre pas, volontairement.**
- Le **bénéficiaire d'un `pay`**. Ce n'est pas l'adresse de retour : c'est un vendeur choisi par
  l'agent. Un agent compromis peut déjà payer n'importe qui, dans la limite de la borne ; marquer la
  pièce d'un vendeur ne lui fait rien gagner et ne coûte rien de plus au propriétaire. Durcir `pay`
  aurait modifié l'entrée la plus relue du contrat (inchangée depuis la v0.7) pour 36 octets, sans
  protéger les fonds du propriétaire. Conséquence pour l'outil : un vendeur qui vérifie un paiement
  doit regarder le montant **et** l'absence de lignée sur la sortie.
- Les **autres sorties** d'un rechargement (rendu du propriétaire) : elles ne sortent pas du coffre.
- Les coffres **v0.7 déjà déployés** : leur script ne change pas ; la limite y demeure.

**La règle d'origine reste porteuse.** « Aucune héritière » (`OpAuthOutputCount(i) == 0`) empêche
toujours qu'une héritière de `X` parte sur une AUTRE sortie pendant un gel ; la nouvelle règle ne
regarde que la sortie `i`.

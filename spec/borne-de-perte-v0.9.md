# Borne de perte du coffre entier : cœur v0.9, lignée KIP-20

Statut : contrat écrit, prouvé et testé contre le vrai moteur de script (27 nov. 2026). **Pas encore
déployé par l'outil, aucun essai sur le testnet.** Les coffres créés aujourd'hui restent en v0.7.

- Contrats : `contracts/coeur.sil` (cœur v0.9, 376 octets avec les paramètres de référence, +43 par
  rapport à la v0.8) et `contracts/sas.sil` (sas v0.2, 227 octets, +37).
- Ce document s'appuie sur `spec/borne-de-perte-v0.6.md` : §2 (les deux règles du réseau), §3 (un
  paiement, une chaîne), §7 (adresse de retour), §8 (`absorb`, sas, prix de la gêne). Il ne les répète
  pas ; il ajoute la lignée et en tire la borne **du coffre entier**.
- Tests : `cli/src/lignee.rs`, `tests/coeur_tests.rs`, `tests/sas_tests.rs`.
- Analyse d'attaque : `spec/red-team/lignee-2026-11-27.md`.

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

Lu dans le code de rusty-kaspa 2.1.0 (celui que le dépôt compile et que la CI exécute), pas supposé.

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

Tout s'exécute contre `kaspa-txscript` 2.1.0, avec le contexte de lignées construit par la fonction
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

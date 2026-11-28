# Vérifier qu'on finance LE bon coffre : protocole de vérification d'une adresse de dépôt

Version 1, 28 novembre 2026. Cœur v0.9.2, sas v0.2.1. Mise en œuvre de référence :
`cli/src/verification.rs` et `cli/src/coffre092.rs` (`vault-cli sas-verifier`). Tests :
`verification::tests`, `coffre092::tests`. Rapport d'attaque : `spec/red-team/genese-2026-11-28.md`.

## 1. À qui cela sert, et contre quoi

À un **tiers** : celui qui s'apprête à envoyer de l'argent à une adresse de dépôt (payeur, service
d'achat), le vendeur qui veut savoir quel budget le protège, l'auditeur. Il ne fait confiance ni à
celui qui lui remet l'adresse (souvent l'agent, ou un outil), ni à Plafond, ni à un nœud en
particulier. Il connaît une seule chose par un autre canal : **la clé publique du propriétaire**
du coffre qu'il veut financer.

Ce que le protocole doit empêcher :

| Attaque | Conséquence sans vérification |
|---|---|
| Adresse de dépôt remplacée | l'argent part chez l'attaquant |
| Sas d'une AUTRE lignée ouverte par l'agent à la même adresse de coffre | le dépôt alimente un budget de plus, hors du plafond annoncé |
| Création « hybride » : une pièce de la lignée sous le script d'un attaquant | la lignée a une pièce que le coffre ne contrôle pas |
| Création sur-allouée : plus de pièces que ce qui est annoncé | la borne réelle est multipliée sans que le payeur le sache |
| Continuation présentée comme création | on vérifie une transaction qui ne prouve rien |
| Sas d'un coffre fermé | le dépôt n'est versé nulle part et attend le propriétaire |
| Nœud qui ment sur ce qui existe | n'importe laquelle des précédentes |

## 2. La fiche de dépôt

Objet JSON, public, sans secret. C'est elle qu'on transmet, jamais une adresse seule.

| Champ | Contenu |
|---|---|
| `version` | `coeur-v0.9.2` |
| `coffre` | paramètres publics : `owner` et `agent` (clés publiques, 32 octets), `capacite` (C), `periode` (R), `retour` (empreinte blake2b du script de l'adresse de retour) |
| `genese` | `txid` de la création ; `entree_txid`, `entree_index` : la pièce dépensée par son entrée 0 ; `valeurs` : la valeur de chaque pièce créée, dans l'ordre (leur nombre est `k`) ; `repere` : bloc de tête noté avant la création, pour la relire |
| `lignee` | identifiant de covenant de la lignée (32 octets) |
| `adresse_coffre`, `adresse_depot` | les deux adresses, telles qu'on les présente |
| `max_frais_sompi` | plafond de frais du sas |
| `depot_minimal_sompi` | plus petit dépôt versé sans clé |
| `attestation` | signature Schnorr de `owner` |

**Ce que signe le propriétaire.** `blake2b-256` (personnalisation `PlafondDepotV1`) de
`adresse_coffre | lignee | adresse_depot`. Cette signature couvre tout le reste par construction :
l'adresse du coffre engage ses cinq paramètres (donc `retour`) ; la lignée engage la pièce d'origine
et toutes les pièces de la création (donc `k` et les valeurs) ; l'adresse de dépôt engage le coffre,
la lignée, l'adresse de retour, la clé du propriétaire et le plafond de frais. Rien de ce qui est
dans la fiche ne peut changer sans que l'une de ces trois valeurs change.

## 3. Les étapes, dans l'ordre

Chaque étape refuse ; aucune ne « corrige ».

**Étape 0. Le propriétaire.** `coffre.owner` est-elle la clé du propriétaire que le payeur
connaît ? (`sas-verifier --proprietaire <clé>` le fait pour lui.) Une fiche parfaitement cohérente
d'un AUTRE propriétaire est un autre coffre.

**Étape 1. Recalcul, hors ligne.**
1. Compiler le cœur v0.9.2 avec les cinq paramètres : on obtient le script `S` et l'adresse du
   coffre. Elle doit être `adresse_coffre`.
2. Recalculer l'identifiant de lignée comme le réseau (KIP-20) :
   `blake2b-256(clé « CovenantID » ; pièce d'origine ; pour i de 0 à k−1 : i, valeurs[i], S)`.
   Il doit être `lignee`.
3. Compiler le sas v0.2.1 avec (empreinte de `S`, `lignee`, `retour`, `owner`, `max_frais_sompi`) :
   on obtient l'adresse de dépôt. Elle doit être `adresse_depot`.
4. Vérifier `attestation` avec `owner`.
5. `depot_minimal_sompi` ne doit pas être inférieur à C.

*Ce que l'étape 2 prouve à elle seule.* L'identifiant de lignée est le hachage de TOUTES les
sorties qui ouvrent la lignée dans la création, avec leur indice, leur valeur et leur script. S'il
se recalcule avec « k sorties, toutes au script S », alors la création n'a ouvert la lignée nulle
part ailleurs et pas avec un autre nombre de pièces : une création hybride ou sur-allouée a un autre
identifiant (sauf collision de blake2b). Et une lignée ne naît qu'une fois : sa pièce d'origine ne
se dépense qu'une fois.

**Étape 2. La création relue.** Retrouver la transaction `genese.txid` sur le réseau (parcours des
blocs depuis `repere`), puis :
1. recalculer son identifiant : ce doit être `genese.txid` ;
2. son entrée 0 dépense la pièce d'origine annoncée ;
3. ses sorties qui portent `lignee` sont exactement les sorties 0 à k−1, toutes au script `S`,
   toutes autorisées par l'entrée 0, avec les valeurs annoncées ;
4. recalculer l'identifiant à partir de ces sorties lues : ce doit être `lignee` ;
5. aucune autre sortie de la création n'est au script `S` (pièce cachée, seconde lignée).

**Étape 3. Les pièces vivantes.** Lire toutes les pièces confirmées à l'adresse du coffre :
- au moins une porte `lignee` (sinon le coffre est fermé : refus) ;
- jamais plus de `k` ne la portent (sinon refus : ce serait une violation de l'invariant) ;
- les autres (autre lignée, sans lignée) sont comptées à part et ne sont PAS le coffre.

**Étape 4. Accord de nœuds.** Les étapes 2 et 3 sont faites sur au moins **deux nœuds
indépendants**, qui doivent donner exactement la même création et exactement les mêmes pièces. Un
désaccord est relu jusqu'à trois fois (une pièce peut être en cours d'inscription), puis refusé.

Alors seulement : **« Adresse vérifiée »**, avec `k`, le nombre de pièces vivantes, la valeur, le
dépôt minimal et la liste des nœuds.

## 4. Pourquoi deux nœuds, et lesquels

Un nœud ne fournit aucune preuve de ce qu'il affirme exister : il peut cacher une pièce, en
inventer une, ou « ne pas trouver » une transaction. L'étape 1 ne dépend d'aucun nœud ; les étapes
2 et 3, si. Choix retenu :

- le **nœud de l'utilisateur d'abord** s'il en a un (`NOEUD_WRPC`) : c'est le seul auquel il a une
  raison de se fier ; un second qu'il désigne (`NOEUD_WRPC_2`) ensuite ;
- sinon, des nœuds publics d'adresses différentes, tirés par le découvreur du réseau ;
- jamais de verdict sur un seul nœud, ni sur deux connexions au même nœud.

Limite assumée : deux nœuds publics peuvent appartenir au même exploitant, ou mentir de concert.
Deux nœuds complices ne peuvent cependant pas faire accepter une fausse fiche (étape 1) ni une
fausse création (étape 2, recalcul) ; il leur reste à mentir sur les pièces vivantes, c'est-à-dire
à faire croire qu'un coffre fermé est ouvert, ou l'inverse. Le dépôt resterait alors au sas, d'où
seul le propriétaire peut le renvoyer à l'adresse de retour : il n'est pas volé.

## 5. Création trop ancienne pour être relue

Les nœuds ordinaires n'ont pas d'index des transactions et élaguent les vieux blocs (ordre de deux
jours). Passé ce délai, ou pour un coffre créé avant l'ajout du repère (28 nov. 2026), l'étape 2
n'est plus possible sur un nœud ordinaire. Le verdict le dit (« création non relue ») et s'appuie
sur l'étape 1, qui prouve la même chose par le calcul. Un nœud d'archive permet de la relire.

## 6. Ce que le protocole ne dit pas

- Que le propriétaire est honnête : il peut fermer son coffre à tout moment.
- Que le coffre contient assez pour ce qu'on attend de lui : seulement sa valeur à l'instant lu.
- Rien sur les coffres v0.7 (sans lignée) : ils n'ont pas d'adresse de dépôt.

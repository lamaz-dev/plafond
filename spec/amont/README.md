# Correctif proposé au relais `kaspa-x402` (pièce marquée d'une lignée)

*Fable, 28 novembre 2026. Rien n'a été envoyé : ni demande de fusion, ni message. Philippe décide de l'envoi.*

## La question

Un agent qui paie depuis un coffre à lignée peut construire un paiement dont la pièce remise au
vendeur porte un identifiant de lignée (covenant id), y compris une lignée toute neuve (genèse
fraîche). Le script et le montant sont justes, mais la pièce n'est pas une pièce ordinaire : selon
le portefeuille du vendeur, elle peut ne pas apparaître ou rester soumise à des règles qu'il ne
contrôle pas (note Red Team du 28 novembre, point F2). Le cœur v0.9.2 ne l'interdit pas : c'est à
celui qui reçoit de refuser.

## Ce que nous avons lu chez Luke (dépôt `elldeeone/kaspa-x402`, commit `aa75523b`, 26 nov. 2026)

**Le relais refuse déjà ce paiement.** Trois barrières indépendantes, lues dans le code :

| Barrière | Fichier | Effet |
|---|---|---|
| Lecture de l'artefact | `protocol/packages/adapters/src/adapters.ts`, `parseSafeOutput` | toute sortie dont `covenant` n'est pas `null` est refusée, quel que soit le profil |
| Enveloppe du profil | même fichier, `assertStandardNativeTransactionEnvelope` et son pendant « additive » | « output N cannot carry a covenant » ; version 0 exigée en standard-native |
| Encodage canonique | `protocol/packages/covenant/src/exact-v0.ts`, `writeOutput` | « standard-native outputs cannot carry covenants » |

S'y ajoute le réseau lui-même : une transaction version 0 ne peut pas porter de lignée
(`CovenantBindingInV0`, rusty-kaspa `tx_validation_in_isolation.rs`), et l'identifiant d'une
transaction version 1 engage le champ covenant de chaque sortie (`hashing/tx.rs`, `write_output`).
Un artefact « propre » ne peut donc pas avoir le même identifiant qu'une transaction marquée.

**Il n'y a donc pas de faille à corriger chez Luke.** Nous ne l'annonçons pas comme telle.

## Ce que contient le correctif

`kaspa-x402-covenant.patch` (50 lignes ajoutées, deux fichiers) :

1. **Un test qui reproduit l'attaque** (`protocol/packages/adapters/test/adapters.test.ts`) : le
   paiement de référence du dépôt, auquel on ajoute une lignée sur la sortie du vendeur, en
   version 0 puis en version 1. Attendu : refus, **sans aucune lecture de la chaîne**. Ce
   comportement existait, mais aucun test ne le fixait : une refonte pouvait le perdre sans bruit.
2. **Une ceinture en plus de la bretelle** (`adapters.ts`, `assertChainTransactionMatchesSafe`) :
   quand le relais compare la transaction acceptée (lue chez l'indexeur) à l'artefact, il comparait
   montant et script des sorties, pas la lignée. Le correctif refuse une transaction acceptée dont
   une sortie porte une lignée. Sur une chaîne honnête ce cas ne peut pas se produire (voir
   ci-dessus) ; le contrôle ne protège que contre un indexeur qui se trompe ou qui ment sur
   l'identifiant. Le test du point 1 couvre aussi ce cas, et **échoue sans le correctif** (vérifié).

## Comment c'est vérifié

Sur une copie locale du dépôt de Luke (lecture seule, rien publié) :

```
cd protocol && npm ci --ignore-scripts && npm run build
git apply /chemin/vers/kaspa-x402-covenant.patch
cd packages/adapters && npx tsc --noEmit && npx vitest run     # 87 tests verts
cd ../server && npx vitest run                                  # 303 tests verts
```

Sans la modification de `adapters.ts`, le nouveau test échoue (« promise resolved instead of
rejecting ») : il mesure bien quelque chose.

## Ce qui n'est PAS vérifié

- La suite complète de Luke (`npm test` à la racine : preuves hors ligne, compatibilité x402,
  paquets client/facilitator/cli) n'a pas été lancée ; seuls `adapters` et `server` l'ont été.
- Les autres schémas du relais (chaîne de hachage, règlement par lots) utilisent volontairement des
  lignées : ils n'ont pas été audités ici et le correctif n'y touche pas.
- Le correctif n'a pas été essayé contre un vrai nœud.

## Côté Plafond

- **Vendeur Plafond** (`cli/src/x402.rs`, `preparer`) : refuse toute sortie vendeur portant une
  lignée, quelle qu'elle soit (« la sortie payée au vendeur porte un identifiant de lignée »).
  Test : `coffre_a_lignee_reconnu_par_adresse_et_lignee` (coffre à lignée et coffre v0.7).
- **Client du relais de Luke** (`cli/src/relais.rs`) : ne construit que des transactions version 0
  sans lignée, ne dépense jamais une pièce sous lignée, et refuse de relire un artefact marqué.
  Tests : `paiement_conforme_au_profil_standard_native`, `piece_marquee_refusee_dans_le_profil_exact`.
- Mémo pour les vendeurs tiers : [`cinq-verifications-vendeur.md`](cinq-verifications-vendeur.md).

# Essai du cœur v0.6 sur testnet-10, 24 novembre 2026

Exécuté par GitHub Actions (`testnet.yml`, branche `coeur-v0.6`) avec les clés de test du dépôt.
Journal brut : `testnet/journal.md`, entrées de 16:32 et 16:44 UTC.

| # | Étape | Résultat | Preuve sur le registre public |
|---|---|---|---|
| 1 | Créer le coffre : 5 TKAS, 4 TKAS/h, 0,5 au plus par achat ; pas de genèse, pas de lignée | ✅ | [de54a559…](https://tn10.kaspa.stream/transactions/de54a55966a26542e22a24d0309279ed990da9f794e465da05fa67f88ba1df7b) |
| 2 | Payer 0,05 TKAS une fois le budget rempli | ✅ accepté | [845152a0…](https://tn10.kaspa.stream/transactions/845152a01e23d66ddd9b26bb85eed08f039d4b738a00f957e792b27a9273e2f4) |
| 3 | Agent Python via le routeur : achat x402 de 0,2 TKAS. Le vendeur recompile le script, trouve la pièce et vérifie son âge (2 713 ≥ 2 212 exigés) | ✅ accepté | [6da83d62…](https://tn10.kaspa.stream/transactions/6da83d6275b8bd0fb46433ac6690403885ed5f9e08e2ecd2b08284b3ab5f3b9f) |
| 4 | Le vendeur demande 1 TKAS, au-delà du plafond | ✅ refusé avant tout paiement | — |
| 5 | Agent compromis : il contourne l'outil et diffuse 1 TKAS | ✅ **refusé par le réseau** (« script ran, but verification failed ») | transaction rejetée `bca98bd4…` |
| 6 | 0,45 TKAS juste après un achat, en annonçant tout l'âge réel de la pièce | ✅ **refusé par le réseau** (« locktime requirement not satisfied : 4783 > 600 ») | transaction rejetée `42f46b37…` |
| 7 | 0,05 TKAS, 90 s plus tard | ✅ accepté | [31256050…](https://tn10.kaspa.stream/transactions/31256050beea873135acf84063841011f1a88914acce69c41124ac0271cbabe1) |
| 8 | Courbe promise : perte nette 0,345 TKAS, sous la courbe (0,609 TKAS à cet instant) | ✅ | lu sur le nœud (`etat`) |
| 9 | Gel : toutes les pièces reviennent au propriétaire | ❌ puis ✅ après correctif | [89570617…](https://tn10.kaspa.stream/transactions/89570617fddf15bb8e18c1f87e7967700c042cade44de9ae6b93ada8c8fa0ac3) (+4,625 TKAS) |

**Bug trouvé et corrigé.** Au premier passage, le gel a été refusé huit fois, avec le message
« script units exceeded the amount committed in the input: used=100589, limit=59999 ». L'outil
déclarait 5 unités de calcul pour `ownerControl`, qui en consomme 11 (une vérification de
signature).

Le correctif (commit `d952629`) fait trois choses :
- il déclare 12 unités ;
- il ajoute le test `budget_de_calcul_du_gel_suffisant`, qui mesure ce coût contre le vrai moteur ;
- il relance le gel, qui passe du premier coup.

Les fonds n'ont jamais été en danger : seul le propriétaire pouvait les déplacer, et le coffre ne
laissait passer que ce que la courbe permet.

**Ce que l'essai confirme**
- **Le rythme est appliqué par le réseau lui-même.** Le refus n° 6 vient de
  `OpCheckSequenceVerify`, avec le délai exigé calculé par le script (4 783).
- **Le vendeur vérifie un coffre sans lignée.** L'adresse recompilée à partir des quatre
  paramètres suffit.

**Réseau.** Les nœuds publics du testnet ont encore souvent eu besoin d'un deuxième essai de
connexion. Ce n'est pas lié au coffre.

## 25 novembre : ardoise depuis le cœur v0.6, avec 4 pièces

| Étape | Résultat | Preuve |
|---|---|---|
| Coffre créé en 4 pièces (5 TKAS) | ✅ | [23953cad…](https://tn10.kaspa.stream/transactions/23953cad4759f4bfe36cba4189989b6361d5572a32eebbbcf4b8d6646d4b31e1) |
| Ardoise de 0,2 TKAS ouverte depuis le coffre, dès que le budget l'a couverte | ✅ | [6c39f155…](https://tn10.kaspa.stream/transactions/6c39f155b9e53bac79c60ae08949c64f85a9a2a5afc492aaf3e1646d9523d429) |
| Trois appels payés par bons cumulés, hors chaîne (0,03 puis 0,06 puis 0,1) | ✅ aucune transaction | — |
| Le vendeur encaisse le dernier bon (0,1 TKAS) en une transaction ; le reste revient au propriétaire | ✅ | [a9a7e30b…](https://tn10.kaspa.stream/transactions/a9a7e30b6c9cf175d16b1cec430798d68fb9744fe99e806bc3a534bdd9cb967c) |
| Perte nette 0,215 TKAS, sous la courbe promise (0,863) | ✅ | `etat` |
| Gel : les 4 pièces rapatriées en une transaction (4,665 TKAS) | ✅ | [ab9e4bcd…](https://tn10.kaspa.stream/transactions/ab9e4bcdc9e2c84201c393278cdc141503301110caff14e220a92dd1e43b2b3a) |

Trois appels payés n'ont coûté qu'une transaction au vendeur, et l'argent de l'ardoise ne
pouvait aller qu'à lui : c'est la liste blanche, garantie par le réseau.

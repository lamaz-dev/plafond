# Démonstration de bout en bout sur testnet-10, 22 novembre 2026

Binaire Windows compilé par la CI (`.github/workflows/windows.yml`, commit `8bac478`), lancé sur un
poste Windows avec des clés jetables du réseau de test, sans indexeur. **7 étapes sur 7 vérifiées.**

| # | Étape | Preuve sur le registre public |
|---|---|---|
| 1 | Créer un agent (« Démo DSI 63214 ») | — |
| 2 | Lui attribuer un budget (2 unités/jour, 0,5 au plus par achat) : coffre ouvert | [513c622e…](https://tn10.kaspa.stream/transactions/513c622ea5c7cf427f060cc4d4e7d39c597665bd432e7aae628e2010e75f4d91) |
| 3 | Lui donner un secret (chiffré pour lui seul, absent des fichiers et journaux) | — |
| 4 | Le connecter (clé installée côté agent, effacée de la console) | — |
| 5 | Payer un service : 0,3 unité | [c5ac822c…](https://tn10.kaspa.stream/transactions/c5ac822ce4fa392112856a842c51bdbf8a3ec5bc0d610817ea5d8386908512ce) |
| 6 | Tenter 0,45 unité (sous le plafond par achat, au-delà du budget restant) : **refusé par le réseau** (« failed to verify the signature script ») | transaction rejetée `a14384af…` |
| 7 | Arrêt d'urgence depuis une console à l'état périmé : coffre retrouvé en relisant la chaîne du nœud (677 blocs, sans indexeur), fonds rapatriés (+1,625) | [c11bf0cf…](https://tn10.kaspa.stream/transactions/c11bf0cf1e61fc7f4c3ac2c38191385995ee5fbb556d8ea9641a8c38e70cba82) |

Premier passage, le même jour : étapes 1 à 6 réussies (refus réseau `76f6371a…`), étape 7 interrompue
parce que le nœud public n'a pas répondu à une connexion. Correctif : trois essais de connexion,
un nouveau nœud à chaque essai (commit `8bac478`). Au second passage, plusieurs connexions ont
encore eu besoin d'un deuxième ou troisième essai : les nœuds publics du réseau de test sont
instables ; `NOEUD_WRPC` permet d'en fixer un.

Rapport brut de la démo : `demo-testnet-2026-11-22.json`.

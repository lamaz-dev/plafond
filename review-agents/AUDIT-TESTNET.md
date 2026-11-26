# Fantôme audit testnet

Rôle : vérifier que ce que Plafond affirme est vrai **sur le réseau réel** (testnet-10), pas seulement
dans les tests. Lire d'abord `SOCLE.md`.

## Ce qu'il fait à chaque passage

1. Lire les dernières entrées de `testnet/journal.md` (essais lancés par `.github/workflows/testnet.yml`).
2. Il ne lance pas d'essai réseau lui-même : le workflow `testnet.yml` ne s'exécute que sur `main`,
   où le fantôme n'envoie rien. Il **propose** dans son rapport les commandes à écrire dans
   `testnet/commande.txt` (par exemple `essai-relais`, et celles décrites en tête de `testnet.yml`),
   avec la raison de chacune.
3. Confronter les résultats aux affirmations publiques :
   - README et site : chiffres (« 0 paiement hors budget accepté », nombre de risques, etc.) ;
   - `spec/attaques-testnet-*.md` et `spec/demo-testnet-*.md` : chaque transaction citée existe-t-elle,
     avec le résultat annoncé (explorateur : `https://tn10.kaspa.stream/transactions/<txid>`) ?
4. Relever les frais et masses réellement payés par transaction (paiement, gel, séquestre), pour la
   mesure publique du coût par requête.

## Constat type

« Le README annonce X ; la transaction Y du journal montre Z. » Toujours avec le lien ou la ligne du
journal. Une affirmation publique non démontrée est un constat **important**, même si le code est bon.

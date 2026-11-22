# Démonstration de bout en bout (réseau de test)

Ce qu'elle montre, chaque étape étant contrôlée automatiquement :

1. créer un agent ;
2. lui attribuer un budget (2 unités par jour, 0,5 au plus par achat) : son coffre s'ouvre ;
3. lui donner un secret (clé d'API chiffrée pour lui seul) ;
4. le connecter : sa clé passe sur « son serveur », la console l'efface ;
5. il paie un service (service de démonstration que nous opérons) ;
6. il tente de dépasser son budget : **le réseau refuse** (pas un contrôle local) ;
7. arrêt d'urgence : les fonds du coffre reviennent dans la trésorerie.

Durée : 5 à 10 minutes (attentes de confirmation comprises). Aucun argent réel.

## Préparer (une fois)

1. Installer Rust (https://rustup.rs) et Git.
2. Récupérer le dépôt, puis compiler :
   ```
   cd kaspa-agent-vault-lab/cli
   cargo build --release
   ```
3. Choisir une phrase de test personnelle (16 caractères au moins, à ne jamais réutiliser ailleurs)
   et la mettre dans la variable `VAULT_PHRASE` :
   - Linux / macOS : `export VAULT_PHRASE="ma phrase de test personnelle"`
   - Windows (PowerShell) : `$env:VAULT_PHRASE="ma phrase de test personnelle"`
4. Afficher l'adresse de la trésorerie et l'approvisionner sur le distributeur de test
   (https://faucet-tn10.kaspanet.io/) : au moins 3 unités.
   ```
   ./target/release/vault-cli adresses
   ```

## Jouer la démo (deux terminaux, même dossier `cli`, même `VAULT_PHRASE`)

- Terminal 1 : `SANS_INDEXEUR=1 ./target/release/vault-cli console`, puis ouvrir le lien affiché. C'est l'écran à filmer :
  l'agent de démo apparaît dans l'onglet Agents, la perte maximale évolue, l'arrêt d'urgence la ramène à zéro.
- Terminal 2 : `./target/release/vault-cli demo`

À la fin, le terminal 2 affiche le bilan des 7 étapes et écrit un rapport `demo-rapport-<date>.json`
(liens vers chaque transaction sur l'explorateur public).

## Dépendances externes de la démo

- **Un nœud du réseau de test**, et rien d'autre pendant la démo. Par défaut, un nœud public est trouvé
  automatiquement ; pour supprimer aussi cette dépendance, indiquer le vôtre : `NOEUD_WRPC=ws://127.0.0.1:17210`.
- **Aucun indexeur.** Pour retrouver le coffre après un paiement de l'agent (arrêt d'urgence, recharge),
  la console relit la chaîne du nœud depuis un repère noté au déploiement (`…-repere.txt`, à côté de
  l'état). La démo interdit le repli sur l'API publique ; pour l'interdire aussi à la console :
  `SANS_INDEXEUR=1 ./target/release/vault-cli console`.
- Le distributeur de jetons de test ne sert qu'une fois, avant la démo. Les liens de l'explorateur dans
  le rapport sont de simples liens de consultation.

## En cas de souci

- « réseau de test injoignable » : connexion Internet, ou indiquer un nœud avec `NOEUD_WRPC=ws://…`.
- « parcours du nœud impossible » ou « lignée incomplète » : le nœud n'a peut-être plus l'historique
  depuis le repère (nœud élagué, coffre créé il y a plus d'environ un jour) ; relancer une démo neuve.
- « trésorerie insuffisante » : approvisionner l'adresse affichée.
- Étape 6 en échec (paiement accepté) : c'est une anomalie grave, garder le rapport et ne pas relancer.

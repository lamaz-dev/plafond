# Démonstration de bout en bout (réseau de test, aucun argent réel)

*[English](DEMO.md) · Français*

**Le plus rapide :** téléchargez le paquet prêt à l'emploi pour votre système sur [Releases](https://github.com/lamaz-dev/plafond/releases/latest), décompressez-le et lancez `./demo` (ou `Demo.bat`). Pas besoin de Rust. Pour compiler depuis le code source :

```
git clone https://github.com/lamaz-dev/plafond.git
cd plafond
./demo.sh
```

Prérequis : Git, Rust (https://rustup.rs) et un compilateur C (Linux : `build-essential` ; macOS : `xcode-select --install`).
Le script vérifie tout avant de commencer. Il ne demande aucune phrase ni aucun mot de passe : il crée des clés jetables du réseau de test.
La console s'ouvre toute seule dans votre navigateur : c'est l'écran à filmer. Si des jetons de test manquent, il affiche l'adresse, un QR code et le montant, puis reprend tout seul.
Durée : 5 à 10 minutes, plus la première compilation.

## Ce que la démo montre (chaque étape est contrôlée)

1. créer un agent ;
2. lui attribuer un budget (2 unités par jour, 0,5 au plus par achat) : son coffre s'ouvre ;
3. lui donner un secret (clé d'API chiffrée pour lui seul) ;
4. le connecter : sa clé passe sur « son serveur », la console l'efface ;
5. il paie un service (service de démonstration que nous opérons) ;
6. il tente de dépasser son budget : **le réseau refuse** (pas un contrôle local) ;
7. arrêt d'urgence : les fonds du coffre reviennent dans la trésorerie.

Avant le réseau, le script vérifie hors ligne que le contrat compilé est bien celui publié et qu'il refuse le
dépassement. À la fin : bilan des 7 étapes et rapport `cli/demo-rapport-<date>.json` (liens vers chaque transaction), écrit aussi
en cas d'échec, avec la cause de l'interruption : joignez-le à votre retour.

## Dépendances externes

- **Un nœud du réseau de test**, trouvé automatiquement, ou le vôtre : `NOEUD_WRPC=ws://127.0.0.1:17210 ./demo.sh`.
- **Aucun indexeur** : après un paiement de l'agent, la console retrouve le coffre en relisant la chaîne du nœud
  depuis un repère noté à sa création.
- Le distributeur de jetons de test, une seule fois. Les liens de l'explorateur sont de simples liens de consultation.

## En cas de souci

- « Rust absent », « compilateur C absent » : installer ce qui est indiqué, relancer `./demo.sh`.
- « réseau de test injoignable » (après 3 essais) : connexion Internet, ou indiquer un nœud avec `NOEUD_WRPC=ws://…`.
- « la console ne s'est pas ouverte » : une autre console occupe déjà le port 8404 ; la fermer, puis relancer (rien n'a été fait).
- « fonds non reçus après 20 min » : distributeur indisponible ; relancer plus tard, l'adresse reste la même.
- Étape 6 en échec (paiement accepté) : anomalie grave, garder le rapport et ne pas relancer.
- Repartir de zéro : supprimer `cli/demo-jetable/` (de nouvelles clés seront créées, donc de nouveaux jetons à demander).

## Utiliser Plafond avec votre propre compte (testnet-10)

La démo ci-dessus utilise des clés jetables. Pour garder un compte :

```
./plafond.sh          # Linux / macOS
Plafond.bat           # Windows, à côté de vault-cli.exe
```

La console s'ouvre verrouillée dans votre navigateur. La première fois, créez votre compte (mot de passe de 12
caractères au moins) : votre clé est créée et chiffrée sur votre ordinateur, dans le dossier `compte`. Ni e-mail, ni
serveur. Les fois suivantes, connectez-vous avec le mot de passe (et le code à 6 chiffres si la double
authentification est active). Mot de passe oublié ? « Restaurer avec ma phrase de 24 mots » recrée la clé sous un
nouveau mot de passe ; l'ancien fichier est conservé. Sauvegardez votre phrase de récupération dès la création, depuis
le bandeau.

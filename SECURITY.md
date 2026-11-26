# Security policy / Politique de sécurité

## Reporting a vulnerability / Signaler une faille

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
**Security** tab of this repository → **Report a vulnerability**.

**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt → **Report a vulnerability**.

Please include / Merci d'indiquer :
- the testnet-10 transaction id (TxID) if the attack was reproduced on chain / l'identifiant de la transaction sur le testnet-10 si l'attaque a été reproduite ;
- step-by-step reproduction / la méthode de reproduction, pas à pas ;
- the affected file and version (contract, vendor verification, tool) / le fichier et la version concernés.

We acknowledge reports within 7 days. Public disclosure: 30 days after the report, or as soon as a fix is published.
Accusé de réception sous 7 jours. Divulgation publique : 30 jours après le signalement, ou dès la correction publiée.

## Scope / Périmètre

Contracts `contracts/agent_budget.sil` (v0.5.1) and `contracts/delivery_escrow.sil` (v0.2), and the vendor-side
verification of the x402 "covenant-budget" profile (`cli/src/x402.rs`). Testnet only: **this code is a
prototype, not audited, and must not hold mainnet funds.**

Rules, out-of-scope items and the planned bounty: see [`BUG-BOUNTY.md`](BUG-BOUNTY.md).
Threat model: [`spec/threat-model.md`](spec/threat-model.md). Pre-audit package: [`spec/pre-audit.md`](spec/pre-audit.md).

## What the system guarantees / Ce que le système garantit

Enforced by Kaspa consensus, for each vault (lane), even if the agent key, the agent software,
the router or the server is compromised. Proof: [`spec/borne-de-perte.md`](spec/borne-de-perte.md);
reproduce it locally with `./verify-proof.sh`.

Garanti par le consensus de Kaspa, pour chaque coffre, même si la clé de l'agent, son logiciel,
le routeur ou le serveur sont compromis :

- **Loss bound / Borne de perte.** Over any real duration `D`, the agent moves out at most
  `capacity + capacity × D / refillPeriod` (amounts plus fees), never more than the vault balance.
  With the "strict" setting (`capacity = budget / 2`, `refillPeriod = period`): at most the
  announced budget over any window of one period, and half of it immediately.
- **Per-payment cap / Plafond par achat**, and the optional payee allowlist.
- **Owner control / Contrôle du propriétaire.** Only the owner key opens `ownerControl`
  (freeze, withdraw, refill). Since core v0.7, even the owner key can only send a vault coin back to
  the vault (refill, value never decreases) or to the **return address** fixed at creation, with at most
  `capacity` of fees per coin. A stolen owner key therefore cannot send vault funds anywhere else.
  If the return address is the owner's treasury (default), the thief could then empty that treasury,
  which is not a vault: choose a return address whose key is not on the console computer (Ledger,
  multisig, custodian) for full protection.
  Depuis le cœur v0.7, même la clé du propriétaire ne peut renvoyer une pièce que vers le coffre
  (rechargement) ou vers l'adresse de retour fixée à la création, au plus `capacity` de frais par
  pièce. Protection complète : une adresse de retour dont la clé n'est pas sur l'ordinateur de la console.
- **No hidden outputs, no payload, one lineage** (KIP-20).

## What the system does NOT guarantee / Ce que le système ne garantit pas

- recovery of a lost owner password or key file (there is no custodian; keep a backup) /
  la récupération d'un mot de passe ou d'un fichier de clé perdu (personne ne détient la clé ; faites une sauvegarde) ;
- protection against compromise of the owner's own device / la protection contre la compromission de l'appareil du propriétaire ;
- the secrecy of the agent key on the agent's machine: it is stored unencrypted there (see below); the loss stays capped by the contract /
  le secret de la clé de l'agent sur sa machine : elle y est stockée sans chiffrement (voir plus bas) ; la perte reste plafonnée par le contrat ;
- the KAS exchange rate: budgets are in KAS, fiat amounts are indicative / le cours du KAS : les budgets sont en KAS, les montants en euros sont indicatifs ;
- the honesty or security of third-party vendors (paying does not guarantee delivery, except through the escrow) /
  l'honnêteté ou la sécurité des vendeurs tiers (payer ne garantit pas la livraison, sauf via le séquestre) ;
- availability: a payment can be delayed or refused (network, fees, mass limits); funds stay safe /
  la disponibilité : un paiement peut être retardé ou refusé ; les fonds restent protégés ;
- exact wall-clock time: the network counts DAA scores (target 10 per second, about 864,000 per 24 h) /
  l'heure exacte : le réseau compte des scores DAA (environ 864 000 par 24 h).

## Keys and secrets on disk / Clés et secrets sur le disque

How the tool stores what it must keep (behaviour of the tool, not a consensus guarantee).
Comment l'outil conserve ce qu'il doit garder (comportement de l'outil, pas une garantie du consensus).

**On the owner's computer (console) / Sur l'ordinateur du propriétaire (console)**

- Owner key: encrypted with the owner's password (Argon2id + XChaCha20-Poly1305), never stored in clear.
  Clé du propriétaire : chiffrée par son mot de passe, jamais en clair.
- Agent keys kept by the console (an agent not yet connected, and the main agent): encrypted with a
  key derived from the owner's private key (HMAC-SHA256 with the label `plafond/cle-agent/v2`, then
  XChaCha20-Poly1305; the file is bound to both the agent's and the owner's public keys, so it does
  not open under another owner). They are therefore worth exactly what the owner key is worth, and
  the owner key is itself only stored encrypted with the password. A key left in clear, or encrypted
  with the password by an earlier version (format v1), is re-encrypted the next time the account is
  opened: the new file is written, read back and checked before the old one is erased. Once an agent
  is connected, the console erases its copy and keeps only the public key.
  Clés d'agent gardées par la console (agent pas encore connecté, agent principal) : chiffrées par une
  clé dérivée de la clé privée du propriétaire (HMAC-SHA256, étiquette `plafond/cle-agent/v2`, puis
  XChaCha20-Poly1305 ; le fichier est lié aux clés publiques de l'agent et du propriétaire : il ne
  s'ouvre pas sous un autre propriétaire). Elles valent donc exactement ce que vaut la clé du
  propriétaire, elle-même stockée uniquement chiffrée par le mot de passe. Une clé laissée en clair,
  ou chiffrée par le mot de passe par une version précédente (format v1), est rechiffrée à l'ouverture
  suivante du compte : le nouveau fichier est écrit, relu et vérifié avant l'effacement de l'ancien.
  Une fois l'agent connecté, la console efface sa copie et ne garde que la clé publique.
- Forgotten password: restoring the account from the 24 words sets a new password and recreates the
  same owner key, so the agent keys kept by the console stay readable: agents not yet connected can
  still be connected. Consequence: whoever holds the 24 words (or the owner key) can also read these
  agent keys. Only exception: an agent key still in the old v1 format, encrypted under the forgotten
  password, can no longer be read: its vault stays visible, fundable and freezable (public key only),
  but that agent must be stopped and created again.
  Mot de passe oublié : restaurer le compte depuis les 24 mots fixe un nouveau mot de passe et recrée
  la même clé de propriétaire : les clés d'agent gardées par la console restent lisibles, et un agent
  pas encore connecté peut toujours l'être. Conséquence : qui détient les 24 mots (ou la clé du
  propriétaire) peut aussi lire ces clés d'agent. Seule exception : une clé d'agent encore à l'ancien
  format v1, chiffrée sous le mot de passe oublié, n'est plus lisible : son coffre reste visible,
  alimentable et gelable (clé publique seule), mais cet agent doit être arrêté puis recréé.
- Test and demo keys (no password): stored in clear, testnet only.
  Clés de test et de démonstration (sans mot de passe) : en clair, réseau de test uniquement.
- Console link: the link printed in the terminal carries a one-time ticket valid for two minutes, not
  the session token. Press Enter in the terminal to get a new link; opening a new link closes the
  previous session.
  Lien de la console : le lien affiché dans le terminal porte un ticket à usage unique valable deux
  minutes, pas le jeton de session. Appuyez sur Entrée dans le terminal pour obtenir un nouveau lien ;
  ouvrir un nouveau lien ferme la session précédente.

**On the agent's machine / Sur la machine de l'agent**

- **The agent key is NOT encrypted there. This is an accepted limit.** The agent pays without a human:
  nobody is present to type a password. The key file is readable by its user only. Whoever reads it
  can spend, but never beyond what the contract allows (loss bound above), and the owner can freeze
  the vault from the console at any time. Size the mandate accordingly.
  **La clé de l'agent n'y est PAS chiffrée. C'est une limite assumée.** L'agent paie sans humain :
  personne n'est là pour saisir un mot de passe. Le fichier de clé n'est lisible que par son
  utilisateur. Qui le lit peut dépenser, mais jamais au-delà de ce que le contrat autorise (borne de
  perte ci-dessus), et le propriétaire peut geler le coffre depuis la console à tout moment.
  Dimensionnez le mandat en conséquence.
- Agent secrets (API keys) are encrypted for the agent key: they are worth what that key file is worth.
  Les secrets de l'agent (clés d'API) sont chiffrés pour la clé de l'agent : ils valent ce que vaut ce fichier.
- Connection kit: `agent-installer` installs, checks that the key and every secret are readable, then
  erases the kit file. If anything fails, the kit is kept so you can retry. Also delete the copy
  downloaded on the owner's computer.
  Kit de connexion : `agent-installer` installe, vérifie que la clé et chaque secret sont lisibles, puis
  efface le fichier du kit. Au moindre échec, le kit est conservé pour réessayer. Supprimez aussi la
  copie téléchargée sur l'ordinateur du propriétaire.

**File permissions / Droits des fichiers**

- Linux, macOS: sensitive files (keys, secrets) are created with mode 0600.
  Linux, macOS : les fichiers sensibles (clés, secrets) sont créés avec les droits 0600.
- Windows: there is no 0600. Sensitive files are created with a protected access list containing a
  single entry, the current user (nothing inherited from the folder). An administrator of the computer
  can still take ownership of any file, as on any system.
  Windows : il n'y a pas de 0600. Les fichiers sensibles sont créés avec une liste d'accès protégée à
  une seule entrée, l'utilisateur courant (rien n'est hérité du dossier). Un administrateur de
  l'ordinateur peut toujours s'approprier un fichier, comme sur tout système.
- Erasing a file overwrites it and then deletes it. On SSDs and copy-on-write file systems the old
  content may physically remain.
  Effacer un fichier le réécrit puis le supprime. Sur SSD ou système de fichiers à copie sur écriture,
  l'ancien contenu peut subsister physiquement.

## Advisories / Avis de sécurité

- [2026-11-20, AgentBudget v0.4: refill time could be "set aside"](spec/advisories/2026-11-20-v0.4-temps-mis-de-cote.md)
  (fixed in v0.5, found by our own loss-bound test / corrigé en v0.5, trouvé par notre propre test de borne).
- [2026-11-20, first independent review: survival-mode decoy, owner freeze priority, parameter guards](spec/advisories/2026-11-20-v0.5-relecture-independante.md)
  (fixed in v0.5.1 / corrigé en v0.5.1).

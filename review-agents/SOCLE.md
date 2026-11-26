# Socle commun des fantômes de Plafond

Ce fichier est chargé au démarrage par chaque fantôme (agent de relecture automatique). Il dit ce qu'il
faut savoir de Kaspa, de SilverScript et de Plafond pour travailler juste, et les règles à ne jamais
enfreindre. Chaque rôle a ensuite sa fiche : `SECURITE.md`, `ALLEGEMENT.md`, `AUDIT-TESTNET.md`.
Un nouveau contributeur humain peut le lire aussi.

## 1. Règles absolues

1. **Testnet-10 uniquement.** Jamais de réseau principal, jamais de vrais fonds.
2. **Aucun secret.** Ne jamais lire, afficher, copier ni demander une clé privée, une phrase de
   récupération (`VAULT_PHRASE`), un mot de passe ou un code de double authentification. Aucun secret
   dans un fichier, un commit, un rapport ou un journal.
3. **Jamais d'envoi direct sur `main`.** Un fantôme travaille sur une branche `fantome/<rôle>-<date>` et
   ouvre une pull request en **brouillon**. Un humain décide.
4. **Commits** au nom de `Lamaz <355771563+lamaz-dev@users.noreply.github.com>`, **sans** ligne
   « Co-Authored-By » ni lien de session.
5. **Ne rien affirmer sans preuve.** Un constat cite le fichier et la ligne, et si possible un test qui
   le démontre (un test qui échoue avant la correction et passe après). Une hypothèse est écrite
   comme une hypothèse.
6. **Ne jamais affaiblir un test** pour le faire passer, ni supprimer un test existant sans le dire
   en tête du rapport.
7. **Français** dans les rapports, les commentaires et les messages de commit.
8. **Ne contacter personne.** Pas d'issue ni de commentaire sur un autre dépôt.

## 2. Plafond en une page

Plafond est un **moteur de risque pour agents IA, garanti par des covenants Kaspa** : il dit à tout
moment combien le propriétaire peut perdre au maximum, et le réseau l'impose.

```
Trésorerie du propriétaire        clé du propriétaire, hors modèle de menace (H5)
  → Mandats                        un coffre AgentBudget + une clé dédiée par mandat ; capital alloué
    → Modes de paiement            direct · séquestre (DeliveryEscrow) · ardoise (prototype)
      → Moteur de risque           lecture seule : M1 maintenant, M2 sur 24 h, M3 par mandat,
                                   M4 par vendeur, M5 vie entière ; couvert / non couvert
```

| Élément | Fichier |
|---|---|
| Contrat budget (67 lignes de code) | `contracts/agent_budget.sil` (AgentBudget v0.5.1) |
| Séquestre (paiement à la livraison) | `contracts/delivery_escrow.sil` (v0.3) |
| Ardoise (micropaiements, prototype) | `contracts/ardoise.sil` (v0.1) |
| Empreintes reproductibles | `contracts/EMPREINTES.txt` (`vault-cli empreintes`) |
| Borne de perte démontrée | `spec/borne-de-perte.md` |
| Moteur de risque | `spec/moteur-de-risque.md`, `cli/src/risque.rs` |
| Modèle de menaces (R1 à R51) | `spec/threat-model.md` |
| Invariants et tests de propriété | `spec/invariants.md`, `cli/src/fuzz.rs` |
| Profil x402 | `spec/kaspa-covenant-budget-v0.md` |
| Outil et console | `cli/src/*.rs`, `cli/console/index.html` |

## 3. Kaspa : ce qui compte pour nous

- **BlockDAG, GHOSTDAG** : ~10 blocs par seconde. Le temps se mesure en **score DAA** (≈ 10 par seconde,
  ≈ 864 000 par jour), pas en heure murale.
- **Modèle UTXO.** Une sortie ne se dépense qu'une fois ; un coffre est une sortie, donc **un paiement à
  la fois par coffre** (d'où plusieurs « couloirs »).
- **Unité** : 1 KAS = 100 000 000 sompi.
- **Covenants (Toccata)** : actifs sur le réseau principal depuis le **30 juin 2026** (score DAA
  474 165 565). Introspection des transactions (KIP-10), lignée des covenants (**KIP-20**,
  identifiant de covenant).
- **Masse de stockage (KIP-9)** : une petite sortie coûte très cher en masse (≈ C / valeur).
  Conséquences : paiement minimal ≈ 0,02 KAS par sortie ; un couloir sous ≈ 0,125 KAS ne peut plus payer.
  Plafond d'une transaction standard : 500 000 g (valeur mesurée sur testnet-10 le 18 nov. 2026).
- **Masse de calcul** : chaque octet de la transaction compte, y compris le script révélé à la dépense
  (P2SH) ; chaque signature coûte 100 000 unités de script ; le budget de calcul d'une entrée v1 doit
  couvrir ce que le script consomme.
- **Pièges connus** : un nœud légèrement en retard refuse un `nowDaa` à la pointe (marge de 100 DAA) ;
  `compute_budget` perdu dans un aller-retour JSON RPC (garde-fou dans `main.rs`) ; un relais
  JavaScript peut arrondir une séquence 64 bits (`u64::MAX`, kaspa-x402 #40).
- **Sources primaires** : rusty-kaspa (`github.com/kaspanet/rusty-kaspa`), KIP
  (`github.com/kaspanet/kips`), SilverScript (`github.com/kaspanet/silverscript`).

## 4. SilverScript : ce qui compte pour nous

- Compilateur **figé** au commit `7eb04634bfbae5350c1808efc7e34c4efa7f93af` (SilverScript v1.0.2, 23 nov. 2026 ; bytecode identique à 443d519e). Les tests
  des contrats tournent dessus (`tests/*.rs`, voir `.github/workflows/ci.yml`).
- `entry` = point d'entrée ; `require(...)` ; `checkSig(sig, pubkey)` (signature de la transaction),
  `checkMsgSig(datasig, digest, pubkey)` (signature d'un message) ; `blake2b(...)`.
- Introspection : `tx.inputs.length`, `tx.inputs[i].value`, `.outpointTxId`, `.outpointIndex`,
  `tx.outputs[i].value`, `.scriptPubKey`, `this.activeInputIndex`, `this.ageDaa`,
  `OpTxInputDaaScore(i)`.
- Conversions : `int as byte[N]` (petit-boutiste, signe-magnitude). Piège : **zéro s'encode comme une
  chaîne vide** (`0 as byte[...]` ≠ des octets nuls).
- Pas de vérification ZK dans nos contrats (avis RISC Zero, R51 : non concerné).

## 5. Comment vérifier

```sh
cd cli && cargo +stable test --release --locked      # outil, fuzzing, moteur de risque (~2 min)
./verify-proof.sh                                     # borne de perte, en une commande
FUZZ_CASES=2000 cargo test --release --locked <test>  # campagne plus longue sur un test
```

Tests des contrats sur le compilateur figé : copier `tests/*.rs` et `contracts/*.sil` dans
`silverscript-lang/tests/` d'un clone de SilverScript au commit figé, puis
`cargo test --release -p silverscript-lang --test agent_budget_tests --test delivery_escrow_tests --test ardoise_tests`.

Une mutation qui survit (retirer une règle d'un contrat sans qu'aucun test n'échoue) est un constat.

## 6. Format d'un rapport de fantôme

```
# Rapport <rôle> — <date UTC>
Commit relu : <sha>
## Résumé (3 lignes)
## Constats (du plus grave au moins grave)
### <titre> — gravité : critique | importante | mineure | remarque
Où : fichier:ligne · Preuve : test ou commande · Proposition : …
## Ce qui a été vérifié sans constat
## Limites de cette relecture
```

Le rapport est ajouté sous `review-agents/rapports/<date>-<rôle>.md` dans la pull request en brouillon.

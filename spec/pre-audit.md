# Dossier de pré-audit — Plafond (anciennement kaspa-agent-vault)

*Pour l'auditeur externe et les participants à la prime aux bugs. Tout ce qui est affirmé ici est vérifiable dans le dépôt, avec la commande ou le test indiqué.*

## 1. Périmètre

| Élément | Fichier | Taille | Statut |
|---|---|---|---|
| Coffre AgentBudget v0.5 | `contracts/agent_budget.sil` | 479 octets (paramètres de référence) | dans le périmètre |
| Séquestre DeliveryEscrow v0.2 | `contracts/delivery_escrow.sil` | 242 octets | dans le périmètre |
| Vérification côté vendeur (profil x402) | `cli/src/x402.rs`, fonction `verify_and_settle` | — | dans le périmètre (logiciel hors chaîne) |
| Outil de démonstration | `cli/src/main.rs` | — | hors périmètre, sauf construction des transactions |

Hors périmètre : voir `spec/threat-model.md` §5 et `BUG-BOUNTY.md`.

## 2. Ce qui est figé

| Élément | Valeur | Vérification |
|---|---|---|
| Compilateur SilverScript | révision `443d519e6688fa03d24c69432763b13e6abe4486` | `cli/Cargo.toml`, `cli/Cargo.lock` |
| Chaîne d'outils Rust | 1.97.0 | `cli/rust-toolchain.toml` |
| Dépendances | figées (`--locked`) | `cli/Cargo.lock` |
| Empreintes des sources et du bytecode | `contracts/EMPREINTES.txt` | recalculées et comparées à chaque envoi par la CI publique (`.github/workflows/ci.yml`) |

Reproduire : `cd cli && cargo build --release --locked && ./target/release/vault-cli empreintes | diff - ../contracts/EMPREINTES.txt`.

Le bytecode dépend des paramètres du coffre (clés, plafonds, état). Pour un coffre réel, le vendeur recompile les paramètres annoncés et compare le P2SH obtenu à l'UTXO sur la chaîne : il ne fait confiance à aucun bytecode transmis.

## 3. Schémas des transactions

Notations : `V` valeur du coffre, `P` paiement, `F` frais, `S` séquestre. Toutes les transactions sont en version 1, chaque entrée porte un budget de calcul (`compute budget`).

### Déployer (propriétaire)

```
entrées : UTXO P2PK du propriétaire (1 à 20), budget de calcul 15 chacune
sorties : [0] coffre  V   P2SH(AgentBudget, tokens=capacity, lastDaa=now)   covenant = genèse(entrée 0, sortie 0)
          [1] monnaie     P2PK propriétaire (facultative)
```
L'identifiant de lignée (KIP-20) est `covenant_id(outpoint de l'entrée 0, [(0, sortie 0)])`.

### Payer (agent, entrée `pay`)

```
entrée  : [0] coffre V, covenant C, budget de calcul 20
          signature : sig_agent (SIGHASH_ALL), amount, nowDaa
sorties : [0] paiement   P         vers le destinataire (liste blanche facultative)
          [1] continuation V-P-F   P2SH(AgentBudget, tokens', lastDaa=nowDaa)  covenant C, autorisée par l'entrée 0
verrou temporel : lockTime = score DAA, avec lockTime ≥ nowDaa
payload : vide
```
Règles du script : invariants I1 à I11 (`spec/invariants.md`).

### Payer un séquestre (agent, entrée `pay`)

Identique à « Payer », la sortie 0 étant `P2SH(DeliveryEscrow)` sans covenant (une seule unité de stockage).

### Contrôle du propriétaire (entrée `ownerControl`)

```
entrées : [0] coffre (signature du propriétaire), [1..n] UTXO P2PK du propriétaire (facultatifs)
sorties : libres
```
Utilisé pour récupérer le coffre (sortie unique vers le propriétaire), le recharger (continuation de même état et même lignée, valeur augmentée) ou valider une dépense hors budget. Aucune contrainte autre que la signature : c'est voulu (I12, non-blocage).

### Réclamer un séquestre (vendeur, entrée `claim`)

```
entrée  : [0] séquestre S, seule entrée (v0.2), séquence 0, budget de calcul 15
          signature : preuve = Schnorr(vérificateur, blake2b(requestHash ‖ resultHash)), resultHash
sortie  : [0] S-F vers l'adresse du vendeur figée à la création, F ≤ maxFee
```
Pas de signature du vendeur : la destination est figée, n'importe qui peut diffuser la réclamation une fois la preuve publiée.

### Rembourser un séquestre (n'importe qui, entrée `refund`)

```
entrée  : [0] séquestre S, seule entrée (v0.2), séquence = timeoutDaa (verrou relatif), budget de calcul 5
sortie  : [0] S-F vers l'adresse de remboursement figée à la création, F ≤ maxFee
```

## 4. Hypothèses sur le consensus Kaspa

| # | Hypothèse | Sur quoi elle repose |
|---|---|---|
| H1 | `tx.daa` (verrou temporel absolu) ne peut pas dépasser le score DAA réel : une transaction au verrou futur n'est pas acceptée | règle de finalité du consensus |
| H2 | `this.ageDaa` (verrou relatif via la séquence) n'est satisfait qu'après `timeoutDaa` blocs de maturité de l'UTXO | observé sur testnet-10 : « sequence locks conditions was not met » (essai 8) |
| H3 | Une sortie liée à un covenant n'est acceptée que si une entrée de la même lignée l'autorise (KIP-20) | test `continuation_hors_lignee_refusee` |
| H4 | L'identifiant de transaction exclut les scripts de signature : une signature réécrite en transit ne change pas l'identifiant | R20 ; observé sur testnet-10 : la fausse et la vraie réclamation ont le même identifiant |
| H5 | Arithmétique du script sur entiers signés 64 bits ; dépassement et division par zéro = échec du script, jamais de retour à zéro | **vérifié dans le code** : `kaspa-txscript` 2.1.0, `opcodes/mod.rs`, `OpAdd`/`OpSub`/`OpMul` en `checked_*` (`NumberTooBig`), `OpDiv`/`OpMod` en `checked_div`/`checked_rem` (`InvalidState`) ; garde `check_params` (P4) ; test `parametres_aberrants_sans_danger_pour_les_fonds` |
| H6 | Limite de masse de stockage 500 000 g, frais de relais calculés sur la masse de calcul et transitoire seulement | mesuré sur testnet-10 (essai 8) ; code du nœud |
| H7 | La cadence du réseau (10 blocs/s) peut changer : les durées comptées en blocs changent de durée réelle | R6 |

## 5. Couverture des tests

| Suite | Nombre | Commande |
|---|---|---|
| Contrat AgentBudget (moteur SilverScript) | 25 + mesure du budget de calcul | job `contrats` de la CI |
| Séquestre DeliveryEscrow | 9 + mesure du budget de calcul | job `contrats` de la CI |
| Masse KIP-9, séquestre, outil | 13 | `cd cli && cargo test --release` |
| Fuzzing d'état | 4 (dont test de contrôle du banc) | idem ; campagne longue `FUZZ_CASES=5000` |
| Essais réels sur testnet-10 | 8 essais | `testnet/journal.md` |

Couverture de branches du code de vérification du vendeur (`cargo llvm-cov`) : à produire avant le gel du code.

## 6. Points de veille vérifiés (18 novembre 2026)

Signalements reçus sur l'activité récente de l'écosystème, vérifiés à la source (lecture git des dépôts kaspanet) et par des tests :

- **kaspanet/kips#49** (20 octobre 2026, « KIP-20: specify CovenantIDHash keying and add a test vector ») : existe ; précise que `CovenantIDHash` est BLAKE2b-256 avec la clé `"CovenantID"` et fournit un vecteur de test. **Notre calcul donne exactement le vecteur officiel** (test `identifiant_de_covenant_conforme_au_vecteur_kip20`).
- **kaspanet/rusty-kaspa#1074** : existe, mais c'est la refonte du générateur de transactions du portefeuille (prise en charge des covenants, masse du consensus, masse standard maximale sous Toccata), pas un correctif de sérialisation du budget de calcul. L'issue #1073 n'est pas lisible par git : son contenu n'est pas confirmé. Le risque qu'elle décrirait est de toute façon vérifié ci-dessous et couvert par un garde-fou.

| Point | Vérification | Résultat |
|---|---|---|
| Budget de calcul remis à 0 lors d'une sérialisation JSON | Code de `kaspa-rpc-core` 2.1.0 : `compute_budget` porte `#[serde(default)]` ; test `json_sans_budget_relu_a_zero` | Risque réel pour les SDK passant par JSON. Notre chemin borsh conserve le champ (8 essais acceptés sur testnet). Garde-fou bloquant ajouté (R31) |
| Une seule entrée sur les chemins de dépense sans le propriétaire | Sources des contrats | `pay` (coffre), `claim` et `refund` (séquestre v0.2) imposent `tx.inputs.length == 1` ; `ownerControl` accepte plusieurs entrées pour l'apport de frais (I12) |
| Dérivation de l'identifiant de covenant (KIP-20) | `covenant_id` de rusty-kaspa 2.1.0 contre le vecteur officiel de kips#49 | Identique au vecteur ; deux genèses acceptées par le testnet-10 (lignées `7bbbb1a7…` et `b4f5c34b…`). Test rejoué à chaque envoi par la CI |
| Éviction d'un paiement non confirmé par une transaction du propriétaire | R15 | Le vendeur livre après acceptation et ne garde aucune réservation |
| Sortie de paiement détournée en état ambigu | Fuzzing, triche `BindPayment` | Refusée par le script (R32). Sans liste blanche, payer n'importe quel script standard reste un usage légitime du budget |

Référence : guide officiel Toccata, https://docs.kaspa.org/toccata (tarification des scripts, identifiants de covenant).

## 6 bis. Relecture ligne à ligne d'AgentBudget v0.5 (20 novembre 2026)

| Ligne(s) | Règle | Constat |
|---|---|---|
| 55 | signature de l'agent | requise pour `pay` ; `ownerControl` exige celle du propriétaire (test `mauvaise_cle_refusee_pour_payer`) |
| 57-58 | `0 < amount ≤ maxPerPayment` | borne par achat ; `maxPerPayment ≤ capacity` vérifié hors chaîne (H4) |
| 61-63 | une entrée, deux sorties, aucune donnée | pas de sortie cachée ni d'instruction de bridge (tests `sortie_supplementaire_refusee`, `instructions_de_bridge_refusees`) |
| 66-67 | `lastDaa ≤ nowDaa ≤ verrou` | verrou forcé en score DAA par la garde `OpWithin` du compilateur, jamais lu comme une date (test `verrou_en_date_refuse`) ; non neutralisable par une séquence maximale (une seule entrée, `OpCheckLockTimeVerify`) |
| 71-72 | inscription réelle ≥ `lastDaa` | refuse un coffre non confirmé (−1) ; un `initLastDaa` posé après l'inscription bloque l'agent, jamais le propriétaire |
| 75-85 | recharge ramenée à `[0, refillPeriod]`, plafond `capacity` | arrondis en faveur du propriétaire ; `capacity × refillPeriod` sur 63 bits (H4), sinon le script échoue (`NumberTooBig`) sans danger ; `refillPeriod = 0` : division refusée, l'agent est bloqué, le propriétaire récupère (R33) |
| 87-90 | liste blanche optionnelle | empreinte blake2b du script de sortie complet |
| 91-98 | montant exact, frais ≤ `maxFee`, dépense ≤ disponible | les frais sont décomptés du budget (test `vidage_par_les_frais_refuse`) |
| 101-103 | une seule continuation, même lignée, mêmes règles, état recalculé | l'agent ne peut changer ni le propriétaire, ni les plafonds, ni la liste, ni l'état (tests `agent_ne_peut_pas_changer_les_regles`, `agent_ne_peut_pas_detourner_le_reste`, fuzz : 10 tricheries) |
| 107-109 | `ownerControl` | le propriétaire peut tout, par construction (gel, rapatriement, recharge) |

Constats : aucune faille nouvelle. Une piste (verrou temporel lu comme une date) a été vérifiée
et écartée grâce à la garde du compilateur ; elle reste en non-régression. Limites connues et
documentées : réorganisation du DAG et poussière KIP-9 (`borne-de-perte.md`, section 4).

## 7. Questions ouvertes pour l'auditeur

1. Le calcul `elapsed * capacity / refillPeriod` arrondit à l'inférieur : la perte d'arrondi peut-elle être exploitée en paiements très rapprochés ? (le budget ne peut que perdre, jamais gagner, selon nos tests)
2. Course `claim` / `refund` après le délai (R22) : la parade côté vendeur (réclamer dès la preuve, délai minimal 600 blocs) est-elle suffisante ?
3. `ownerControl` sans restriction : un propriétaire distrait peut détruire sa propre lignée. Faut-il une entrée de recharge contrainte ?
4. Gardes de paramètres dans le contrat (`refillPeriod > 0`, `maxPerPayment <= capacity`) : aujourd'hui assurées hors chaîne par l'outil et par le vendeur, qui recompilent avec `check_params`. Un coffre déployé hors outil avec des paramètres aberrants ne met aucun fonds en danger (R33). Faut-il quand même les inscrire dans le script ? Prévu pour la prochaine version du contrat, regroupé avec les retours d'audit, pour ne pas redéployer deux fois.
5. Liste blanche par empreinte du script de sortie : une même clé peut recevoir sur plusieurs scripts (P2PK Schnorr, P2PK ECDSA, P2SH). La liste blanche autorise exactement les scripts inscrits, ni plus ni moins ; c'est voulu, mais le propriétaire doit inscrire le bon script.
6. Séquestre : l'unicité de `requestHash` et l'honnêteté du vérificateur relèvent de l'application (R-série séquestre) ; le contrat garantit seulement le lien preuve ↔ requête ↔ résultat.

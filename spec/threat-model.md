# Modèle de menace — AgentBudget v0.3 et profil x402 « covenant-budget »

Statut : brouillon, prototype non audité, testnet-10 uniquement. Ce document sert de cahier
des charges aux tests antagonistes et au périmètre de la prime aux bugs (`BUG-BOUNTY.md`).

## 1. Ce qu'on protège

| Bien | Propriétaire | Ce qu'on garantit |
|---|---|---|
| Fonds du coffre | Propriétaire | L'agent ne peut sortir que `capacity` d'un coup, puis au rythme de la recharge ; montant + frais comptés. |
| Contrôle du coffre | Propriétaire | La clé propriétaire peut toujours tout récupérer ou recharger, y compris des fonds envoyés hors lignée. |
| Revenu du vendeur | Vendeur | Le vendeur ne livre qu'après acceptation par le réseau d'un paiement venant d'un coffre authentique et solvable. |

## 2. Acteurs et hypothèses de confiance

| Acteur | Hypothèse |
|---|---|
| Propriétaire | De confiance. Sa clé est hors ligne ou sur son téléphone, jamais sur le serveur ni chez l'agent. |
| Agent IA | **Supposé totalement compromis** (injection de prompt, clé volée). Le coffre doit tenir quoi qu'il fasse. |
| Vendeur | Honnête mais exposé : peut être spammé ; ne doit jamais livrer sans paiement accepté. |
| Mineurs | Majorité honnête (hypothèse de consensus Kaspa). |
| Réseau | 10 blocs/s au moment de l'écriture. Voir R6. |

## 3. Scénario central : l'agent est totalement compromis

L'attaquant détient la clé agent. Ce qu'il peut faire, au maximum :

- dépenser `capacity` immédiatement (montant + frais), puis `capacity` par `refillPeriod` ;
- jamais plus de `maxPerPayment` par paiement ;
- vers n'importe quel destinataire si la liste blanche est désactivée (c'est un choix du propriétaire) ;
- rien de plus : ni plus vite, ni par les frais, ni via un clone, ni en combinant des couloirs.

Parade côté propriétaire : récupérer le coffre (`recuperer`) ; la clé agent volée devient inutile.

## 4. Risques et parades

| # | Risque | Parade | Vérification |
|---|---|---|---|
| R1 | Vider le coffre par les frais (paiements minuscules à frais élevés) | Montant + frais décomptés du budget ; frais ≤ `maxFee` | tests `vidage_par_les_frais_refuse`, `frais_au_dessus_du_plafond_refuses` |
| R2 | Coffre cloné : fonds envoyés à l'adresse du coffre = budget dupliqué | Lignée KIP-20 obligatoire pour `pay` ; continuation liée à la lignée | tests `clone_sans_lignee_refuse`, `continuation_hors_lignee_refusee` |
| R3 | Fonds bloqués par des envois parasites (poussière) à l'adresse | Les envois parasites sont des UTXO séparés : ils ne bloquent pas le coffre ; le propriétaire peut tout balayer | test `proprietaire_recupere_meme_un_clone` |
| R4 | Mentir sur le temps pour recharger plus vite | `nowDaa` borné par le verrou temporel (CLTV) : un instant futur est refusé par le réseau ; un instant passé réduit le budget | test `agent_ne_peut_pas_annoncer_un_instant_futur`, refus observé sur testnet |
| R5 | Accumuler le budget pendant l'inactivité | Recharge plafonnée à `capacity` | test `le_budget_inutilise_ne_s_accumule_pas` |
| R6 | **Changement de cadence du réseau** (10 → 20+ blocs/s) : la recharge, comptée en blocs, s'accélère d'autant en temps réel | Hypothèse opérationnelle documentée : migrer les coffres (recréer avec `refillPeriod` ajusté) lors d'un hard fork de cadence | à surveiller à chaque hard fork |
| R7 | Combiner deux couloirs dans une transaction | Une seule entrée, deux sorties exactement | test `impossible_de_combiner_deux_couloirs` |
| R8 | Dépassement d'entier dans le calcul de recharge | `elapsed` plafonné à `refillPeriod` ; `capacity × refillPeriod < 2^63` et cohérence des paramètres vérifiées à la création (outil) et à la vérification (vendeur) | `check_params` dans `compile_params` ; fuzzing à venir |
| R9 | Vendeur trompé par un faux coffre | Recompilation des paramètres annoncés + présence on-chain + lignée | scénario 3 de la démo testnet |
| R10 | Vendeur livrant avant paiement (0-conf) | Livraison seulement après acceptation de la sortie par le réseau | démo testnet |
| R11 | Rejeu d'une autorisation x402 | Autorisation liée à l'identifiant de transaction (UTXO dépensé une seule fois), à la requête et à une expiration | revue de code |
| R12 | Déni de service sur le vendeur (recompilations en masse) | Cache des scripts recompilés ; vérifications bon marché d'abord | à compléter par une limite de débit |
| R13 | Injection via GitHub Actions | Déclenchement seulement sur la branche principale et par le propriétaire du dépôt ; aucun déclencheur `pull_request(_target)` ; liste blanche des commandes ; `cles` interdite en CI ; scan gitleaks de tout l'historique à chaque envoi | `.github/workflows/testnet.yml`, `secrets.yml` (historique : aucune fuite) |
| R14 | Agent qui paie un service légitime en boucle (injection de prompt) | Le budget borne la perte ; le futur serveur MCP ajoutera un coupe-circuit (débit par domaine, confirmation humaine au-delà d'un seuil) | à concevoir avec `mcp-server/` |
| R16 | Contournement de la liste blanche par un bridge : l'agent paie l'adresse autorisée d'un bridge en y joignant sa propre adresse de destination | Paiements de l'agent sans payload (v0.4) ; ne jamais mettre un bridge en liste blanche ; la perte reste bornée par le budget | test `instructions_de_bridge_refusees` |
| R17 | Composition avec un jeton (futur coffre KSD) : jeton substitué ou coffre bloqué faute de KAS pour les frais | Cahier des charges du modèle KSD : même identifiant de covenant du jeton en entrée et en sortie, budget en unités du jeton, UTXO de KAS séparé pour les frais | à implémenter avec le modèle KSD |
| R18 | Paiements cross-chain via bridge (frais de destination, remboursements bloqués) | Hors périmètre : le produit paie des services sur Kaspa ; le serveur MCP refusera par défaut toute destination de bridge | — |
| R19 | **Masse critique KIP-9** : la continuation du coffre (P2SH + identifiant de covenant) occupe 2 unités de stockage et pèse 4 fois plus qu'une sortie ordinaire ; les petites sorties font dépasser la limite du réseau (500 000 g, mesurée sur testnet-10) | Paiement minimal ≈ 0,02 KAS ; un couloir sous ≈ 0,125 KAS ne peut plus payer (plancher de survie) ; l'outil refuse localement avec un message clair ; le propriétaire récupère un couloir presque vide en ajoutant une entrée à lui (formule assouplie, sortie unique) | refus observé sur testnet-10 (essai 8, 1 000 055 g), tests `masse::*` (calcul exact avec le calculateur du consensus), `proprietaire_peut_ajouter_une_entree_pour_payer_les_frais` |
| R20 | Malléabilité : modifier le script de signature en transit pour changer le TxID | L'identifiant de transaction Kaspa exclut les scripts de signature (v0 et v1) ; la signature SIGHASH_ALL couvre entrées, sorties et payload ; le vendeur suit l'UTXO dépensé (outpoint) | vérifié dans `kaspa-consensus-core` (hashing/tx.rs) |
| R21 | Règles changées par l'agent : continuation vers un coffre au bon état mais avec un plafond ou un propriétaire différent | Le script de continuation doit être exactement celui du coffre (validateOutputState) | test `agent_ne_peut_pas_changer_les_regles` |
| R22 | Séquestre : course entre `claim` et `refund` après le délai | Kaspa ne sait pas exprimer « avant tel instant » : après le délai, les deux restent possibles et la première transaction acceptée gagne. Parade : délai minimal imposé par le vendeur, le vendeur réclame dès la preuve obtenue | à documenter dans la spécification et à démontrer sur testnet |
| R23 | **KForge** : l'agent achète des jetons avec son budget, mais les jetons ou le produit de leur revente arrivent sur une adresse qu'il contrôle hors du coffre (capital accumulé hors contrôle) | Couloir KForge (étape 4) : la sortie qui reçoit les jetons ou le produit doit être l'adresse du propriétaire ou un UTXO sous covenant ; le contrat actuel n'autorise que des paiements en KAS sans payload, donc aucune opération KForge | à concevoir avec le format KForge sur testnet |
| R24 | **Igra** : le payload `0x94` porte un appel EVM encodé en RLP ; ne vérifier que le montant en KAS laisse l'agent appeler un contrat hostile ou transférer ses iKAS à un attaquant. Retrait iKAS → KAS de 48 à 72 h qui gèle le couloir | v0.4 refuse tout payload (R16). Couloir Igra (étape 4) : contrat cible et fonction en liste blanche dans le covenant, délai de retrait intégré au calcul du budget | à concevoir après étude du format Igra |
| R25 | **Kaskad** : un agent compromis ne peut pas voler, mais peut emprunter au maximum sur un actif volatil pour provoquer une liquidation et faire perdre les frais de liquidation au propriétaire | Couloir Kaskad (étape 4) : plafond d'emprunt et ratio prêt/valeur maximal fixés par le propriétaire, remboursement autorisé sans plafond, emprunt plafonné par le budget | à concevoir après KForge et Igra |
| R26 | **Fusion de séquestres** (trouvé le 18 novembre 2026 en revue) : deux séquestres échus, ou deux réclamations dont la preuve est visible dans le mempool, dépensés dans une même transaction vers une sortie qui ne vaut qu'un séquestre ; l'autre part en frais chez le mineur. Aucune signature n'est demandée, donc n'importe quel mineur peut le faire | **Corrigé en v0.2** : `tx.inputs.length == 1` dans `claim` et `refund`. Le coffre l'imposait déjà (`pay`) | `fusion_de_deux_sequestres_refusee` (contrat et outil), fuzzing avec entrée supplémentaire |
| R27 | **Vendeur planté ou surchargé par des requêtes forgées** : identifiant de transaction malformé (`unwrap` sur une entrée du client) ; recompilation et appels au nœud avant les contrôles gratuits | **Corrigé** : conversions sans panique ; ordre des contrôles forme → prix → plafond → signature de l'agent, puis seulement recompilation (en cache) et nœud | revue de `verify_and_settle` |
| R28 | Divergence entre le moteur local et le nœud réel (version de rusty-kaspa, règles du mempool sur les chaînes de transactions non confirmées, cas limites des opcodes récents) | Le fuzzing exécute le moteur de `kaspa-txscript` 2.1.0 ; chaque comportement critique est rejoué sur testnet-10 (8 essais). Chaînes de paiements non confirmés : à tester à l'étape 3 (rafale) | essais testnet, étape 3 |
| R29 | Cache du vendeur désynchronisé (coffre récupéré entre-temps) | Le cache ne garde que la recompilation, qui ne dépend que des paramètres ; la présence de l'UTXO et sa lignée sont relues sur le nœud à chaque requête, et la livraison attend l'acceptation par le réseau | code de `verify_and_settle` |
| R30 | Deux processus de l'agent dépensent le même couloir en même temps : l'un échoue, l'état local peut se désynchroniser | Verrou des couloirs et resynchronisation depuis le nœud dans le serveur MCP (étape 3) ; aujourd'hui, l'outil de démo est mono-processus | étape 3 |
| R31 | Budget de calcul perdu à la sérialisation (champ `compute_budget` relu à 0 dans un JSON qui l'omet, `#[serde(default)]` dans rusty-kaspa 2.1.0) : transaction rejetée | Chemin Rust/borsh qui conserve le champ ; **garde-fou bloquant** `garde_diffusion` sur l'objet RPC envoyé, pour l'outil et le vendeur ; le vendeur exige au moins 11 unités sur l'entrée du coffre | `garde_bloque_un_budget_nul`, `json_sans_budget_relu_a_zero` |
| R32 | Sortie de paiement rattachée à la lignée du coffre (deuxième coffre, état ambigu) | Le script exige que l'entrée du coffre n'autorise qu'une sortie, la n° 1 | fuzzing, triche `BindPayment` |
| R15 | Recharge du propriétaire pendant une dépense de l'agent | Les deux transactions dépensent le même UTXO : une seule est acceptée, l'autre est rejetée sans perte. Le vendeur ne livre qu'après acceptation et ne garde aucune réservation : un paiement évincé se solde par un refus, sans état à nettoyer | à tester sur testnet |

## 5. Hors périmètre (v0.3)

- Sécurité de l'appareil du propriétaire.
- Erreurs du compilateur SilverScript lui-même (pas encore de version auditée).
- Attaque à 51 % du réseau Kaspa.
- Le standard kUSDT (v2).

## 6. Prochains tests antagonistes

- Rafale x402 : 50 achats concurrents sur 5 couloirs (verrouillage local des UTXO côté agent, chaînage 0-conf sur la continuation, cache côté vendeur).
- Réorganisation et éviction du mempool : 3 paiements chaînés en 0-conf dont le 2e est retardé ou rejeté.
- **Fait** : tests à propriétés (proptest), séquences aléatoires et 8 familles de triche contre le vrai moteur de script, 2 000 séquences sans divergence (spec/invariants.md).

- **Fait en partie** : montants nuls, négatifs et au-delà du plafond, frais au-delà du plafond. Reste : paramètres extrêmes du coffre (`refillPeriod` = 1, capacité maximale).
- Paiements concurrents sur un même couloir (R15).
- Coffres dont les paramètres frôlent la limite de dépassement (R8).

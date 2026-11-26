# Red Team interne : le mandataire (clé de l'agent, kit de connexion, secrets, routeur, console)

Séance du 26 novembre 2026 (matin, après le rapport `rapport-2026-11-26.md` sur le contrat).
Banc de test local uniquement : aucun essai sur le testnet, aucune cible tierce.

Objectif hostile : voler la clé de l'agent ou celle du propriétaire, contourner l'installation,
détourner la configuration, récupérer les secrets, faire payer l'agent vers un autre vendeur.
Le contrat `coeur.sil` n'a pas été réattaqué.

Méthode : pour chaque faille, un test écrit d'abord en échec (preuve), puis le correctif, puis le
test au vert. Les attaques qui échouent laissent un test qui fige le comportement.

État des tests : 131 au départ, 146 passés et 1 ignoré (R73) à la fin, 0 échec.

## Résumé

| Constat | Gravité | Ce qui cassait | État | Commit |
|---|---|---|---|---|
| R65 | IMPORTANT | Double authentification contournée : le fichier de clé chiffré sortait avec le mot de passe seul | corrigé | `74222d1` |
| R66 | IMPORTANT | Phrase de récupération devinable mot par mot par la « confirmation de sauvegarde » | corrigé | `74222d1` |
| R67 | IMPORTANT | Essais de code à 6 chiffres illimités (compteur remis à zéro par un mot de passe seul) | corrigé | `74222d1` |
| R68 | IMPORTANT | Paramètres d'URL (clé d'API possible) écrits dans le journal du routeur en cas d'échec | corrigé | `b680a8c` |
| R69 | FAIBLE | L'installation de l'agent écrivait à travers un lien symbolique | corrigé | `6c02845` |
| R70 | FAIBLE | Registre des mandats illisible : la règle « un mandat par machine » sautait en silence | corrigé | `6c02845` |
| R71 | IMPORTANT | Fichier de secrets non signé : fabricable par un tiers, rejouable | corrigé | `1354716` |
| R72 | CRITIQUE (clé de l'agent) | Le lien de session suffisait à sortir la clé privée d'un agent (kit + code) | corrigé | `92c650a` |
| R73 | FAIBLE à IMPORTANT (poste partagé) | Jeton de session visible dans la ligne de commande du navigateur | non corrigé, test ignoré | ce commit |

Aucune faille trouvée dans : la force du code de connexion, le scellement du kit, le stockage chiffré
de la clé du propriétaire, le chiffrement des secrets, l'authentification du routeur, la protection
de la console contre une page web tierce.

## Tableau par attaque

### 1. Kit de connexion (`cli/src/connexion.rs`)

| Idée | Test | Résultat |
|---|---|---|
| Code de connexion plus faible qu'annoncé (biais, alphabet, longueur) | `code_de_connexion_99_bits_sans_biais` | tient : 20 symboles uniformes parmi 31 = 99,08 bits, tirage par rejet sans biais |
| Kit forgé qui impose des paramètres Argon2 faibles ou démesurés | `kit_forge_substitue_ou_affaibli_refuse` | tient : refus avant tout calcul (19 Mio à 1 Gio, 2 à 10 passes, 1 à 8 voies) |
| Substitution de l'en-tête (autre agent, autre clé publique, limite déplacée) | idem | tient : en-tête lié au chiffré, et recontrôlé après ouverture |
| Chiffré d'un autre agent sous le même code | idem | tient |
| Kit dont la clé privée ne correspond pas à la clé publique annoncée | idem | tient |
| Nom non authentifié dans l'en-tête (séquences de terminal) | idem | tient : ce nom n'est jamais utilisé, le nom installé vient du chiffré |
| Messages d'erreur qui citent le code, la clé ou le chiffré | idem | tient |
| Lien symbolique à la place de `agent.key` pour détourner la clé | `installation_cle_privee_jamais_exposee` | tient : création exclusive, la clé ne suit pas le lien |
| Clé privée dans un autre fichier installé, fichiers modifiables par d'autres | idem | tient : clé en 0600, absente des autres fichiers |
| Écrasement d'une installation existante par un autre kit | idem | tient |
| Effacement réel de la copie de la console (lien physique gardé de côté) | idem | tient : contenu réécrit sur place puis supprimé |
| Lien symbolique à la place d'`agent.json`, de l'état ou des secrets | `r69_installation_ne_suit_pas_les_liens_symboliques` | **cassait : R69** |
| Registre des mandats abîmé pour faire sauter « un mandat par machine » | `r70_registre_illisible_refuse_au_lieu_de_tout_permettre` | **cassait : R70** |
| Fichier de secrets fabriqué par un tiers, modifié, pour un autre agent, ancien | `r71_secrets_forges_par_un_tiers_refuses` | **cassait : R71** |
| Traversée de répertoire par un nom venu du kit | lecture du code | tient : aucun chemin n'est construit à partir du kit (noms de fichiers fixes) |
| Rejeu d'un ancien kit, kit d'un autre agent | lecture du code | tient : il faut le code ; qui a kit + code a déjà la clé |

### 2. Clé du propriétaire, secrets, double authentification (`cle.rs`, `secrets.rs`, `double_auth.rs`, `agents.rs`, `console.rs`)

| Idée | Test | Résultat |
|---|---|---|
| Sortir le fichier de clé chiffré avec le mot de passe seul, puis l'ouvrir hors ligne | `r65_fichier_de_cle_chiffre_exige_la_double_authentification` | **cassait : R65** |
| Deviner la phrase mot par mot (positions répétées, essais illimités) | `r66_confirmation_de_sauvegarde_sans_oracle`, `r66_confirmation_de_sauvegarde_legitime` | **cassait : R66** |
| Force brute du code à 6 chiffres sans verrou | `r67_essais_de_code_non_remis_a_zero_par_le_mot_de_passe_seul` | **cassait : R67** |
| Sortir la clé d'un agent avec le seul lien de session | `r72_kit_de_connexion_exige_le_mot_de_passe` | **cassait : R72** |
| Clé d'agent, secret, mot de passe ou code de connexion dans une réponse, le journal ou un fichier de la console | `chaine_complete_sans_fuite_de_cle_ni_de_secret` (console réelle, HTTP) | tient |
| Secret réaffichable (liste, export, autre agent) | idem | tient : écriture seule, un autre agent ne déchiffre pas |
| Fichier de clé falsifié (paramètres faibles, clé publique échangée) | tests existants de `cle.rs` | tient |
| Comparaisons non constantes | lecture du code | tient : jeton et clé d'API comparés en temps constant ; le code à 6 chiffres est borné par le verrou |

### 3. Routeur (`cli/src/routeur.rs`, `cli/src/x402.rs`)

| Idée | Test | Résultat |
|---|---|---|
| Appeler `/v1/fetch`, `/v1/coffre` ou la démo sans la clé (casse, préfixe, autre schéma, clé dans l'URL ou le corps) | `routeur_ferme_sans_la_cle_exacte` | tient |
| Secret dans les journaux du routeur | `r68_parametres_d_url_jamais_dans_le_journal` | **cassait : R68** |
| Faire payer un vendeur non autorisé (URL ambiguë, redirection, adresse interne) | tests existants (`adresses_deguisees_et_urls_ambigues_refusees`, `redirection_jamais_suivie`) relus | tient |
| Lire les secrets d'un autre agent par le routeur | lecture du code | sans objet aujourd'hui : le routeur ne lit pas le coffre de secrets |

### 4. Console (`cli/src/console.rs`, `cli/console/index.html`)

| Idée | Test | Résultat |
|---|---|---|
| Page web tierce : jeton ailleurs que dans l'en-tête, jeton presque juste | `page_malveillante_sans_prise_sur_la_console` | tient |
| Origine étrangère avec le bon jeton (`null`, autre port, https, domaine piégé) | idem | tient |
| DNS rebinding (autre nom d'hôte, sans port, IPv6, 0.0.0.0) | idem | tient |
| Ouverture entre origines (CORS, pré-vérification, cadre) | idem | tient : aucun en-tête CORS, cadre interdit, politique de contenu stricte |
| Injection dans la page (nom d'agent, cours, événements) | lecture de la page | tient : aucun `innerHTML`, tout passe par `textContent` |
| Jeton de session volé hors du navigateur | `r73_lien_remis_au_navigateur_sans_jeton_de_session` (ignoré) | **casse : R73, non corrigé** |

## Constats

### R65 : la double authentification se contournait par la sauvegarde du fichier chiffré (IMPORTANT, corrigé)

`POST /api/cle-chiffree` rendait le fichier de clé avec le mot de passe seul. Or ce fichier et le mot
de passe suffisent, hors ligne, à retrouver la phrase de 24 mots et le secret de double
authentification. Quelqu'un qui tenait le mot de passe et la session n'avait donc jamais besoin du
code à 6 chiffres.

Correctif : le code est exigé pour cette action quand la double authentification est active.
**Changement visible** : « Sauvegarder le fichier chiffré » demande le code à 6 chiffres (seulement
si la double authentification est active).

### R66 : la confirmation de sauvegarde servait d'oracle sur la phrase (IMPORTANT, corrigé)

`POST /api/recuperation/confirmer` (mot de passe seul, par choix) acceptait trois fois la même
position et ne comptait pas les échecs. Un mot se devinait seul en 2 048 essais au plus, la phrase
entière en moins de 50 000 requêtes, sans le code à 6 chiffres.

Correctif : trois positions distinctes exigées, chaque essai manqué compte pour le verrouillage.
**Changement visible** : cinq erreurs de saisie des mots verrouillent une minute.

### R67 : essais de code à 6 chiffres illimités (IMPORTANT, corrigé)

Le compteur d'échecs était commun au mot de passe et au code, et un mot de passe juste le remettait
à zéro. En intercalant une action au mot de passe seul tous les quatre essais, on n'était jamais
verrouillé.

Correctif : les échecs de code sont comptés à part, seul un code juste les efface, et les verrous
consécutifs s'allongent (1 min, 2 min, 4 min… 1 h au plus). **Changement visible** : après plusieurs
séries de cinq codes faux, l'attente dépasse une minute.

### R68 : paramètres d'URL dans le journal du routeur (IMPORTANT, corrigé)

Le journal retire volontairement les paramètres d'URL (ils peuvent porter une clé d'API). Mais quand
la requête échouait, le message d'erreur du client HTTP citait l'URL complète : il partait dans
`routeur-journal.jsonl`, dans la réponse, et l'URL complète s'affichait sur la sortie du routeur.

Correctif : on ne garde que la nature de l'échec ; la sortie n'affiche que l'URL sans paramètres.
**Changement visible** : le message d'erreur d'un achat qui échoue avant paiement ne cite plus l'URL.

### R69 : écriture à travers un lien symbolique à l'installation (FAIBLE, corrigé)

Si le dossier d'installation était préparé par quelqu'un d'autre, un lien symbolique à la place
d'`agent.json`, de l'état ou des secrets faisait écrire l'installation dans un autre fichier de
l'utilisateur. La clé privée, elle, n'a jamais suivi un lien.

Correctif : ces fichiers sont créés neufs, le lien est retiré. Rien de visible.

### R70 : registre des mandats illisible (FAIBLE, corrigé)

Un registre tronqué ou abîmé était lu comme « aucun mandat » : la règle « un mandat par machine »
(R52) ne s'appliquait plus, puis le registre était réécrit sans les anciens mandats.

Correctif : registre illisible = installation refusée avec un message qui dit quoi faire ; écriture
atomique. **Changement visible** : ce message, dans ce seul cas. Cette règle reste un garde-fou
contre l'erreur de configuration, pas une barrière (un autre compte de l'ordinateur ou la variable
`PLAFOND_REGISTRE_AGENTS` la contournent).

### R71 : fichier de secrets non signé (IMPORTANT, corrigé)

Le fichier exporté pour un agent déjà connecté était chiffré pour l'agent, mais pas signé. La clé
publique de l'agent étant publique, n'importe qui pouvait fabriquer un fichier que l'agent
installait : sa propre clé d'API à la place de la bonne (il voit alors passer le trafic de l'agent),
ou un ancien fichier (clé révoquée).

Correctif : la console signe l'export avec la clé du propriétaire ; l'agent vérifie la signature, le
destinataire et la date (jamais plus ancien que les secrets déjà installés).
**Changement visible** : un fichier de secrets exporté avant ce changement est refusé, il faut
l'exporter de nouveau. Un agent installé avant ce changement accepte tout export signé de son
propriétaire (pas de date de référence).

### R72 : le lien de session suffisait à sortir la clé d'un agent (CRITIQUE, corrigé)

`POST /api/connecter/preparer` rendait le kit scellé et son code dans la même réponse, sans mot de
passe. Qui tenait le jeton de session pouvait créer un mandat, l'alimenter, en sortir la clé et
dépenser : l'export de la clé du propriétaire était gardé par le mot de passe, pas celui des agents.

Correctif : mot de passe exigé, et code à 6 chiffres si la double authentification est active.
**Changement visible** : « Connecter l'agent » demande le mot de passe avant d'afficher le code de
connexion (rien n'est demandé avec les clés de test). Les deux parcours ont été joués dans un
navigateur (API simulée).

Limite de la preuve : le test en échec montrait l'absence de garde sur l'agent de test (réponse 409
au lieu de 403) ; la remise réelle du kit est couverte, après correctif, par
`chaine_complete_sans_fuite_de_cle_ni_de_secret`.

### R73 : jeton de session dans la ligne de commande du navigateur (non corrigé)

À l'ouverture automatique, le lien complet (jeton compris) est passé au navigateur en argument de
commande. Sur Linux et macOS, les arguments d'une commande sont lisibles par les autres utilisateurs
de l'ordinateur. Sur un poste partagé, un autre utilisateur peut donc piloter la console : geler,
alimenter, créer un mandat, remplacer un secret, ou, avant l'ouverture du compte, restaurer un autre
compte à la place. Depuis R65 et R72, il ne peut plus sortir de clé.

Gravité : FAIBLE sur un poste personnel, IMPORTANT sur un poste partagé.

Non corrigé parce que le correctif change l'usage : remettre au navigateur un ticket à usage unique,
échangé par la page contre le jeton, ferait que le lien affiché dans le terminal ne s'ouvre plus
qu'une fois. Décision du propriétaire. Test : `r73_lien_remis_au_navigateur_sans_jeton_de_session`,
marqué `#[ignore]`.

## Ce qui reste

- **R73** : décision à prendre (ticket à usage unique, ou accepter la limite et la documenter).
- **Clés d'agent en clair sur le disque de la console** (`agents/<id>.key` jusqu'à la connexion,
  `agent-principal.key` en permanence), protégées par les seuls droits du fichier (0600). Par
  conception ; à chiffrer sous le mot de passe du propriétaire si on veut fermer ce point.
- **Kit laissé sur le disque** après installation : le message dit qu'on peut le supprimer.
  `agent-installer` pourrait l'effacer lui-même.
- **Mémoire** : le corps JSON des requêtes de la console (mot de passe, valeur d'un secret) est
  libéré sans être effacé ; seule la chaîne brute l'est. Le code de connexion passe aussi en clair
  dans la réponse.
- **Rejeu d'un code à 6 chiffres après redémarrage de la console** : le dernier pas accepté n'est
  gardé qu'en mémoire (fenêtre de 90 s, il faut aussi le mot de passe).
- **Jeton de session = pouvoir d'agir** : geler, alimenter, créer un mandat, remplacer un secret
  restent sans mot de passe, par choix (le gel ne doit jamais être freiné).
- **Secrets non utilisés par le routeur** : le jour où il les lira, lier chaque secret à son
  fournisseur et à ses hôtes autorisés (le champ `fournisseur` n'est pas authentifié aujourd'hui).

## Limites de cette séance

- **Windows non testé.** Hors Unix, clés et secrets sont écrits avec les droits hérités du dossier
  (pas de 0600). Dans le dossier de l'utilisateur c'est en général suffisant, ailleurs non.
- Aucun essai sur le testnet : les parcours qui parlent au nœud (tableau, alimenter, geler) n'ont pas
  été rejoués.
- Effacement de fichier : réécriture sur place puis suppression. Sur SSD ou système de fichiers à
  copie sur écriture, l'ancien contenu peut subsister physiquement.
- La page de la console a été relue et deux parcours modifiés joués dans un navigateur ; pas d'audit
  complet du JavaScript.
- Contrat, moteur de risque et vendeur x402 hors périmètre (voir `rapport-2026-11-26.md`).

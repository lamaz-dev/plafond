# Un coffre dont le budget dort en jeton (KCC-20) : étude de faisabilité

28 novembre 2026. **Étude seulement : aucun contrat n'a été écrit ni compilé pour cette étude.**
Demande du propriétaire du projet : que Kaspa ne serve que de garde-fou mathématique, que le budget
dorme en stablecoin, que le KAS ne serve qu'aux frais, et que le client pense en requêtes.

## Verdict

**Faisable, avec des réserves sérieuses.** La même borne `k × (C + C·D/R)` peut être tenue sur des
montants de jetons, avec les briques qui existent déjà dans le compilateur figé du dépôt. Mais :

- le code qui touche à l'argent serait environ **trois fois plus gros** (ordre de 1 500 à 1 900
  octets, contre 550), et chaque paiement environ **trois fois plus lourd** ;
- **toutes** les entrées du cœur devraient connaître le jeton, pas seulement le paiement (voir §2,
  « le piège ») : c'est une surface d'attaque nouvelle ;
- la sécurité du budget dépendrait en plus du contrat du jeton et, pour kUSDT, d'un pont à 3
  signataires sur 5, non audité ;
- le texte final de la norme KCC-20 n'a pas pu être lu pour cette étude (voir §7).

Recommandation : ne pas toucher au cœur v0.9.2. Si la piste est retenue, faire un **prototype
séparé** sur le banc local (§6), et ne décider qu'après mesure.

## 1. Ce qui a été vérifié, et où

| Point | Source | Vérifié |
|---|---|---|
| Un jeton KCC-20 est une lignée de pièces (identifiant de covenant) ; chaque pièce porte un état : propriétaire (32 octets), type de propriétaire, montant, drapeau « émetteur » | exemple `fungible-token.sil` du compilateur figé (`7eb04634`, renommé `kcc20.sil` dans le livre en ligne) ; livre KCC-20 de SilverScript | lu dans le source |
| Trois types de propriétaire : clé publique (signature), **empreinte de script** (une entrée de la transaction doit être à ce script P2SH), **identifiant de covenant** (une entrée doit porter cet identifiant) | idem ; livre, chapitre « The KCC20 Contract » | lu |
| Le jeton vérifie seulement : le droit de dépenser, la **conservation** (somme des montants entrants = somme des sortants), et qu'une branche ordinaire ne crée pas d'émetteur. Il **ne regarde pas où vont les jetons** : c'est au script propriétaire de le faire | idem | lu |
| Un autre contrat peut lire le montant d'une pièce de jeton en entrée et imposer l'état d'une pièce de jeton en sortie (`readInputStateWithTemplate`, `validateOutputStateWithInputTemplate`, `OpCovInputIdx`, `OpCovOutputIdx`, `OpCovInputCount`, `OpCovOutputCount`) | exemple `fungible-token-minter.sil` du compilateur figé ; livre, chapitre « The KCC20Minter Contract » | lu ; l'exemple passe ses tests ici |
| Tailles : jeton (2 entrées, 2 sorties au plus) **1 507 octets** ; contrôleur d'émission de l'exemple **1 374 octets** | mesuré ici, compilateur figé | mesuré |
| kUSDT : jeton KCC-20 sur Kaspa, adossé 1 pour 1 à de l'USDT bloqué sur Ethereum ou BNB Chain ; dit utiliser « le code KCC-20 standard, inchangé » ; en ligne sur le réseau principal depuis le 15 nov. 2026 ; 6 décimales ; 5 signataires, 3 suffisent pour émettre ou payer ; **non audité** ; frais de sortie minimaux 5 USDT (Ethereum) ou 0,50 USDT (BNB Chain) ; dépôts de 10 à 8 000 USDT | documentation kUSDT (page d'accueil et « Trust model »), lue le 28 nov. 2026 | lu, non recoupé |
| Ces exemples « ne sont pas la norme » : ils renvoient à `kaspanet/kccs`, `kcc-0020.md` | en-tête des exemples | lu |

**Non vérifié** : le texte de KCC-20, KCC-1 et KCC-2 (l'accès à la page de la norme a été refusé
pendant cette étude) ; que le bytecode de kUSDT est bien celui de l'exemple ; les identifiants de
covenant de kUSDT ; le sens exact de « borrowed receive » (le terme n'apparaît ni dans les exemples
ni dans les pages lues) ; le comportement des portefeuilles.

## 2. Un « cœur en jeton »

### Le principe

Le coffre garde sa forme : une **lignée `X`** de `k` pièces au script du cœur, qui ne portent plus
qu'un peu de KAS (pour les frais). Les jetons sont dans des pièces du jeton dont l'état dit
« propriétaire : le covenant `X` ». Pour dépenser ces jetons, une transaction doit contenir une
pièce de la lignée `X` en entrée : c'est donc le script du cœur qui décide.

Un paiement de l'agent consommerait une pièce du cœur et une pièce de jetons, et produirait : le
reste du cœur (héritière), les jetons du vendeur, le reste des jetons (propriétaire `X`). Le script
du cœur lirait le montant de jetons entrant, imposerait les deux états sortants, calculerait
`dépensé = entrant − reste` et exigerait, comme aujourd'hui, `dépensé ≤ C` et un âge de la pièce du
cœur `≥ ⌈dépensé·R/C⌉`.

### La borne tient-elle ? Oui, pour la même raison

- **L'âge et le verrou relatif fonctionnent pareil** : ils portent sur la pièce du cœur, qui est
  une pièce Kaspa ordinaire. L'âge des pièces de jetons ne joue aucun rôle.
- **Le nombre de rythmes reste `k`** : chaque paiement consomme une pièce de la lignée `X`, et
  l'invariant de lignée (preuve §4) ne change pas. Le nombre de pièces de jetons n'entre pas dans
  la borne : dix pièces de jetons au nom de `X` ne donnent pas un rythme de plus.
- Conséquence agréable : **recharger devient un simple envoi de jetons** « au propriétaire `X` ».
  N'importe qui peut le faire, sans clé ; ce n'est pas un rythme de plus. Le sas ne serait plus
  nécessaire pour le rechargement.
- La conservation des montants est garantie par le contrat du jeton ; le cœur n'a à vérifier que
  ce qui revient au coffre.

### Le piège, à ne pas manquer

Le jeton accepte de bouger dès qu'**une entrée porte l'identifiant `X`**, quelle que soit l'entrée
du cœur utilisée. Or `absorb` se déclenche sans clé et ne regarde pas les autres entrées ni les
autres sorties. Sans précaution, n'importe qui joindrait une pièce de jetons du coffre à un
regonflement et enverrait les jetons où il veut. Donc :

- **chaque entrée du cœur** (paiement, rechargement, retrait, gel, regonflement sans clé) devrait
  compter les pièces du jeton présentes dans la transaction et, hors paiement et retrait, exiger
  qu'il n'y en ait aucune, ou qu'elles reviennent intactes au coffre ;
- l'identifiant du jeton deviendrait un paramètre du cœur. Un autre jeton envoyé au nom de `X`
  resterait volable par ce chemin : ce serait un don perdu, pas l'argent du client, mais il
  faudrait le dire.

C'est le point qui demande le plus de soin : une règle oubliée dans une seule entrée ouvre tout.

### Jeton générique ou kUSDT seulement ?

Le cœur porterait trois paramètres de plus : identifiant de covenant du jeton, empreinte du gabarit
de son script, longueurs du gabarit. Tout jeton qui utilise le même code que l'exemple conviendrait.
Un jeton au code différent (autre disposition de l'état) demanderait un autre cœur.

## 3. Un « réservoir » en jeton

Demande : un seul dépôt du client ; il ne peut que remplir le coffre de l'agent, au plus `X` par
période, sans clé, ou revenir à l'adresse de retour.

C'est le cœur lui-même, avec un bénéficiaire imposé : une seconde lignée, dont le « paiement » ne
peut créer que des jetons au nom du coffre de l'agent, au même rythme `⌈montant·R'/C'⌉`, et dont
l'entrée n'a pas besoin de signature puisque la destination est fixe. La règle du rythme, la règle
d'héritière et le retour à l'adresse de retour se réutilisent tels quels ; l'entrée `absorb` et le
sas ne servent plus. La borne du client devient : ce que l'agent peut perdre est limité par son
coffre, et ce que le coffre peut recevoir est limité par le réservoir.

Réserve : deux contrats qui lisent le jeton au lieu d'un, donc deux fois le risque du §2.

## 4. Taille et masse (estimations, sauf mention « mesuré »)

| | Cœur v0.9.2 (KAS) | Cœur en jeton |
|---|---|---|
| Script du cœur | 550 octets (mesuré) | 1 500 à 1 900 octets : le contrôleur de l'exemple, qui lit une pièce de jetons et en impose deux, fait déjà 1 374 octets (mesuré) sans règle de rythme ni adresse de retour |
| Script révélé à chaque paiement | 550 octets | celui du cœur **plus** celui du jeton, 1 507 octets (mesuré) |
| Taille d'un paiement | environ 900 octets (masse transitoire 3 620 g, mesurée sur testnet) | 3 500 à 4 500 octets |
| Frais minimaux d'un paiement, à 100 sompi par gramme | environ 0,003 KAS | 0,007 à 0,010 KAS |
| KAS immobilisé par paiement | aucun | chaque pièce de jetons créée (celle du vendeur, le reste) doit porter un peu de KAS pour respecter la masse de stockage ; ordre de 0,02 à 0,1 KAS par pièce, à mesurer |
| Réservoir | sans objet | même ordre que le cœur en jeton |

Le souhait « le code qui touche à l'argent reste minuscule » n'est **pas** tenu : on passe de 550
octets relus ligne à ligne à environ 3 000 octets exécutés par paiement, dont la moitié écrite par
d'autres.

## 5. Risques

1. **Pont kUSDT.** Trois signataires sur cinq peuvent émettre ou payer dans les limites
   quotidiennes (100 000 kUSDT par jour côté Kaspa) ; du kUSDT forgé « a l'air vrai ». Non audité ;
   la documentation dit de n'y mettre que ce qu'on peut perdre. Le garde-fou mathématique de
   Plafond borne ce que l'agent dépense, pas la valeur du jeton.
2. **Sortie.** Frais minimaux de 5 USDT (Ethereum) ou 0,50 USDT (BNB Chain) par remboursement, une
   dizaine de minutes d'attente, pause possible par un gardien. Un petit budget de requêtes peut
   coûter plus cher à récupérer qu'il ne vaut.
3. **Liquidité.** Le vendeur doit accepter du kUSDT. Aucun vendeur x402 connu ici ne le fait ; à
   vérifier avant tout.
4. **Portefeuilles.** Une pièce de jetons détenue par un script n'apparaît dans aucun portefeuille
   comme un solde du client : seul l'outil Plafond saurait l'afficher. Portefeuilles annoncés pour
   kUSDT : kUSDT Wallet, KasWare, Kastle, Kasanova, Kaspire. Kaspium et Ledger ne sont pas cités.
5. **Limite W10.** Elle se retourne : le cœur v0.9.2 garantit que ce qui revient à l'adresse de
   retour est une pièce ordinaire, sans lignée. Des jetons rendus au propriétaire sont par nature
   des pièces à lignée (celle du jeton). L'adresse de retour devrait donc être un portefeuille qui
   gère KCC-20 ; le profil « compte sur une plateforme » ne conviendrait que si la plateforme
   crédite le kUSDT natif, ce qui n'est pas vérifié.
6. **Deux unités.** Les frais et le KAS porté par les pièces de jetons restent en KAS : il faut
   toujours un petit budget KAS, lui aussi à borner.
7. **Dépendance au contrat du jeton.** Une faille du contrat KCC-20, ou un jeton qui n'utiliserait
   pas exactement ce code, casserait la borne sans que le cœur y puisse rien.
8. **Norme non lue.** Les exemples lus disent eux-mêmes ne pas être la norme.

## 6. Plan, si la piste est retenue

1. Lire `kcc-0020.md`, KCC-1 et KCC-2 ; comparer le bytecode publié de kUSDT à l'exemple ; relever
   ses identifiants. Demander à un relecteur proche des développeurs ce que « borrowed receive »
   désigne.
2. Prototype **hors du cœur** (`contracts/recherche/`), sur le banc local, avec le jeton d'exemple
   du compilateur figé : paiement, retour, et la liste d'attaques « une entrée du cœur sert de
   passe-droit au jeton » pour chaque entrée. Mesurer la taille et la masse réelles.
3. Si la taille reste acceptable : preuve écrite (la borne par emplacement, en unités de jeton),
   sabotages, fuzzing, comme pour la v0.9.
4. Essai sur le réseau de test public de kUSDT.
5. Audit humain. Pas de réseau principal avant.

Alternative plus légère à étudier en parallèle : garder le cœur en KAS tel quel et traiter la
volatilité **hors du contrat** (réservoir en stablecoin chez le client, conversion en KAS au fil de
l'eau par petites recharges du sas). Le code qui touche à l'argent resterait à 550 octets ; le
risque de cours ne porterait que sur quelques jours de budget.

## 7. Limites de cette étude

- Aucune ligne de contrat n'a été écrite : les tailles du cœur en jeton sont des ordres de
  grandeur tirés de l'exemple de contrôleur, pas des mesures.
- La norme elle-même n'a pas été lue (accès refusé pendant l'étude) ; tout repose sur les exemples
  du compilateur figé, sur le livre KCC-20 de SilverScript et sur la documentation de kUSDT.
- Rien n'a été essayé sur un réseau.

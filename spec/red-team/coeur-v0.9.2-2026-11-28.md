# Cœur v0.9.2 et sas v0.2.1 : note Red Team du 28 novembre 2026

Objet : `contracts/coeur.sil` (cœur v0.9.2, 550 octets) et `contracts/sas.sil` (sas v0.2.1, 264
octets). Suite de `spec/red-team/retrait-2026-11-27.md`, dont trois points ont été arbitrés par le
propriétaire du projet le 28 novembre :

1. **W10 : parade appliquée partout.** Toute sortie vers l'adresse de retour (gel, retrait partiel,
   retour d'un dépôt du sas) doit être une pièce ordinaire, sans aucune lignée, genèse comprise.
2. **Le retrait partiel est fondu dans `ownerControl`**, puisque cette entrée est modifiée de toute
   façon, à condition de ne rien affaiblir.
3. **L'attente avant un retrait partiel est acceptée** (frais au rythme du contrat, W4) ; la
   fermeture reste immédiate.

Banc local, vrai moteur de script (`kaspa-txscript` 2.2.0 figé par `Cargo.lock`) avec le contexte de
lignées construit par la fonction du nœud, compilateur SilverScript figé (`7eb04634`). Preuve :
`spec/borne-de-perte-v0.9.md`, §9 et §10. Versions archivées à l'identique : `coeur-v0.9.sil`,
`coeur-v0.9.1.sil`, `sas-v0.2.sil` (aucune n'a été déployée).

## Résumé

| Réf. | Sujet | État en v0.9.2 / v0.2.1 |
|---|---|---|
| W10 | Pièce de retour marquée d'une lignée neuve | **fermé par le contrat** dans le cœur et le sas ; demeure sur les coffres v0.7 déployés |
| W6 | Taille | 550 octets (v0.9.1 : 577), règle W10 comprise |
| W1, W2, W3 | Frais brûlés, sortie comptée deux fois, lignée | fermés, comme en v0.9.1 (mêmes règles, rejouées) |
| W4 | Attente avant un retrait partiel | acceptée par le propriétaire du projet |
| F1 | Aiguillage rechargement / retrait dans `ownerControl` | nouveau point d'attention, couvert par une attaque et un sabotage |
| F2 | Bénéficiaire d'un `pay` marqué d'une lignée neuve | hors périmètre, justifié ; à vérifier côté vendeur |
| F3 | Le sas grossit de 37 octets | assumé |

103 attaques nommées refusées (61 de la v0.9, 34 sur le retrait, 8 sur les pièces marquées), 41
sabotages détectés, fuzzing du coffre entier avec tentatives de pièces marquées à chaque gel et à
chaque retrait d'une clé volée.

## W10 : ce qui a été fait

Règle ajoutée à trois endroits : `OpOutputCovenantId(sortie) == 0…0` (l'identifiant que le moteur
rend pour une sortie sans lignée). `OpOutputAuthorizingInput`, plus court, n'est pas exposé par le
compilateur figé.

- `ownerControl`, gel : sortie `i`. La règle « aucune héritière » est gardée : elle seule empêche
  une héritière de la lignée du coffre de partir sur une autre sortie (sabotage rejoué).
- `ownerControl`, retrait partiel : sortie 1.
- sas, `retour` : sortie `i`.

Huit attaques : gel marqué ; gel par lot dont une pièce marquée ; genèse « autorisée » par l'entrée
d'un tiers ; rapatriement d'une poussière marqué ; retrait partiel marqué ; retour d'un dépôt
marqué ; gel et retour ensemble, dépôt marqué ; gel et retour ensemble, lignée du coffre déplacée
sur le dépôt renvoyé. Témoins : les mêmes transactions passent sur les cœurs v0.9 et v0.9.1 et sur
le sas v0.2 archivés (`w10_piece_de_retour_ordinaire`).

**Ce qui n'est toujours pas vérifié** : la façon dont Kaspium, un Ledger ou une plateforme traitent
une pièce marquée. La parade rend la question sans objet pour les nouveaux coffres ; elle reste
posée pour les coffres v0.7 existants (à fermer et recréer quand l'outil déploiera la v0.9.2).

## F2 : le bénéficiaire d'un paiement n'est pas durci

Examiné, non modifié. Raisons :

- ce n'est pas l'adresse de retour : c'est un vendeur que l'agent choisit. Un agent compromis peut
  déjà envoyer sa dépense à n'importe quelle adresse, dans la borne ; marquer la pièce ne lui donne
  rien de plus et ne coûte rien de plus au propriétaire ;
- la pièce marquée reste dépensable par son destinataire ;
- durcir aurait modifié `pay`, l'entrée la plus relue, inchangée depuis la v0.7, pour 36 octets.

Conséquence, **pour l'outil** : un vendeur ou un relais qui vérifie un paiement doit contrôler que
la sortie payée ne porte aucune lignée (sinon il pourrait livrer contre une pièce que son
portefeuille n'affiche pas). Le relais x402 de Plafond reçoit le paiement dans le porte-monnaie de
l'agent, puis paie le vendeur par une transaction ordinaire : le vendeur n'est pas exposé par ce
chemin. Figé par un test pour que cela ne change pas sans être vu.

## F1 : l'aiguillage dans `ownerControl`

En fondant le retrait dans `ownerControl`, la règle « rechargement : la pièce revient au moins
entière » devient une condition : si la sortie `i` est au coffre et plus petite que l'entrée, c'est
un retrait partiel, soumis à ses règles ; sinon c'est un rechargement, libre comme avant (autres
entrées et sorties permises). Le risque à écarter : une transaction à plusieurs entrées où la pièce
revient plus petite « comme un rechargement », la différence partant chez un tiers. Elle tombe dans
la branche du retrait, qui exige une seule entrée et deux sorties : refusée (attaque « pièce du
coffre rognée sous couvert de rechargement »). Sabotage : en déplaçant le seuil de l'aiguillage de
`C`, l'attaque passe.

Le rechargement lui-même n'est pas affaibli : mêmes conditions qu'en v0.9 (sortie `i` au script du
coffre, valeur au moins égale, une seule héritière).

## Ce que la fusion change, honnêtement

- `ownerControl` n'est plus identique à la v0.9 : c'est la seule entrée à relire, en entier. `pay`
  et `absorb` sont inchangés au caractère près (test).
- L'ordre des sorties du retrait change par rapport à la v0.9.1 : sortie 0 = le reste (convention
  « entrée i, sortie i »), sortie 1 = l'adresse de retour.
- Aucune garantie n'est affaiblie : les 34 attaques du retrait (les 32 de la v0.9.1 moins une sans
  objet, « l'agent utilise l'entrée du retrait », plus trois nouvelles sur l'aiguillage) sont
  refusées, et chaque règle a son sabotage.

## Essai sur testnet-10 et `maxFrais` (ajout du 28 nov., après l'essai)

Essai fait le jour même : `spec/essai-testnet-2026-11-28-v0.9.2.md`. Tout a eu le résultat attendu ;
S8 et W8 sont levés. Le versement sans signature est relayé comme une transaction ordinaire.

**S2, `maxFrais` fixé à 0,01 KAS (1 000 000 sompi)** par défaut, au lieu de 0,06. Mesure : le nœud
exige 100 sompi par gramme de la plus grande des masses « calcul » et « transitoire normalisée » ;
pour un versement, 222 600 sompi (0,0022 KAS). Le plafond vaut environ 4,5 fois ce minimum :
- au pire, un tiers fait brûler 0,01 KAS par dépôt (six fois moins qu'avant) ;
- il reste de la marge si les frais du réseau montent ou si le script est un peu plus long ;
- si les frais dépassaient un jour le plafond, les versements sans clé attendraient ; le
  propriétaire pourrait toujours renvoyer les dépôts en ajoutant une pièce à lui pour les frais
  (`retour` ne plafonne que ce qui est pris sur le dépôt).
Les frais ordinaires d'un versement passent à 350 000 sompi (une fois et demie le minimum).
Non vérifié : le prix au gramme sur le réseau principal (la mesure est celle du testnet-10).

## Avant de déployer

1. ~~Essai sur testnet-10~~ : fait.
2. ~~Fixer `maxFrais`~~ : fait (ci-dessus).
3. Brancher l'outil ; côté vendeur, vérifier l'absence de lignée sur la sortie payée (F2).
4. Faire relire `ownerControl` et `retour`.

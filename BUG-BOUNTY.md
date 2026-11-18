# Prime aux bugs — AgentBudget v0.4 sur le testnet-10

> **Statut : revue publique ouverte, prime en attente de financement.** Aucun montant n'est promis
> tant que le financement n'est pas acquis. Les signalements reçus dès maintenant sont crédités
> au tableau d'honneur et deviennent éligibles à la prime, à date de signalement, dès son ouverture.

## Périmètre

- Le contrat `contracts/agent_budget.sil` v0.4, déployé à l'adresse publiée ci-dessous sur le
  testnet-10 de Kaspa. Adresse et identifiant de lignée : *à publier lors de l'annonce*.
- Le vendeur de démo x402 « covenant-budget » (`cli/src/x402.rs`), dans la mesure où une
  attaque peut être reproduite contre lui.

- Le séquestre `contracts/delivery_escrow.sil` (paiement à la livraison), une fois déployé.

Hors périmètre :
- le mainnet, les attaques contre GitHub ou l'infrastructure, les attaques à 51 %, l'ingénierie
  sociale, le déni de service par simple volume réseau ;
- **dépenser dans le budget légitime** : avec la clé de l'agent (publiée pour l'épreuve), payer
  n'importe qui jusqu'au plafond est le comportement prévu, pas une faille ;
- les limites de masse KIP-9 documentées (paiement minimal ≈ 0,02 KAS, couloir bloqué sous
  ≈ 0,125 KAS tant que le propriétaire ne le recharge pas) ;
- la course `claim`/`refund` du séquestre après le délai (risque R22, documenté) ;
- les bugs du compilateur SilverScript lui-même, à signaler à ses auteurs (une mention reste
  appréciée).

## Conditions de victoire

1. **Dépasser le budget** : faire sortir du coffre plus que ce que les règles autorisent sur une
   période (montant + frais), sans la clé du propriétaire.
2. **Bloquer le propriétaire** : empêcher durablement la clé propriétaire de récupérer les fonds.
3. **Tromper le vendeur** : obtenir le contenu de démo avec un faux coffre, un coffre insolvable
   ou sans paiement accepté par le réseau.

La clé de l'agent pourra être publiée pour l'épreuve, afin de simuler un agent totalement compromis. Le coffre de l'épreuve utilisera des clés neuves, dédiées, distinctes de celles des essais de développement.

## Preuve demandée

- L'identifiant de la transaction (TxID) sur le testnet-10 ;
- la méthode de reproduction, pas à pas ;
- un signalement privé via l'onglet **Security** du dépôt → **Report a vulnerability** (voir `SECURITY.md`), avant toute divulgation publique.

## Récompense

La prime sera financée par la demande de subvention déposée auprès de la communauté Kaspa, en
même temps que l'audit externe. Elle ne sera annoncée qu'une fois les fonds disponibles. Grille
prévue, payée en KAS sur le mainnet (les TKAS du coffre de test n'ont aucune valeur) :

| Gravité | Exemple | Prime prévue |
|---|---|---|
| Critique | condition 1 : dépasser le budget, voler le capital du propriétaire | ≈ 300 $ en KAS |
| Élevée | condition 2 : bloquer définitivement les fonds | ≈ 150 $ en KAS |
| Moyenne | condition 3 : tromper la vérification du vendeur | ≈ 50 $ en KAS |

Plafond total prévu : 500 $ sur 4 semaines après l'ouverture de la prime.

En attendant : **tableau d'honneur** dans ce dépôt et sur Kaspa France pour tout signalement
valide. Une **réserve de divulgation** est prévue : une faille sérieuse signalée en privé, hors
des conditions ci-dessus, peut aussi être récompensée.

Premier arrivé, premier servi : une même faille n'est récompensée qu'une fois. Délai de
divulgation publique : 30 jours après le signalement, ou dès la correction publiée.

## Tableau d'honneur

*(aucun signalement pour l'instant)*

## Référence

Le modèle de menace (`spec/threat-model.md`) décrit les protections prévues et leurs tests.

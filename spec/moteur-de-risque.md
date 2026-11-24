# Moteur de risque : mesurer la perte maximale garantie

> **Statut (24 nov. 2026, soir) : implémenté dans la console pour le cœur v0.6**
> (`cli/src/risque.rs`, garanti par les fuzzings de `cli/src/coeur.rs` contre le vrai moteur de
> script et les règles du réseau). Un couloir est désormais **une pièce** du coffre. Les séquestres
> ouverts en ligne de commande ne sont pas encore suivis par la console.
> Elle s'appuie sur la borne démontrée et testée de `spec/borne-de-perte-v0.6.md` (courbe promise
> comprise) et sur le séquestre DeliveryEscrow v0.3. Ni la borne ni ce document n'ont encore été audités.
> Rédigée comme un standard ouvert : n'importe quel outil peut calculer ces quatre mesures et
> doit obtenir les mêmes chiffres.

## 1. La question

Les outils de dépense pour agents montrent en général **ce qui a été dépensé**. Le moteur de risque
répond à une autre question :

> **Si tous mes agents étaient compromis maintenant, combien pourrais-je perdre au maximum ?**

Chez Plafond, la réponse n'est pas une estimation : chaque limite est écrite dans un covenant que
le réseau Kaspa fait respecter. Le chiffre se calcule à partir des paramètres des contrats et de
l'état de la chaîne, et il tient même face à un agent qui ment, antidate ou triche
(`spec/borne-de-perte.md`, théorème et corollaire).

## 2. Architecture

```
Étage 1  Trésorerie du propriétaire     (clé du propriétaire, hors du modèle de menace : H5)
   ↓
Étage 2  Budgets d'agents               (AgentBudget : un ou plusieurs couloirs par agent)
   ↓
Étage 3  Modes de paiement              (direct · séquestre · ardoise · futurs modes)
   ↓
Moteur de risque                        (lecture seule : ne détient aucun fonds)
```

Le moteur est **indépendant du mode de paiement** : chaque mode fournit sa propre formule de pire cas,
démontrée une fois ; le moteur additionne. Ajouter un mode, c'est ajouter une formule (section 5),
sans toucher aux autres.

## 3. Les quatre mesures

| Mesure | Définition |
|---|---|
| **M1. Perte maximale immédiate** | Ce qui peut quitter le contrôle du propriétaire à l'instant présent si tous les agents deviennent hostiles. |
| **M2. Perte maximale sur une durée D** | La même chose sur toute fenêtre qui commence maintenant et dure `D`. Par défaut, D = 24 h. |
| **M3. Exposition par agent** | M1 et M2 restreintes aux couloirs et aux engagements d'un agent. |
| **M5. Perte maximale du mandat** | Sur toute la vie d'un mandat (et de l'ensemble des mandats) : son capital alloué. |
| **M4. Exposition par vendeur** | Ce qui peut finir chez un vendeur donné : engagements ouverts chez lui, plus ce que les couloirs peuvent encore lui payer. |

« Perte » veut dire : des fonds qui sortent du contrôle du propriétaire, frais compris. Un paiement
légitime est une perte au sens de ce moteur : il mesure l'exposition, pas l'intention.

## 4. Formules

### 4.1 Notations

Pour une pièce `i` d'un coffre cœur v0.6 (paramètres publics du contrat, pièce lue sur le nœud) :

- `C_i` capacité (`capacity`, le plafond par achat frais compris), `R_i` période (`period`), en scores DAA ;
- `c_i` score DAA d'inscription de la pièce ; `g_i = now − c_i` son âge (pièce non confirmée : `g_i = 0`,
  borne sûre puisqu'elle ne peut être dépensée qu'après son inscription) ;
- `V_i` valeur de la pièce, en sompi ;
- `now` score DAA virtuel courant.

Toutes les divisions sont entières et arrondies vers le bas ; ces arrondis ne jouent jamais contre
le propriétaire.

### 4.2 Pièce d'un coffre (étage 2, paiement direct)

**Perte maximale immédiate** de la pièce (exactement ce que le script et le réseau accepteraient
maintenant) :

```
L1_i = min(V_i, C_i, C_i × g_i / R_i)
```

**Perte maximale sur D** (D en scores DAA), la pièce et toutes ses descendantes :

```
L2_i(D) = min(V_i, min(C_i, C_i × g_i / R_i) + C_i × D / R_i)
```

*Justification.* Théorème du §1 de `borne-de-perte-v0.6.md`. Il couvre aussi ce que l'agent
transfère vers un coffre frère : une pièce ne laisse jamais sortir plus que ce qu'elle a reçu.

**Courbe promise à la création** d'un mandat créé au score `t₀` par des apports `(Vₖ, xₖ)` du
propriétaire :

```
Courbe(t) = Σₖ min(Vₖ, C × (t − xₖ) / R)        perte nette maximale depuis la création
```

Elle ne dépend d'aucune hypothèse sur ce que fait l'agent ensuite (§1b de la preuve). La console
l'affiche à la création, puis la perte nette réelle à côté.

Une pièce déposée par n'importe qui à l'adresse du coffre est comptée comme les autres : le chiffre
surestime alors la perte du propriétaire (c'est l'argent de qui l'a déposé), sans jamais la
sous-estimer.

### 4.3 Séquestre DeliveryEscrow (étage 3)

Un séquestre ouvert a déjà quitté le couloir : sa dépense est comptée dans le couloir au moment
où il est financé. Tant qu'il n'est ni réclamé ni remboursé, sa valeur `S_j` est **engagée** chez le
vendeur `v_j` :

```
E_j = S_j            (au pire, le vendeur réclame ; les frais, ≤ maxFee, sont inclus dans S_j)
```

Après le délai, le remboursement vers le propriétaire devient possible, mais la réclamation aussi
(course documentée, R22) : le séquestre reste compté jusqu'à ce qu'il soit dépensé.

### 4.4 Agrégation

```
M1 = Σ_i L1_i + Σ_j E_j
M2(D) = Σ_i L2_i(D) + Σ_j E_j
M3(agent) = mêmes sommes, restreintes aux couloirs et séquestres de cet agent
```

**M5 (vie des mandats)** : `M5 = Σ_i V_i + Σ_j E_j`, par mandat ou pour l'ensemble.
*Justification :* un couloir ne peut dépenser que ce qu'il contient ; ce chiffre ne dépend ni du temps
ni d'une échéance. Il ne bouge que si le propriétaire ajoute des fonds (il augmente alors du montant
ajouté) ou révoque (il tombe à 0).

**Mandat et durée.** Un mandat de budget `b` par période `p` et de durée `n` jours reçoit
`b × ⌈n × 864 000 / p⌉` à l'ouverture (« capital alloué ») : sa perte maximale garantie est fixée dès
la création. La révocation automatique à l'échéance est un confort opérationnel (elle suppose la
console ouverte) ; la garantie repose sur le capital alloué, pas sur la date.

**M4 (vendeur `v`)** :

```
M4(v, D) = Σ_{j : v_j = v} E_j + Σ_{i : v peut être payé par i} L2_i(D)
```

Un couloir `i` peut payer `v` si :

- il n'a pas de liste blanche (`useAllowlist = 0`) : **tout vendeur**, donc son exposition entière ;
- ou `v` est dans sa liste blanche.

Conséquence affichée telle quelle : sans liste blanche, l'exposition « par vendeur » n'est pas plus
petite que l'exposition de l'agent. Le moteur ne doit jamais présenter un chiffre par vendeur plus
rassurant que ce que les contrats imposent.

## 5. Ajouter un mode de paiement

Un mode de paiement entre dans le moteur avec trois éléments :

1. une formule `E` de pire cas, en fonction de son état sur la chaîne ;
2. la démonstration que `E` borne ce qui peut sortir par ce mode ;
3. la règle d'attribution : à quel agent, à quel vendeur.

Exigence de composition : **un mode de l'étage 3 n'est financé que par un couloir de l'étage 2**, et ce
financement est compté dans la borne du couloir. Ainsi, aucun mode ne peut augmenter M2 au-delà de
la somme des couloirs plus ses propres engagements déjà ouverts.

**Ardoise (contrat v0.1, `contracts/ardoise.sil`).** Le dépôt `S` est payé depuis un couloir (donc
compté dans sa borne), puis bloqué par le covenant. Tant que l'ardoise est ouverte :
`E = S`, attribuée à son vendeur. *Justification :* `close` ne peut envoyer au vendeur que
`total ≤ S` (plus au plus `maxFee` si le reste est infime), le reste au propriétaire ; `refund` ne peut
envoyer qu'au propriétaire. Aucune sortie ne peut donc faire perdre plus que `S`.

## 6. Ce qui est garanti, et ce qui ne l'est pas

Le moteur affiche toujours ce tableau à côté des chiffres.

| | Couvert par la garantie |
|---|---|
| ✅ | Fonds dans les coffres cœur v0.6 (toutes les pièces de l'adresse) ; courbe promise à la création |
| ✅ | Séquestres DeliveryEscrow v0.3 ouverts depuis ces coffres |
| ⚠ | Exposition par vendeur : le cœur v0.6 n'a pas de liste blanche, elle est égale à celle de l'agent entier |
| ⚠ | Fenêtre glissante qui commence plus tard, pour un agent qui a la clé de plusieurs coffres (R52) : couverte en direct, pas a priori ; la courbe, elle, tient |
| ❌ | Portefeuille ordinaire de l'agent, ou tout fonds hors des coffres Plafond |
| ⚠ | Révocation automatique à l'échéance d'un mandat : seulement si la console est ouverte (le capital alloué reste garanti) |
| ❌ | Clé du propriétaire compromise (elle peut tout faire, par construction : H5) |
| ❌ | Coffres de versions refusées (v0.4, v0.5) ou de contrats inconnus |

Hypothèses dont dépendent les chiffres :

- **Contrat et preuve non audités.** La borne est démontrée sur papier et vérifiée par des milliers de
  scénarios contre le vrai moteur de script ; ce n'est pas une preuve formelle vérifiée par machine.
- **Temps en scores DAA.** Le réseau vise 10 scores par seconde, soit environ 864 000 pour 24 h ;
  la durée réelle varie légèrement. Le moteur affiche D en heures et en scores DAA.
- **Lecture de la chaîne.** Les chiffres valent pour l'état lu sur le nœud interrogé. Un vérificateur
  prudent interroge plusieurs nœuds indépendants.
- **Réorganisation.** La borne porte sur l'historique final (le réseau revalide le verrou relatif) ; un
  chiffre calculé juste avant une réorganisation est recalculé après.

## 7. Vérifiable par n'importe qui

Le calcul n'a besoin d'aucun secret. Il suffit :

1. des **paramètres et de l'état** de chaque couloir et séquestre (publiables sans risque : ils ne
   permettent pas de dépenser) ;
2. de la **chaîne** : un vérificateur recompile chaque contrat avec ces paramètres, vérifie que
   l'adresse obtenue porte bien la sortie annoncée et sa lignée KIP-20 (comme le vendeur à l'étape 2
   du profil x402), puis applique les formules.

Un associé, un comptable ou un auditeur peut donc refaire le calcul sans faire confiance à Plafond.

## 8. Format d'échange (proposition)

```json
{
  "version": "plafond-risque-v0",
  "daa": "631708669",
  "fenetre_daa": "864000",
  "perte_max_immediate_sompi": "320000000",
  "perte_max_fenetre_sompi": "720000000",
  "par_agent": [{ "agent": "<clé x-only>", "immediate": "…", "fenetre": "…" }],
  "par_vendeur": [{ "vendeur": "<empreinte du script>", "fenetre": "…", "restreint": true }],
  "non_couvert": ["agent:<clé> sans liste blanche", "…"]
}
```

Montants en sompi, sous forme de chaînes (entiers 64 bits sans perte de précision, voir l'issue
kaspa-x402 #40).

## 9. Tests à écrire avec l'implémentation

- Pour des suites aléatoires d'un agent avide (même générateur que
  `agent_avide_ne_depasse_jamais_la_borne`) : la dépense réelle sur `[now, now + D]` ne dépasse
  jamais `M2(D)` calculé à `now`, contre le vrai moteur de script.
- `M1` est atteignable, et pas davantage : une rafale de paiements (chacun ≤ `maxPerPayment`)
  partie de `now` atteint `A_i` à la recharge près des secondes écoulées, et un sompi de plus est
  refusé. `L1_i` est une borne haute prudente : le coffre ne peut pas être vidé jusqu'au dernier
  sompi (continuation obligatoire, masse KIP-9).
- Un vendeur hors liste blanche a une exposition directe nulle ; sans liste blanche, `M4 = M3`.
- Séquestre réclamé ou remboursé : il disparaît de `E`.

# Borne de perte : modèle de sécurité d'AgentBudget v0.5

> **Statut (20 nov. 2026) : propriété démontrée sur papier et vérifiée par tests automatisés**
> contre le vrai moteur de script (campagne longue : 4 000 scénarios par test, tous passés).
> **Pas encore** relue de façon indépendante ni auditée ; démonstrations testnet à faire.
> Reproduire : `./verify-proof.sh`.

## 1. Ce que l'on promet

Pour un couloir (un coffre) de réserve `C` (capacity) et de période de recharge `R`
(refillPeriod), sur **toute** durée réelle `D`, un agent, même compromis, ne peut pas faire
sortir du coffre plus que :

```
C + C × D / R      (et jamais plus que le solde du coffre)
```

La dépense comptée inclut les frais (montant + frais), parce que le contrat les décompte du budget.

**Réglage « garantie stricte » (option A, choix du 20 nov. 2026).** Pour un budget affiché `B`
sur une période `P` : `C = ⌊B / 2⌋`, `R = P`. Pour toute fenêtre `D ≤ P` :
`dépense ≤ 2 × ⌊B / 2⌋ ≤ B`. **Risque immédiat** (ce qu'un agent peut dépenser à l'instant
où il devient fou) : `C`, soit la moitié du budget.

Avec `n` couloirs, les bornes s'additionnent : l'outil doit répartir le budget, la somme des
réserves restant ≤ `⌊B / 2⌋`.

## 2. Ce qui a changé par rapport à v0.4 (et pourquoi)

En v0.4, la recharge courait depuis `lastDaa`, instant **annoncé par l'agent**. Le réseau garantit
seulement que cet instant n'est pas dans le futur (verrou temporel), jamais qu'il n'est pas dans
le passé. Attaque (« temps mis de côté ») sur un coffre plein et inactif : l'agent paie en annonçant
`nowDaa = lastDaa` (aucune recharge réclamée), vide la réserve sans faire avancer `lastDaa`, puis
réclame d'un coup le temps écoulé pendant que la réserve était pleine. Mesuré par le vrai moteur
de script : **3 × C sur une seule période** (test `attaque_temps_mis_de_cote_fermee`, historique).

En v0.5, la recharge court depuis `inputDaa`, le score DAA auquel le réseau a **réellement**
inscrit le coffre courant, lu dans le script par `OpTxInputDaaScore`. L'agent ne peut pas le
choisir. Motif repris de SompiVault (elldeeone), qui traite la même famille d'attaque.

Règles ajoutées au point d'entrée `pay` :

```
int inputDaa = OpTxInputDaaScore(this.activeInputIndex);
require(inputDaa >= lastDaa);        // coffre réellement inscrit ; un coffre non confirmé (−1) est refusé
int elapsed = nowDaa - inputDaa;     // ramené à [0, refillPeriod]
```

## 3. Démonstration

**Notation.** Les paiements acceptés d'un couloir forment une suite totalement ordonnée (chaque
paiement dépense la continuation du précédent : lignée KIP-20, une seule continuation).
Pour le paiement `k` :

- `t_k` : score DAA auquel le réseau accepte le paiement `k`, qui est aussi le score
  d'inscription de sa continuation ; `t_0` : inscription du coffre initial ;
- `now_k` : instant annoncé par l'agent ; `s_k` : dépense (montant + frais) ;
- `T_k` : jetons après le paiement `k`, `T_0 ≤ C` (garanti par `check_params`).

**Ce que le script impose** (v0.5) :

1. `now_k ≤ t_k` : `tx.daa ≥ now_k`, et le réseau n'accepte pas une transaction avant son verrou ;
2. `e_k = clamp(now_k − t_{k−1}, 0, R)`, donc `e_k ≤ t_k − t_{k−1}` ;
3. `a_k = min(C, T_{k−1} + ⌊e_k × C / R⌋)` ;
4. `s_k ≤ a_k` et `T_k = a_k − s_k ≥ 0` (état suivant validé par `validateOutputState`).

**Lemme.** Pour `k ≥ 1` : `a_k − T_{k−1} ≤ C × (t_k − t_{k−1}) / R`.
*Preuve :* `a_k ≤ T_{k−1} + ⌊e_k C / R⌋ ≤ T_{k−1} + e_k C / R`, et `e_k ≤ t_k − t_{k−1}` (2).
Les arrondis entiers (division euclidienne, plafond `min`, borne `clamp`) ne font que diminuer
`a_k` : ils jouent toujours en faveur du propriétaire.

**Théorème.** Pour tous `i ≤ j` : `s_i + … + s_j ≤ C + C × (t_j − t_i) / R`.
*Preuve :* `s_k = a_k − T_k`, d'où

```
Σ_{k=i..j} s_k = a_i − T_j + Σ_{k=i+1..j} (a_k − T_{k−1})
              ≤ C − 0 + Σ_{k=i+1..j} C (t_k − t_{k−1}) / R      (a_i ≤ C, T_j ≥ 0, lemme)
              = C + C (t_j − t_i) / R.                            (somme télescopique)
```

**Corollaire (fenêtre glissante).** Tous les paiements acceptés dans une fenêtre réelle de
durée `D` vérifient `t_j − t_i ≤ D`, d'où `dépense ≤ C + C × D / R`. ∎

## 4. Hypothèses (à vérifier par l'auditeur)

| # | Hypothèse | Où elle est vérifiée |
|---|---|---|
| H1 | `now_k ≤ t_k` : le verrou est testé contre le score DAA du bloc qui contient la transaction (`lock_time < daa_score` strict), lequel est ≤ au score d'acceptation `t_k` (point de vue de la chaîne qui l'accepte) inscrit sur les sorties ; le verrou ne peut pas être neutralisé par une séquence maximale, car `OpCheckLockTimeVerify` échoue dans ce cas et le contrat exige une entrée unique | lu dans `kaspa-consensus 2.1.0` (`body_validation_in_context.rs`, `tx_validation_in_header_context.rs`, `utxo_validation.rs` : sorties créées au `pov_daa_score`) et `kaspa-txscript 2.1.0` (`OpCheckLockTimeVerify`) ; **à relire par l'auditeur** |
| H2 | `OpTxInputDaaScore` renvoie ce score ; pour une sortie non confirmée il vaut `u64::MAX`, vu −1 par le script, donc refusé par `inputDaa ≥ lastDaa` | `kaspa-txscript 2.1.0`, `opcodes/mod.rs` ; test `coffre_non_confirme_refuse` |
| H3 | Une seule continuation par paiement, pas d'autre entrée, pas de sortie cachée | règles de forme du contrat ; fuzz `coffre_moteur_egal_modele` |
| H4 | Paramètres sains (`R > 0`, `maxPerPayment ≤ C`, `C × R` sur 63 bits, `T_0 ≤ C`, `initLastDaa ≤` inscription) | `check_params` (outil et vendeur) ; R33 |
| H5 | La clé du propriétaire n'est pas compromise (elle peut tout faire, par construction) | hors du modèle : clé chiffrée sur l'appareil du propriétaire |

**Unité de temps.** Le réseau mesure des scores DAA, pas des heures. La cible est de 10 par seconde,
soit environ 864 000 par 24 h ; l'ajustement de difficulté fait varier légèrement la durée réelle.
L'interface parle de « jour » ; ce document donne la définition exacte : `R` en scores DAA.

**Coût pour l'agent honnête.** La recharge ne compte plus le temps entre l'instant annoncé et
l'inscription (quelques secondes par paiement) ; un paiement enchaîné sur un coffre non encore
confirmé attend la confirmation (environ une seconde).

## 5. Validation automatique

| Test (`cli/src/fuzz.rs`) | Ce qu'il éprouve, contre le vrai moteur `kaspa-txscript` |
|---|---|
| `agent_avide_ne_depasse_jamais_la_borne` | le théorème, sur des suites aléatoires d'un agent avide qui antidate et triche, entre les instants **réels** d'inclusion |
| `attaque_temps_mis_de_cote_fermee` | l'attaque de v0.4 : le temps mis de côté rapporte 0 ; total ≤ 2 × C sur une période |
| `coffre_moteur_egal_modele` | le moteur et le modèle de référence décident toujours pareil (10 tricheries) |
| `coffre_non_confirme_refuse` | H2 |
| `parametres_aberrants_sans_danger_pour_les_fonds` | H4 |

| `faille_v04_demontree` | la faille sur le contrat v0.4 archivé : 3 × C sur une période (le test doit continuer à la montrer) |

Campagne longue du 20 nov. 2026 : `FUZZ_CASES=4000 cargo test --release fuzz::` : 11 tests,
tous passés (1 014 s). Commande unique : `./verify-proof.sh` ; la CI la rejoue à chaque envoi,
et chaque lundi avec 2 000 scénarios par test.

Restent à faire : relecture indépendante de la preuve et de H1,
démonstrations testnet (achat réussi, prix hors budget refusé, agent compromis rejeté par le
réseau), et une campagne sur le réglage exact de l'option A.

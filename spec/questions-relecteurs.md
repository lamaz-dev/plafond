# Questions à poser aux relecteurs

Notées au fil du travail, à envoyer quand la relecture externe commencera.

## Michael Sutton (SilverScript, covenants)

1. **Garde du verrou temporel.** AgentBudget s'appuie sur le fait que `require(tx.daa >= x)` est
   compilé avec `OpWithin(0, LOCK_TIME_THRESHOLD)` avant `OpCheckLockTimeVerify`
   (`silverscript-lang/src/compiler/compile/statement.rs`, `compile_require_tx_daa_statement`).
   Sans cette garde, un agent pourrait annoncer un instant ≥ 500 000 000 000 : le verrou serait lu
   comme une date déjà passée et le script accorderait une recharge complète. Cette garde est-elle
   une garantie stable du langage (documentée, conservée dans les versions futures) ? Notre test
   `verrou_en_date_refuse` la surveille.
2. **`OpTxInputDaaScore`.** Nous faisons courir la recharge depuis le score d'inscription de
   l'entrée (motif SompiVault) et refusons la valeur −1 (sortie non confirmée, `u64::MAX`).
   Ce score est-il garanti égal au score d'acceptation (`pov_daa_score`) dans tous les cas, y
   compris après une réorganisation ?
3. **Simplification envisagée pour une v0.6 : remplacer `lastDaa` par `require(inputDaa >= 0)`.**
   Une relecture externe (22 nov. 2026) propose de retirer `lastDaa` de l'état, jugé redondant avec
   `OpTxInputDaaScore`. Notre analyse : une fois l'entrée confirmée, `inputDaa >= lastDaa` découle
   bien du consensus (la sortie est inscrite à un score ≥ `tx.daa` ≥ `nowDaa`) ; mais pour une entrée
   **non confirmée** (paiements enchaînés dans le mempool), le score lu est −1, et ce contrôle est ce
   qui refuse le cas. Sans refus explicite, chaque paiement enchaîné recevrait une recharge complète
   et la borne prouvée tomberait (test `paiements_enchaines_non_confirmes_ne_rechargent_pas`,
   mutation M5). Questions : (a) un contrôle `require(inputDaa >= 0)` suffit-il, c'est-à-dire −1
   est-il la seule valeur possible hors confirmation ? (b) le gain de masse justifie-t-il un
   changement de contrat (le paiement minimal ≈ 0,02 KAS dépend surtout de la valeur des sorties,
   KIP-9, pas de la taille du script) ? Aucun changement de contrat n'est prévu sans mesure ni avis.

## Relecture du cœur v0.9.1 (lignée KIP-20, retrait partiel)

Notées le 27 nov. 2026 (`spec/red-team/retrait-2026-11-27.md`).

4. **Pièce marquée d'une lignée neuve (W10).** Une entrée peut ouvrir une lignée neuve (genèse) sur
   une sortie payée à une adresse ordinaire, et `OpAuthOutputCount` ne compte pas les genèses. La
   sortie d'un gel ou d'un retrait peut donc arriver à l'adresse de retour avec un identifiant de
   covenant. Un portefeuille courant (Kaspium, Ledger) ou une plateforme d'échange affiche-t-il et
   dépense-t-il une telle pièce comme une autre ? Faut-il l'interdire dans le script
   (`OpOutputCovenantId(i)` égal à l'identifiant nul) ?
5. **Frais du retrait partiel au rythme du contrat.** L'entrée `ownerWithdraw` applique aux frais la
   règle de `pay` (`f ≤ C`, âge `≥ ⌈f·R/C⌉`) pour qu'une clé de propriétaire volée ne puisse pas
   brûler le coffre en frais. Voyez-vous une forme plus simple qui donne la même garantie ?
6. **Dépense sans signature portant une lignée.** `absorb` et `recharger` ne sont pas signés. Les
   nœuds relaient-ils ces transactions comme les autres (pas de règle de relais particulière) ?

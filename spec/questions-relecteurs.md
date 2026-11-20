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

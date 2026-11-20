
## 2026-11-19 04:07 UTC

```
$ vault-cli adresses
Propriétaire (à alimenter au faucet) : kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz
Agent                                : kaspatest:qz07e7axgtmxaclyvnyk2e5vf95da8t6saalu0ym8nly5xpk8samsgkcr7c8a
Service payé par l'agent             : kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl
Porte-monnaie du relais (Kaspa x402) : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4

```

## 2026-11-19 04:21 UTC

```
$ vault-cli etat
Connecté au testnet-10 : wss://quark-10.kaspa.red/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 627272510
Solde du propriétaire : 1000 TKAS (1 UTXO)
Coffre : pas encore déployé

$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 605a11382264b13adf2c53e2e135258805cbc4ca21e3e14fa06632af2f66524e
Transaction : https://tn10.kaspa.stream/transactions/2c1777009e5c3ee913523e5dd5507185f291e0650a750f25581eec0c8d65cf1d

$ vault-cli pause 30
(pause de 30 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 627273003
Solde du propriétaire : 994.985 TKAS (1 UTXO)
Coffre : 5 TKAS, budget disponible ~2 TKAS (sortie 2c1777009e5c3ee913523e5dd5507185f291e0650a750f25581eec0c8d65cf1d:0)

$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (0 sompi)
GET https://demo.kaspa-x402.org/exact
Échec : fetch failed
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-19 04:25 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (0 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /supported : HTTP 200
  {"ok":true,"enabled":true,"kinds":[{"x402Version":2,"scheme":"exact","network":"kaspa:testnet-10","extra":{"asset":"KAS","binding":"kaspa-exact-v2","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2.0.0","modes":["verify","settle"]}},{"x402Version":2,"scheme":"batch-settlement
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Échec : fetch failed ← bounded fetch DNS answer contains a private or reserved address
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-19 04:39 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (0 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /supported : HTTP 200
  {"ok":true,"enabled":true,"kinds":[{"x402Version":2,"scheme":"exact","network":"kaspa:testnet-10","extra":{"asset":"KAS","binding":"kaspa-exact-v2","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2.0.0","modes":["verify","settle"]}},{"x402Version":2,"scheme":"batch-settlement
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Échec : invalid_kaspa_x402_payload exact funding requires a complete payer policy or explicit authorization callback
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-19 04:41 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (0 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /supported : HTTP 200
  {"ok":true,"enabled":true,"kinds":[{"x402Version":2,"scheme":"exact","network":"kaspa:testnet-10","extra":{"asset":"KAS","binding":"kaspa-exact-v2","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2.0.0","modes":["verify","settle"]}},{"x402Version":2,"scheme":"batch-settlement
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Connecté au testnet-10 : wss://quark-10.kaspa.red/kaspa/testnet-10/wrpc/borsh
Coffre → porte-monnaie : 0.5 TKAS : https://tn10.kaspa.stream/transactions/4abbbbabc8aa384a315f74dfac7a37825938db648b828c08885233c3cebf4426
Recharge du porte-monnaie depuis le coffre : 0.5 TKAS, transaction 4abbbbabc8aa384a315f74dfac7a37825938db648b828c08885233c3cebf4426
  https://tn10.kaspa.stream/transactions/4abbbbabc8aa384a315f74dfac7a37825938db648b828c08885233c3cebf4426
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-19 04:43 UTC

```
$ vault-cli pieces-porte-monnaie
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
[{"address":"kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4","amount":"50000000","outpoint":{"index":0,"txid":"4abbbbabc8aa384a315f74dfac7a37825938db648b828c08885233c3cebf4426"},"scriptPublicKey":"000020a3b905fef9f2f28872125d8b0c4fc703ce1ebdcf9fb0439e84f5c9626ceb80eeac"}]
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (50000000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /supported : HTTP 200
  {"ok":true,"enabled":true,"kinds":[{"x402Version":2,"scheme":"exact","network":"kaspa:testnet-10","extra":{"asset":"KAS","binding":"kaspa-exact-v2","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2.0.0","modes":["verify","settle"]}},{"x402Version":2,"scheme":"batch-settlement
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Réponse à la tentative payée : HTTP 503
  content-type: application/json; charset=utf-8
  corps : {"error":"exact_settlement_recovery_required"}
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-19 04:47 UTC

```
$ vault-cli relais-test-diffusion
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Masses : calcul 2036 g, transitoire 1264 g, stockage 63670 g (engagée 63670)
Transaction v0 acceptée : https://tn10.kaspa.stream/transactions/b137fd8ecbd66b00e6df107876bf6e0385e00bc0521ae681a98e5f9ebbf45f93

$ vault-cli pieces-porte-monnaie
Connecté au testnet-10 : wss://quark-10.kaspa.red/kaspa/testnet-10/wrpc/borsh
[{"address":"kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4","amount":"29700000","outpoint":{"index":1,"txid":"b137fd8ecbd66b00e6df107876bf6e0385e00bc0521ae681a98e5f9ebbf45f93"},"scriptPublicKey":"000020a3b905fef9f2f28872125d8b0c4fc703ce1ebdcf9fb0439e84f5c9626ceb80eeac"}]
```

## 2026-11-19 04:49 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-19T04:45:51.590Z","trigger":"scheduled","ok":true,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"627286645"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Réponse à la tentative payée : HTTP 503
  content-type: application/json; charset=utf-8
  corps : {"error":"exact_settlement_recovery_required"}
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

$ vault-cli pieces-porte-monnaie
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
[{"address":"kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4","amount":"29700000","outpoint":{"index":1,"txid":"b137fd8ecbd66b00e6df107876bf6e0385e00bc0521ae681a98e5f9ebbf45f93"},"scriptPublicKey":"000020a3b905fef9f2f28872125d8b0c4fc703ce1ebdcf9fb0439e84f5c9626ceb80eeac"}]
```

## 2026-11-20 04:25 UTC

```
$ routeur (démo) + agent Python
Budget de l'agent : 2.0 TKAS disponibles, 0.5 TKAS max par paiement

=== 1. L'agent achète une donnée (0,2 TKAS) ===
Contenu : Météo du réseau Kaspa : 10 blocs/s, mempool calme, frais bas.
Payé 0.2 TKAS depuis le coffre : https://tn10.kaspa.stream/transactions/3583ba3e9d0fb145ccf62d4e952f79bea38b9e361dfbc3673ff79e8b48a4aa75

=== 2. Le vendeur demande 1 TKAS, au-dessus du plafond de 0,5 ===
Refusé avant tout paiement : prix 100000000 sompi supérieur au plafond demandé (50000000)

=== 3. Agent compromis : il contourne le logiciel et diffuse 1 TKAS directement ===
Le réseau Kaspa REFUSE la transaction : elle viole le covenant du coffre.
Réponse du nœud : RPC Server (remote error) -> Rejected transaction 6f23fff91d6cb185f5c23fc8f035c62528f4cb10e6baaead72f8b1fe390d493b: failed to verify the signature script: script ran, but verification failed

Budget restant : 1.78794444 TKAS
VERDICT : le coffre a payé ce qui était permis et le réseau a bloqué le reste.
--- journal du routeur ---
[ROUTEUR] à l'écoute sur http://127.0.0.1:8403 (démo : oui, plafond par requête : 50000000 sompi)
[ROUTEUR] l'agent demande http://127.0.0.1:8402/meteo-kaspa

[AGENT] GET http://127.0.0.1:8402/meteo-kaspa
[VENDEUR] /meteo-kaspa : paiement requis (0.2 TKAS)
[AGENT] 402 reçu : 0.2 TKAS à payer à kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl
[AGENT] paiement signé depuis le coffre, envoi au vendeur
[VENDEUR] autorisation valide : signée par la clé agent du coffre pour cette requête
[VENDEUR] coffre authentique : script AgentBudget recompilé = sortie on-chain (4.485 TKAS), lignée 605a11382264b13adf2c53e2e135258805cbc4ca21e3e14fa06632af2f66524e
[VENDEUR] solvable : budget restant 2 TKAS ≥ prix 0.2 TKAS
[VENDEUR] paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/3583ba3e9d0fb145ccf62d4e952f79bea38b9e361dfbc3673ff79e8b48a4aa75
[AGENT] ✅ contenu reçu : « Météo du réseau Kaspa : 10 blocs/s, mempool calme, frais bas. »
[AGENT] reçu de paiement : transaction 3583ba3e9d0fb145ccf62d4e952f79bea38b9e361dfbc3673ff79e8b48a4aa75
[ROUTEUR] l'agent demande http://127.0.0.1:8402/rapport-premium

[AGENT] GET http://127.0.0.1:8402/rapport-premium
[VENDEUR] /rapport-premium : paiement requis (1 TKAS)
[AGENT] 402 reçu : 1 TKAS à payer à kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl
[AGENT] je refuse : prix supérieur au plafond de cette requête
[ROUTEUR] démo : paiement de 1 TKAS diffusé SANS contrôle local

```

## 2026-11-20 09:43 UTC

```
$ vault-cli recuperer-v04
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/1e56fb331dfe10dc2016f9186801d3d05cb75d5c1d2e8a3471342de6a25792df

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli deployer
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 5bfda1d635cf07e8b5dfbdd90227a2f04fac7f3006dee8afe1ccb447b155e3f9
Transaction : https://tn10.kaspa.stream/transactions/cccae0caa2211c86e687b0b82369d7f5dcef06a2e20fd0883b265de68b502f78

$ vault-cli pause 20
(pause de 20 s)

$ vault-cli payer 20000000
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Budget disponible : 2 TKAS, paiement demandé : 0.2 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/dbd1e55df21c4eec090b6928473d26f55e7d6dcefb58e57f0133f62dc402134f

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli payer 30000000
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Budget disponible : 1.78805555 TKAS, paiement demandé : 0.3 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/41323aed939bd3fe953638c53b9ab8f33a5a6ecccf61e1995e9d17b097311939

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628327461
Solde du propriétaire : 994.41 TKAS (2 UTXO)
Coffre : 4.47 TKAS, budget disponible ~1.47672221 TKAS (sortie 41323aed939bd3fe953638c53b9ab8f33a5a6ecccf61e1995e9d17b097311939:1)

$ vault-cli recuperer --sans-etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
État local absent ou périmé : recherche du coffre courant (mode survie)…
Coffre retrouvé après 2 paiement(s), chaque saut vérifié : sortie 41323aed939bd3fe953638c53b9ab8f33a5a6ecccf61e1995e9d17b097311939:1, 4.47 TKAS
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/02ba27cf4adcbf72c7b2614985d7e514cfd4506a0affccafdfdb06ceeea6465e

$ vault-cli pause 10
(pause de 10 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628327578
Solde du propriétaire : 998.865 TKAS (3 UTXO)
Coffre : pas encore déployé

```

## 2026-11-20 10:15 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 7cbd7f2a5432734844520b75518b727dc7343c6278dd0bb4b562fd140cc7a180
Transaction : https://tn10.kaspa.stream/transactions/f3479b88a8ff10029413054c43569ae4a29e4c6a84ee9870cbbdcd8b49859d11

$ vault-cli pause 360
(pause de 360 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628348205
Solde du propriétaire : 993.82 TKAS (1 UTXO)
Coffre : 5 TKAS, budget disponible ~2 TKAS (sortie f3479b88a8ff10029413054c43569ae4a29e4c6a84ee9870cbbdcd8b49859d11:0)

$ vault-cli attaque tout
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
[ATTAQUE] jetons gonflés dans l'état suivant : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction c1d2c8337a26d4c704e8eb98bff3ccb73d11c27c9592860eddc74626a4782864: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] règles plus lâches dans la continuation : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 68ccb42347486e42b9aafa488e1431e3862e5f0b8cc64d214172fded09c92931: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] reste du coffre détourné vers l'attaquant : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction c77007a53c4548103827f0a775a28746737b79b72f493c37475e2e0ec857cd83: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] frais excessifs (vidage par les frais) : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction a8f17aebfd024f1a4afe57c6246e7eec65650c6bdea5f4bcac7275f61053b126: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] paiement de poussière (1 000 sompi, KIP-9) : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction f9b559c91534606b6272eeebea057d6cc3074a16e6878f1e0952150e691a7732: transaction storage mass of 1000000024 is larger than max allowed size of 500000
[TÉMOIN] vidage antidaté n°1 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/35fe0e1e92c9eafd20df5368872f78746bb20fd5fdb22efa2e9c81691ea79ef8
[TÉMOIN] vidage antidaté n°2 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/41450c51953a83f161cc083e61def2f07a8044db353b0560e4f202f3b0331105
[TÉMOIN] vidage antidaté n°3 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/a8ac4d8484b6b62b51a8bbdd1b4dfb6742f1b206ee5f9e6a1f92c3e98a8009a3
[TÉMOIN] vidage antidaté n°4 (0.44 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/28141982d17612af275e465a07764ae258c9deab897d56cda1c88972bc05e269
[ATTAQUE] temps mis de côté : en v0.4 l'agent aurait disposé de 0.18555555 TKAS ; en v0.5 de 0 TKAS ; il tente 0.17055555 TKAS
Error: "paramètres invalides : plafond, frais ou jetons supérieurs à la capacité"
(code de sortie 1)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628348311
Solde du propriétaire : 993.82 TKAS (1 UTXO)
Coffre : 3 TKAS, budget disponible ~0 TKAS (sortie 28141982d17612af275e465a07764ae258c9deab897d56cda1c88972bc05e269:1)

$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/4370f70c55a197ccf475ee808f436bee247399d317c6f334c4db36a210141c28

$ vault-cli pause 10
(pause de 10 s)

$ vault-cli etat
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628348819
Solde du propriétaire : 996.805 TKAS (2 UTXO)
Coffre : pas encore déployé

```

## 2026-11-20 10:26 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 1793d11282748ddd8bfa5a7c6ec0aca9b66cf9af41a03af4dd69fd10cb7b8c2a
Transaction : https://tn10.kaspa.stream/transactions/a25188efb9a05d0e1136c7b7a329ebfc443cc97ac7c53a148e94d0c85941f6ec

$ vault-cli pause 360
(pause de 360 s)

$ vault-cli attaque temps
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
[TÉMOIN] vidage antidaté n°1 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/5a849a0aecf85bb595e052818a675b37820bdbaffe00d1ffcee03bd4d640ccbf
[TÉMOIN] vidage antidaté n°2 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/864010c3e73449226b71518f1b542e0720b9a2c34a31c5ebdfca18f75d95c0b2
[TÉMOIN] vidage antidaté n°3 (0.5 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/7180c9aff2639389b11879edd2f3a687ea3ab3cdd01cac2c3c64e82d3d873f89
[TÉMOIN] vidage antidaté n°4 (0.44 TKAS) : acceptée : https://tn10.kaspa.stream/transactions/15b462e7d9ecc24aef4073925c29e57ba7f664651d71fe1126148a07ad8fde37
[ATTAQUE] temps mis de côté : en v0.4 l'agent aurait disposé de 0.21244444 TKAS ; en v0.5 de 0 TKAS ; il tente 0.19744444 TKAS
[ATTAQUE] réclamation du temps mis de côté : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction d240a5babcd6d78c56bc4629785d56b2a67f13b1b6edc04732f3aeff4638624e: failed to verify the signature script: script ran, but verification failed

$ vault-cli etat
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628354532
Solde du propriétaire : 993.715 TKAS (5 UTXO)
Coffre : 3 TKAS, budget disponible ~0.0075 TKAS (sortie 15b462e7d9ecc24aef4073925c29e57ba7f664651d71fe1126148a07ad8fde37:1)

$ vault-cli recuperer
Connecté au testnet-10 : wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/3dfe079679f73134ea32f1605cdd1f8a84bb09b6b650d7554917e1e1f6b67f91

$ vault-cli pause 10
(pause de 10 s)

$ vault-cli etat
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628354893
Solde du propriétaire : 996.7 TKAS (6 UTXO)
Coffre : pas encore déployé

```

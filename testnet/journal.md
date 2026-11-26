
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

## 2026-11-20 11:30 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 65168a33b23989fa3e00293455d9b5f0b5a3572b381500061d8b2dcbd2f80854
Transaction : https://tn10.kaspa.stream/transactions/e4a5c1f147fc08dce3b96d25ba2a3804f103ea600eb51880f0a69cd743d84687

$ vault-cli pause 20
(pause de 20 s)

$ vault-cli payer 20000000
Connecté au testnet-10 : wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh
Budget disponible : 2 TKAS, paiement demandé : 0.2 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/4c5924717e0bcdcc68d36a70a93d6fd3de74b00ce5702e8424863ab35483b630

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli attaque regles
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
[ATTAQUE] jetons gonflés dans l'état suivant : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 37f412d993efbfb5a1a049b7182be665f5f8575346a0313d571a518544744765: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] règles plus lâches dans la continuation : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 3368770c8d5a23404ed7ee8eee6028a246fdb1d12beaad3317c72d3e2872528b: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] reste du coffre détourné vers l'attaquant : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 80d74ea8bcc85374a3c140681cb03d0c33a360a230324a6b729fa5cd7a141da7: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] frais excessifs (vidage par les frais) : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 40998bc7fc91bdbd4e3d61ac9fbc641e1727e3026719121adf6428dae9de14c1: failed to verify the signature script: script ran, but verification failed
[ATTAQUE] paiement de poussière (1 000 sompi, KIP-9) : REJETÉE par le réseau, comme attendu
          message du nœud : RPC Server (remote error) -> Rejected transaction 9c7c6d92ed89d40ff5d9a69a3c963b944492969045964a4f8f3766d966938a29: transaction storage mass of 1000000027 is larger than max allowed size of 500000

$ vault-cli recuperer --sans-etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
État local absent ou périmé : recherche du coffre courant (mode survie)…
Coffre retrouvé après 1 paiement(s), chaque saut vérifié : sortie 4c5924717e0bcdcc68d36a70a93d6fd3de74b00ce5702e8424863ab35483b630:1, 4.785 TKAS
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/071908d565f36609e31ce85bff589abf3175dab4f614b49725d00949211d17b2 (frais 0.06 TKAS, tentative 1)

$ vault-cli pause 10
(pause de 10 s)

$ vault-cli etat
Connecté au testnet-10 : wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628390860
Solde du propriétaire : 996.41 TKAS (7 UTXO)
Coffre : pas encore déployé

```

## 2026-11-20 11:50 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée d2c1a6d9cdce6c5870aff43e92085066a230d0133e45a059f01c20c863850f95
Transaction : https://tn10.kaspa.stream/transactions/f9a335c113f4b3d805c50b3e355a774764a34ca8fda859c0956099b4147b0a1d

$ vault-cli pause 20
(pause de 20 s)

$ vault-cli payer 20000000
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Budget disponible : 2 TKAS, paiement demandé : 0.2 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/191e4474dfaa89db7235e31d4bf555a851f7d4c030ed9e7257aa8f26809ce553

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli payer 30000000
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Budget disponible : 1.81111111 TKAS, paiement demandé : 0.3 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/35aa90a097000aaf8f6eef7c1602b6c1909152117773767aa922a18b52426a1a

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli recuperer --sans-etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
État local absent ou périmé : recherche du coffre courant (mode survie)…
Coffre retrouvé après 2 paiement(s), chaque saut vérifié : sortie 35aa90a097000aaf8f6eef7c1602b6c1909152117773767aa922a18b52426a1a:1, 4.47 TKAS
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/4982d4c321ae25c132cb6fdd4417e9e170c539bb77a4c5e5fd9b6fbe8a39c071 (frais 0.06 TKAS, tentative 1)

$ vault-cli pause 10
(pause de 10 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 628403450
Solde du propriétaire : 995.79 TKAS (7 UTXO)
Coffre : pas encore déployé

```

## 2026-11-20 13:06 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre déployé : 5 TKAS, budget 2 TKAS, lignée 39f8db380f7984143e80adaeef122e3f90334ee964ba832d20740d69dfa54f5c
Transaction : https://tn10.kaspa.stream/transactions/98fee03c839e70ab57309ebb575210fd45064df056d89dc0c2a852b7d751ca27

$ vault-cli pause 20
(pause de 20 s)

$ vault-cli payer 20000000
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Budget disponible : 2 TKAS, paiement demandé : 0.2 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/8f1df8f70ea029a15d29a37e91b685e4d54d8dbc0b8232d61ec43b5eb62e021d

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli payer 30000000
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Budget disponible : 1.78805555 TKAS, paiement demandé : 0.3 TKAS
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/e85503772a2ae8358896ecd94a62595c7299e7a16ab079e8a328f90658f4354f

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli tableau
Connecté au testnet-10 : wss://electron-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
{
  "adresse_proprietaire": "kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz",
  "cours": null,
  "depense_periode_sompi": 53000000,
  "exposition_immediate_sompi": 148638888,
  "historique": [
    {
      "destinataire": "203969c8eb54dcf9e166422364e009138202f25464a0dad468607f19e41db367b7ac",
      "frais_sompi": 1500000,
      "genre": "achat",
      "instant_daa": 628448454,
      "montant_sompi": 30000000,
      "txid": "e85503772a2ae8358896ecd94a62595c7299e7a16ab079e8a328f90658f4354f"
    },
    {
      "destinataire": "203969c8eb54dcf9e166422364e009138202f25464a0dad468607f19e41db367b7ac",
      "frais_sompi": 1500000,
      "genre": "achat",
      "instant_daa": 628448288,
      "montant_sompi": 20000000,
      "txid": "8f1df8f70ea029a15d29a37e91b685e4d54d8dbc0b8232d61ec43b5eb62e021d"
    }
  ],
  "regles": {
    "budget_garanti_par_periode_sompi": 400000000,
    "frais_max_par_achat_sompi": 3000000,
    "periode_daa": 36000,
    "periode_secondes": 3600,
    "plafond_par_achat_sompi": 50000000,
    "reserve_sompi": 200000000
  },
  "sante": "normal",
  "solde_coffre_sompi": 447000000,
  "solde_proprietaire_sompi": 99076000000,
  "technique": {
    "contrat": "AgentBudget v0.5.1 (covenant SilverScript)",
    "empreinte_source_contrat": "849ca5814d6fd359c806e522fa06479ac2ee43298f1a66e97a7e9b30ec0f8223",
    "explorateur": "https://tn10.kaspa.stream/transactions/e85503772a2ae8358896ecd94a62595c7299e7a16ab079e8a328f90658f4354f",
    "lignee": "39f8db380f7984143e80adaeef122e3f90334ee964ba832d20740d69dfa54f5c",
    "reseau": "Kaspa testnet-10",
    "sortie_courante": "e85503772a2ae8358896ecd94a62595c7299e7a16ab079e8a328f90658f4354f:1"
  }
}

$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre récupéré par le propriétaire : https://tn10.kaspa.stream/transactions/cb6ed00ff0e3dad0afca0d36f2eb8c7053c34748f9feb03835905251fd84c6ba (frais 0.06 TKAS, tentative 1)

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli tableau
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
{
  "adresse_proprietaire": "kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz",
  "cours": null,
  "gel": "cb6ed00ff0e3dad0afca0d36f2eb8c7053c34748f9feb03835905251fd84c6ba",
  "historique": [
    {
      "destinataire": "203969c8eb54dcf9e166422364e009138202f25464a0dad468607f19e41db367b7ac",
      "frais_sompi": 1500000,
      "genre": "achat",
      "instant_daa": 628448288,
      "montant_sompi": 20000000,
      "txid": "8f1df8f70ea029a15d29a37e91b685e4d54d8dbc0b8232d61ec43b5eb62e021d"
    },
    {
      "destinataire": "203969c8eb54dcf9e166422364e009138202f25464a0dad468607f19e41db367b7ac",
      "frais_sompi": 1500000,
      "genre": "achat",
      "instant_daa": 628448454,
      "montant_sompi": 30000000,
      "txid": "e85503772a2ae8358896ecd94a62595c7299e7a16ab079e8a328f90658f4354f"
    },
    {
      "destinataire": null,
      "frais_sompi": 6000000,
      "genre": "gel",
      "instant_daa": null,
      "montant_sompi": 441000000,
      "txid": "cb6ed00ff0e3dad0afca0d36f2eb8c7053c34748f9feb03835905251fd84c6ba"
    }
  ],
  "regles": {
    "budget_garanti_par_periode_sompi": 400000000,
    "frais_max_par_achat_sompi": 3000000,
    "periode_daa": 36000,
    "periode_secondes": 3600,
    "plafond_par_achat_sompi": 50000000,
    "reserve_sompi": 200000000
  },
  "sante": "gele",
  "solde_proprietaire_sompi": 99517000000
}

```

## 2026-11-24 07:56 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-24T07:46:26.942Z","trigger":"scheduled","ok":true,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"631708669"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{
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

## 2026-11-24 07:58 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-24T07:46:26.942Z","trigger":"scheduled","ok":true,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"631708669"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://neutrino-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (1/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (2/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (3/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (4/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (5/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (6/6)
Réponse à la tentative payée : HTTP 503
  content-type: application/json; charset=utf-8
  corps : {"error":"exact_settlement_recovery_required"}
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-24 11:22 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-24T11:16:20.648Z","trigger":"scheduled","ok":true,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"631834233"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (1/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (2/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (3/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (4/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (5/6)
Réponse 503 (reprise du règlement en cours) : nouvel envoi de la même requête signée dans 10 s (6/6)
Réponse à la tentative payée : HTTP 503
  content-type: application/json; charset=utf-8
  corps : {"ok":false,"error":"invalid_transaction_state"}
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-24 11:26 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-24T11:16:20.648Z","trigger":"scheduled","ok":true,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"631834233"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Transaction de paiement signée 2026-11-24T11:27:22.395Z : tentative 21f6a62d399c7089fcc09521abcbb3dde51d01104d9015b03d48f5d4e613b581, transaction 6837e74168aa97b717b5fa9a436ae424e70faa2bd4865e058955e126ddaa4cb7, entrées b137fd8ecbd66b00e6df107876bf6e0385e00bc0521ae681a98e5f9ebbf45f93:1
2026-11-24T11:27:34.676Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (1/6)
2026-11-24T11:27:54.152Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (2/6)
2026-11-24T11:28:16.234Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (3/6)
2026-11-24T11:28:35.645Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (4/6)
2026-11-24T11:28:59.122Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (5/6)
2026-11-24T11:29:21.122Z réponse 503 {"error":"exact_settlement_recovery_required"} : nouvel envoi de la même requête signée dans 10 s (6/6)
Réponse à la tentative payée : HTTP 503 (2026-11-24T11:29:40.523Z)
  content-type: application/json; charset=utf-8
  corps : {"error":"exact_settlement_recovery_required"}
Échec : invalid_kaspa_settlement_response paid retry response is missing PAYMENT-RESPONSE
VERDICT : ÉCHEC
(code de sortie 1)

```

## 2026-11-24 16:32 UTC

```
$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632023840
Solde du propriétaire : 995.17 TKAS (7 UTXO)
Coffre : pas encore déployé

$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.6) : 5 TKAS à l'adresse kaspatest:pp4me74nq5xs3llwv4lxjyd6tzsst29m2q29efjqs6fm83g39r8tz4y3ufxxr
Transaction : https://tn10.kaspa.stream/transactions/de54a55966a26542e22a24d0309279ed990da9f794e465da05fa67f88ba1df7b

$ vault-cli pause 30
(pause de 30 s)

$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 2/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Error: "réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC"
(code de sortie 1)

$ vault-cli payer 5000000
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/845152a01e23d66ddd9b26bb85eed08f039d4b738a00f957e792b27a9273e2f4

$ vault-cli pause 240
(pause de 240 s)

$ routeur (démo) + agent Python
Budget de l'agent : 0.26220104 TKAS disponibles, 0.485 TKAS max par paiement

=== 1. L'agent achète une donnée (0,2 TKAS) ===
Contenu : Météo du réseau Kaspa : 10 blocs/s, mempool calme, frais bas.
Payé 0.2 TKAS depuis le coffre : https://tn10.kaspa.stream/transactions/6da83d6275b8bd0fb46433ac6690403885ed5f9e08e2ecd2b08284b3ab5f3b9f

=== 2. Le vendeur demande 1 TKAS, au-dessus du plafond de 0,5 ===
Refusé avant tout paiement : prix 100000000 sompi supérieur au plafond demandé (48500000)

=== 3. Agent compromis : il contourne le logiciel et diffuse 1 TKAS directement ===
Le réseau Kaspa REFUSE la transaction : elle viole le covenant du coffre.
Réponse du nœud : REFUSÉ par le réseau : RPC Server (remote error) -> Rejected transaction bca98bd4a33061bb49678017d71d5e86d5e71bbcb33b7f6006233173876ad144: failed to verify the signature script: script ran, but verification failed

Budget restant : 0.05735951 TKAS
VERDICT : le coffre a payé ce qui était permis et le réseau a bloqué le reste.
--- journal du routeur ---

[AGENT] GET http://127.0.0.1:8402/meteo-kaspa
[VENDEUR] /meteo-kaspa : paiement requis (0.2 TKAS)
[AGENT] 402 reçu : 0.2 TKAS à payer à kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl
[AGENT] paiement signé depuis le coffre, envoi au vendeur
[VENDEUR] autorisation valide : signée par la clé agent du coffre pour cette requête
[VENDEUR] coffre authentique : script Plafond recompilé = pièce on-chain (4.935 TKAS)
[VENDEUR] solvable : âge de la pièce 2713 ≥ délai exigé 2212 pour 0.215 TKAS
[VENDEUR] paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/6da83d6275b8bd0fb46433ac6690403885ed5f9e08e2ecd2b08284b3ab5f3b9f
[AGENT] ✅ contenu reçu : « Météo du réseau Kaspa : 10 blocs/s, mempool calme, frais bas. »
[AGENT] reçu de paiement : transaction 6da83d6275b8bd0fb46433ac6690403885ed5f9e08e2ecd2b08284b3ab5f3b9f
[ROUTEUR] l'agent demande http://127.0.0.1:8402/rapport-premium

[AGENT] GET http://127.0.0.1:8402/rapport-premium
[VENDEUR] /rapport-premium : paiement requis (1 TKAS)
[AGENT] 402 reçu : 1 TKAS à payer à kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl
[AGENT] je refuse : prix supérieur au plafond de cette requête
[ROUTEUR] démo : paiement de 1 TKAS diffusé SANS contrôle local
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)

$ vault-cli payer 45000000 --sans-verif
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Paiement REFUSÉ par le réseau : RPC Server (remote error) -> Rejected transaction 42f46b37f0ca2da8d55869481a77d6ceb486e886faa67a06bc84d399e87f5a85: failed to verify the signature script: Unsatisfied lock time: locktime requirement not satisfied -- locktime is greater than the transaction locktime: 4783 > 600
(code de sortie 2)

$ vault-cli pause 90
(pause de 90 s)

$ vault-cli payer 5000000
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Paiement accepté par le réseau : https://tn10.kaspa.stream/transactions/31256050beea873135acf84063841011f1a88914acce69c41124ac0271cbabe1

$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632030112
Solde du propriétaire : 990.125 TKAS (5 UTXO)
Coffre (cœur v0.6) kaspatest:pp4me74nq5xs3llwv4lxjyd6tzsst29m2q29efjqs6fm83g39r8tz4y3ufxxr : 4.655 TKAS en 1 pièce(s)
  disponible maintenant : 0.0264437 TKAS ; pire cas sur 24 h : 4.655 TKAS
  perte nette depuis la création : 0.345 TKAS (courbe promise : 0.60927474 TKAS)

$ vault-cli recuperer
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
tentative 1 : RPC Server (remote error) -> Rejected transaction 89570617fddf15bb8e18c1f87e7967700c042cade44de9ae6b93ada8c8fa0ac3: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 1 refusée : RPC Server (remote error) -> Rejected transaction 89570617fddf15bb8e18c1f87e7967700c042cade44de9ae6b93ada8c8fa0ac3: replace by fee found no double spending transaction in the mempool
tentative 2 : RPC Server (remote error) -> Rejected transaction 1f7021434f17837fac09ef071ac57e387a55a1e9d73a6d68c08ad46d70b9df53: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 2 refusée : RPC Server (remote error) -> Rejected transaction 1f7021434f17837fac09ef071ac57e387a55a1e9d73a6d68c08ad46d70b9df53: replace by fee found no double spending transaction in the mempool
tentative 3 : RPC Server (remote error) -> Rejected transaction fed14dc43ae6e3839c82529adc86468a5f5e089e867967905d353e1ba88c6aac: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 3 refusée : RPC Server (remote error) -> Rejected transaction fed14dc43ae6e3839c82529adc86468a5f5e089e867967905d353e1ba88c6aac: replace by fee found no double spending transaction in the mempool
tentative 4 : RPC Server (remote error) -> Rejected transaction 16b93ac9db69822d8154e802c1c588f912cad1bdb8e069f42b06c79c47568014: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 4 refusée : RPC Server (remote error) -> Rejected transaction 16b93ac9db69822d8154e802c1c588f912cad1bdb8e069f42b06c79c47568014: replace by fee found no double spending transaction in the mempool
tentative 5 : RPC Server (remote error) -> Rejected transaction 6307d971549a6f460fe54cf5ba94a9fb49933c59be8cd215311d47995399b920: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 5 refusée : RPC Server (remote error) -> Rejected transaction 6307d971549a6f460fe54cf5ba94a9fb49933c59be8cd215311d47995399b920: replace by fee found no double spending transaction in the mempool
tentative 6 : RPC Server (remote error) -> Rejected transaction e2d1a8c22e85f4d2a3603efbac756d8e19b9a69aac451d240e66d91cf16edaed: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 6 refusée : RPC Server (remote error) -> Rejected transaction e2d1a8c22e85f4d2a3603efbac756d8e19b9a69aac451d240e66d91cf16edaed: replace by fee found no double spending transaction in the mempool
tentative 7 : RPC Server (remote error) -> Rejected transaction 1e47662c296684473bd1d8724654877e20b01892fa29b094a8984b2beee4e00f: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 7 refusée : RPC Server (remote error) -> Rejected transaction 1e47662c296684473bd1d8724654877e20b01892fa29b094a8984b2beee4e00f: replace by fee found no double spending transaction in the mempool
tentative 8 : RPC Server (remote error) -> Rejected transaction 3017eadfc75f42746732f19ca50e797c1559b0e80c5ee66d66041cfad6f6bdfd: failed to verify the signature script: script units exceeded the amount committed in the input: used=100589, limit=59999 ; remplacement du paiement en attente
tentative 8 refusée : RPC Server (remote error) -> Rejected transaction 3017eadfc75f42746732f19ca50e797c1559b0e80c5ee66d66041cfad6f6bdfd: replace by fee found no double spending transaction in the mempool
Error: "gel incomplet : 1 pièce(s) encore dans le coffre, relancer"
(code de sortie 1)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632030648
Solde du propriétaire : 990.125 TKAS (5 UTXO)
Coffre (cœur v0.6) kaspatest:pp4me74nq5xs3llwv4lxjyd6tzsst29m2q29efjqs6fm83g39r8tz4y3ufxxr : 4.655 TKAS en 1 pièce(s)
  disponible maintenant : 0.07835893 TKAS ; pire cas sur 24 h : 4.655 TKAS
  perte nette depuis la création : 0.345 TKAS (courbe promise : 0.66118996 TKAS)

```

## 2026-11-24 16:44 UTC

```
$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632032752
Solde du propriétaire : 990.125 TKAS (5 UTXO)
Coffre (cœur v0.6) kaspatest:pp4me74nq5xs3llwv4lxjyd6tzsst29m2q29efjqs6fm83g39r8tz4y3ufxxr : 4.655 TKAS en 1 pièce(s)
  disponible maintenant : 0.28261714 TKAS ; pire cas sur 24 h : 4.655 TKAS
  perte nette depuis la création : 0.345 TKAS (courbe promise : 0.86544818 TKAS)

$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
1 pièce(s) rapatriée(s) : 4.625 TKAS, https://tn10.kaspa.stream/transactions/89570617fddf15bb8e18c1f87e7967700c042cade44de9ae6b93ada8c8fa0ac3

$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632033290
Solde du propriétaire : 994.75 TKAS (6 UTXO)
Coffre : pas encore déployé

```

## 2026-11-24 16:51 UTC

```
$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632037675
Solde du propriétaire : 994.75 TKAS (6 UTXO)
Coffre : pas encore déployé

```

## 2026-11-25 13:47 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.6) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:ppunu6a5274nn79m3rrg0ysvqmvf69zd3p9dxnuwla5lgxll44h5cfzmcqdp2
Transaction : https://tn10.kaspa.stream/transactions/23953cad4759f4bfe36cba4189989b6361d5572a32eebbbcf4b8d6646d4b31e1

$ vault-cli ardoise-ouvrir 20000000
Ardoise chez le vendeur kaspatest:qquknj8t2nw0nctxgg3kfcqfzwpq9uj5vjsd44rgvpl3neqakdnmwy8muhgdl : dépôt 0.2 TKAS, délai 864000 blocs (~1440 min)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Ardoise ouverte depuis le coffre : https://tn10.kaspa.stream/transactions/6c39f155b9e53bac79c60ae08949c64f85a9a2a5afc492aaf3e1646d9523d429

$ vault-cli ardoise-bon 3000000
Bon signé hors chaîne : total dû 0.03 TKAS sur 0.2 (aucune transaction)

$ vault-cli ardoise-bon 3000000
Bon signé hors chaîne : total dû 0.06 TKAS sur 0.2 (aucune transaction)

$ vault-cli ardoise-bon 4000000
Bon signé hors chaîne : total dû 0.1 TKAS sur 0.2 (aucune transaction)

$ vault-cli ardoise-clore
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Ardoise close par le vendeur : 0.1 TKAS encaissés, le reste revient au propriétaire : https://tn10.kaspa.stream/transactions/a9a7e30b6c9cf175d16b1cec430798d68fb9744fe99e806bc3a534bdd9cb967c

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632802705
Solde du propriétaire : 989.82 TKAS (6 UTXO)
Coffre (cœur v0.6) kaspatest:ppunu6a5274nn79m3rrg0ysvqmvf69zd3p9dxnuwla5lgxll44h5cfzmcqdp2 : 4.785 TKAS en 4 pièce(s)
  disponible maintenant : 0.64662497 TKAS ; pire cas sur 24 h : 4.785 TKAS
  perte nette depuis la création : 0.215 TKAS (courbe promise : 0.86255552 TKAS)

$ vault-cli recuperer
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
4 pièce(s) rapatriée(s) : 4.665 TKAS, https://tn10.kaspa.stream/transactions/ab9e4bcdc9e2c84201c393278cdc141503301110caff14e220a92dd1e43b2b3a

$ vault-cli etat
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 632802967
Solde du propriétaire : 994.485 TKAS (7 UTXO)
Coffre : pas encore déployé

```

## 2026-11-26 05:13 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (29700000 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-26T05:00:41.067Z","trigger":"scheduled","ok":false,"checks":[{"name":"kaspa-chain","status":"failed","detail":"invalid_transaction_state"},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":{"status":200}},{"name":"current-release","status":"ok","detail":"current 1.0.1 release metadata resolved","evidence":{"status":200}},{
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Transaction de paiement signée 2026-11-26T05:13:53.338Z : tentative 34b06685811c5355f95f20c571dcef349d04d444792b66f2288f11e24fc8084b, transaction df9bd0b0ff7a5b257a7d7ec5c19710aecfd51e7351d50d2a2060d56034b21f16, entrées b137fd8ecbd66b00e6df107876bf6e0385e00bc0521ae681a98e5f9ebbf45f93:1
Réponse à la tentative payée : HTTP 200 (2026-11-26T05:14:10.434Z)
  content-type: application/json; charset=utf-8
  payment-response: eyJhbW91bnQiOiIyMDAwMDAwMCIsImV4dGVuc2lvbnMiOnsia2FzcGEiOnsiZXhhY3RQcm9maWxlIjoic3RhbmRhcmQtbmF0aXZlIiwiZmluYWxpdHkiOiJhY2NlcHRlZCIsInBheW1lbnRPdXRwdXRJbmRleCI6MCwicmVxdWVzdEhhc2giOiI2M2ZhNjUzMmJmNTEzODQ3YTFjNTg0NjMyYTdhM2IzNWVlNDQ0MTM4ZWQ5NDRmNzdkYTA4NGQ3YTk1YTIwZTBmIiwidHJhbnNhY3Rpb25FbmNvZGluZyI6
  corps : {"ok":true,"network":"kaspa:testnet-10","profile":"exact","resource":"https://demo.kaspa-x402.org/exact","requestFingerprint":"63fa6532bf513847a1c584632a7a3b35ee444138ed944f77da084d7a95a20e0f","paymentIdentifier":"lamaz_relais_testnet_1795670030842","payment":{"scheme":"exact","transactionId":"df9bd0b0ff7a5b257a7d7ec5c19710aecfd51e7351d50d2a2060d56034b21f16","paymentOutputIndex":0,"finality":"accepted"}}
Réponse du vendeur : HTTP 200
Corps : {"ok":true,"network":"kaspa:testnet-10","profile":"exact","resource":"https://demo.kaspa-x402.org/exact","requestFingerprint":"63fa6532bf513847a1c584632a7a3b35ee444138ed944f77da084d7a95a20e0f","paymentIdentifier":"lamaz_relais_testnet_1795670030842","payment":{"scheme":"exact","transactionId":"df9bd0b0ff7a5b257a7d7ec5c19710aecfd51e7351d50d2a2060d56034b21f16","paymentOutputIndex":0,"finality":"acce
Règlement : success=true, transaction df9bd0b0ff7a5b257a7d7ec5c19710aecfd51e7351d50d2a2060d56034b21f16, montant 20000000 sompi, réseau kaspa:testnet-10
  https://tn10.kaspa.stream/transactions/df9bd0b0ff7a5b257a7d7ec5c19710aecfd51e7351d50d2a2060d56034b21f16
VERDICT : le vendeur public Kaspa x402 a accepté et réglé le paiement du coffre.

```

## 2026-11-26 07:58 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.6) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:ppunu6a5274nn79m3rrg0ysvqmvf69zd3p9dxnuwla5lgxll44h5cfzmcqdp2
Transaction : https://tn10.kaspa.stream/transactions/8b8cc5cbd2a4c7c303fb5c6e29b186442fe1f561c8c1ec7075917cdaca351b48

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli etat
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633441401
Solde du propriétaire : 989.455 TKAS (6 UTXO)
Coffre (cœur v0.6) kaspatest:ppunu6a5274nn79m3rrg0ysvqmvf69zd3p9dxnuwla5lgxll44h5cfzmcqdp2 : 5 TKAS en 4 pièce(s)
  disponible maintenant : 0.00883332 TKAS ; pire cas sur 24 h : 5 TKAS
  perte nette depuis la création : 0 TKAS (courbe promise : 0.0095 TKAS)

$ vault-cli recharger 100000000
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre rechargé de 1 TKAS (pièce existante regonflée, rythme inchangé) : https://tn10.kaspa.stream/transactions/0cb18be31f3183a46cc85d3ad749b0036da6b1f8e1e576f1f101b9c078db81b9

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633441810
Solde du propriétaire : 988.395 TKAS (4 UTXO)
Coffre (cœur v0.6) kaspatest:ppunu6a5274nn79m3rrg0ysvqmvf69zd3p9dxnuwla5lgxll44h5cfzmcqdp2 : 6 TKAS en 4 pièce(s)
  disponible maintenant : 0.02572221 TKAS ; pire cas sur 24 h : 6 TKAS
  perte nette depuis la création : 0 TKAS (courbe promise : 0.03459719 TKAS)

$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
4 pièce(s) rapatriée(s) : 5.88 TKAS, https://tn10.kaspa.stream/transactions/f326e39018c2ec940f66b5090ac5c477944a1135a8699833003214b560b964f5

$ vault-cli etat
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633442148
Solde du propriétaire : 994.275 TKAS (5 UTXO)
Coffre : pas encore déployé

```

## 2026-11-26 13:18 UTC

```
$ vault-cli deployer kaspatest:qzznh6lxw7ryl5h9d9efe5e8ahrq8003ej2vc5swqednec49z8gpyk89quv6f
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.7) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:pr4zc7wyw46832lu3jda7up9xl97jgjjnatvz7helt8w5p6h37xzuvn8k3yh0
Adresse de retour (gel, retrait) : kaspatest:qzznh6lxw7ryl5h9d9efe5e8ahrq8003ej2vc5swqednec49z8gpyk89quv6f
Transaction : https://tn10.kaspa.stream/transactions/1e2e19bb37578f111918a38dfaabd0b725fe0aee52350bb849d247ff003efced

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli etat
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633633800
Solde du propriétaire : 989.245 TKAS (4 UTXO)
Coffre (cœur v0.6) kaspatest:pr4zc7wyw46832lu3jda7up9xl97jgjjnatvz7helt8w5p6h37xzuvn8k3yh0 : 5 TKAS en 4 pièce(s)
  disponible maintenant : 0.00827776 TKAS ; pire cas sur 24 h : 5 TKAS
  perte nette depuis la création : 0 TKAS (courbe promise : 0.00983332 TKAS)

$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
4 pièce(s) rapatriée(s) vers kaspatest:qzznh6lxw7ryl5h9d9efe5e8ahrq8003ej2vc5swqednec49z8gpyk89quv6f : 4.98358 TKAS, https://tn10.kaspa.stream/transactions/ec404c9f8ccedfd42c97c4e7d1e636473fbd89421ed86ccf0507e1eb105d2d22

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633634136
Solde du propriétaire : 989.245 TKAS (4 UTXO)
Coffre : pas encore déployé

```

## 2026-11-26 14:18 UTC

```
$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.7) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90
Adresse de retour (gel, retrait) : kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz
Transaction : https://tn10.kaspa.stream/transactions/647815cc7525d25c297e0f2134c3addfc206cfa7e5a8e57a3bc98d32b9a9e411

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli course-recharge
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 2/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
(attente d'une pièce prête : 270 s)
(attente d'une pièce prête : 241 s)
(attente d'une pièce prête : 209 s)
(attente d'une pièce prête : 175 s)
(attente d'une pièce prête : 141 s)
(attente d'une pièce prête : 106 s)
(attente d'une pièce prête : 77 s)
(attente d'une pièce prête : 46 s)
(attente d'une pièce prête : 15 s)
Course : paiement de l'agent (0.03 TKAS) contre rechargement de 1 TKAS, même pièce
Connecté au testnet-10 : wss://quark-10.kaspa.red/kaspa/testnet-10/wrpc/borsh
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
  paiement : refusé par le nœud (RPC Server (remote error) -> Rejected transaction 890fb9ebd627f32b2a870eaa4fd4b658bcc813c6d638acf24bcf92b772273625: output (647815cc7525d25c297e0f2134c3addfc206cfa7e5a8e57a3bc98d32b9a9e411, 1) already spent by transaction 74883ce62f64c28356c8b88e21308550d84951c8dddc4bdb736f29247db7c2c8 in the mempool)
  rechargement : accepté par le nœud (https://tn10.kaspa.stream/transactions/74883ce62f64c28356c8b88e21308550d84951c8dddc4bdb736f29247db7c2c8)
  gagnant inscrit : le rechargement
[OK] course paiement/rechargement : nombre de pièces 4 → 4 (rythme inchangé), argent du propriétaire versé au coffre (rechargement gagnant)

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633673733
Solde du propriétaire : 983.2 TKAS (4 UTXO)
Coffre (cœur v0.7) kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90 : 6 TKAS en 4 pièce(s)
  disponible maintenant : 0.18318053 TKAS ; pire cas sur 24 h : 6 TKAS
  perte nette depuis la création : 0 TKAS (courbe promise : 0.23527775 TKAS)

$ vault-cli course-gel
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 2/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Course : paiement de l'agent (0.03 TKAS) contre gel du propriétaire, même pièce (1.25 TKAS)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
  paiement : accepté par le nœud (https://tn10.kaspa.stream/transactions/6bafe112b406a3807952d6615759539a8179d1e09dac975344079d579419c370)
  gel : accepté par le nœud (https://tn10.kaspa.stream/transactions/e2f9e66820c5db53893c15032a061f94afdc258c009abc730b4133c107aa7d02)
  gagnant inscrit : le gel
  gel terminé : coffre déjà vide
[OK] course paiement/gel : coffre vide après gel (oui), paiement sous le plafond par achat (oui)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633674568
Solde du propriétaire : 989.18358 TKAS (8 UTXO)
Coffre (cœur v0.7) kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90 : 0 TKAS en 0 pièce(s)
  disponible maintenant : 0 TKAS ; pire cas sur 24 h : 0 TKAS
  perte nette depuis la création : 6 TKAS (courbe promise : 0.293125 TKAS)

```

## 2026-11-26 14:30 UTC

```
$ vault-cli deployer
Error: "un coffre est déjà déployé"
(code de sortie 1)

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli course-recharge
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli course-recharge
Connecté au testnet-10 : wss://quark-10.kaspa.red/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli course-recharge
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli course-gel
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633677211
Solde du propriétaire : 989.18358 TKAS (8 UTXO)
Coffre (cœur v0.7) kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90 : 0 TKAS en 0 pièce(s)
  disponible maintenant : 0 TKAS ; pire cas sur 24 h : 0 TKAS
  perte nette depuis la création : 6 TKAS (courbe promise : 0.476875 TKAS)

$ vault-cli deployer
Error: "un coffre est déjà déployé"
(code de sortie 1)

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli course-gel
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli course-gel
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Error: "aucune pièce du coffre ne couvre le paiement d'essai"
(code de sortie 1)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633677635
Solde du propriétaire : 989.18358 TKAS (8 UTXO)
Coffre (cœur v0.7) kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90 : 0 TKAS en 0 pièce(s)
  disponible maintenant : 0 TKAS ; pire cas sur 24 h : 0 TKAS
  perte nette depuis la création : 6 TKAS (courbe promise : 0.50618055 TKAS)

```

## 2026-11-26 14:33 UTC

```
$ vault-cli recuperer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Error: "coffre déjà vide"
(code de sortie 1)

$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.7) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90
Adresse de retour (gel, retrait) : kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz
Transaction : https://tn10.kaspa.stream/transactions/277201686d801d9ab696fb21971d49fd2f43cb509c839330d55220ccd1bb4b90

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli course-recharge
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
(attente d'une pièce prête : 284 s)
(attente d'une pièce prête : 254 s)
(attente d'une pièce prête : 226 s)
(attente d'une pièce prête : 194 s)
(attente d'une pièce prête : 161 s)
(attente d'une pièce prête : 127 s)
(attente d'une pièce prête : 95 s)
(attente d'une pièce prête : 60 s)
(attente d'une pièce prête : 28 s)
Course : paiement de l'agent (0.03 TKAS) contre rechargement de 1 TKAS, même pièce
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
  paiement : accepté par le nœud (https://tn10.kaspa.stream/transactions/2e525dec2f673fe71cbbb01aefe12455351cff07191880901d6c3602566859f4)
  rechargement : refusé par le nœud (RPC Server (remote error) -> Rejected transaction 3b7c16d5572089a5d0a5928e9f56db93bb08b248e49ee4a1345ea63598af9f2d: output (277201686d801d9ab696fb21971d49fd2f43cb509c839330d55220ccd1bb4b90, 0) already spent by transaction 2e525dec2f673fe71cbbb01aefe12455351cff07191880901d6c3602566859f4 in the mempool)
  gagnant inscrit : le paiement
[OK] course paiement/rechargement : nombre de pièces 4 → 4 (rythme inchangé), argent du propriétaire intact

$ vault-cli course-recharge
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Course : paiement de l'agent (0.03 TKAS) contre rechargement de 1 TKAS, même pièce
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
  paiement : accepté par le nœud (https://tn10.kaspa.stream/transactions/aa476ceb800df1e8459549cd2ab5427da22eee81f93d4463a31c9746f48e2be8)
  rechargement : accepté par le nœud (https://tn10.kaspa.stream/transactions/9af2eab38924fa9c75a448a939b9321863de6bac1326f4598ba69a21b8b8c009)
  gagnant inscrit : le rechargement
[OK] course paiement/rechargement : nombre de pièces 4 → 4 (rythme inchangé), argent du propriétaire versé au coffre (rechargement gagnant)

$ vault-cli course-recharge
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Course : paiement de l'agent (0.03 TKAS) contre rechargement de 1 TKAS, même pièce
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
  paiement : accepté par le nœud (https://tn10.kaspa.stream/transactions/9fa5345b7c1c632b2043134a0c545d159036705569ddd9b8b7b68bd90855722b)
  rechargement : refusé par le nœud (RPC Server (remote error) -> Rejected transaction 0f332d31e388c78c569271ce77821a07bae8517a2876ad753fd0fefa6d5fe465: output (277201686d801d9ab696fb21971d49fd2f43cb509c839330d55220ccd1bb4b90, 3) already spent by transaction 9fa5345b7c1c632b2043134a0c545d159036705569ddd9b8b7b68bd90855722b in the mempool)
  gagnant inscrit : le paiement
[OK] course paiement/rechargement : nombre de pièces 4 → 4 (rythme inchangé), argent du propriétaire intact

$ vault-cli course-gel
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Course : paiement de l'agent (0.03 TKAS) contre gel du propriétaire, même pièce (1.25 TKAS)
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
(nœud injoignable, essai 2/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
  paiement : refusé par le nœud (RPC Server (remote error) -> Rejected transaction 19ab23517b51c6baa90b789c12b1ef1fbc4292ce9ab5017d3ac6ac46462527a1: output (277201686d801d9ab696fb21971d49fd2f43cb509c839330d55220ccd1bb4b90, 2) already spent by transaction cd6880090d3f445851d736a66881954a549537faf50fcab9f8d80a64ff8473c8 in the mempool)
  gel : accepté par le nœud (https://tn10.kaspa.stream/transactions/cd6880090d3f445851d736a66881954a549537faf50fcab9f8d80a64ff8473c8)
  gagnant inscrit : le gel
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
  gel terminé : coffre déjà vide
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
[OK] course paiement/gel : coffre vide après gel (oui), paiement sous le plafond par achat (oui)

$ vault-cli etat
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633684537
Solde du propriétaire : 988.97216 TKAS (8 UTXO)
Coffre : pas encore déployé

$ vault-cli deployer
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Coffre créé (cœur v0.7) : 5 TKAS en 4 pièce(s) à l'adresse kaspatest:prexx2zf6yf6syp8hgcxrf3fzn9ygd3h6qc0nlpkgkt6c5re5mvpy6dr4gm90
Adresse de retour (gel, retrait) : kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz
Transaction : https://tn10.kaspa.stream/transactions/c210eafc0e8129aafe12500f08542442aa60f5ada291e7cdd980c2022abdea62

$ vault-cli pause 15
(pause de 15 s)

$ vault-cli course-gel
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
(attente d'une pièce prête : 290 s)
(attente d'une pièce prête : 260 s)
(attente d'une pièce prête : 232 s)
(attente d'une pièce prête : 201 s)
(attente d'une pièce prête : 169 s)
(attente d'une pièce prête : 140 s)
(attente d'une pièce prête : 112 s)
(attente d'une pièce prête : 84 s)
(attente d'une pièce prête : 54 s)
(attente d'une pièce prête : 29 s)
Course : paiement de l'agent (0.03 TKAS) contre gel du propriétaire, même pièce (1.25 TKAS)
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
  paiement : accepté par le nœud (https://tn10.kaspa.stream/transactions/1a2c513d234d9ecc046ed4d613a1ef2df4c9856f6e975bee2c4c941098f73d1b)
  gel : refusé par le nœud (RPC Server (remote error) -> Rejected transaction 781836ab8e40bc6efb7d78100f5d1e1c3c5a32808141018fd841acb93f955f82: output (c210eafc0e8129aafe12500f08542442aa60f5ada291e7cdd980c2022abdea62, 3) already spent by transaction 1a2c513d234d9ecc046ed4d613a1ef2df4c9856f6e975bee2c4c941098f73d1b in the mempool)
  gagnant inscrit : le paiement
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://proton-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
4 pièce(s) rapatriée(s) vers kaspatest:qz9kvefaars6au3nt45ljcam67qm5a4hg4vvehwmqan736pft6st5lhhymxhz : 4.93858 TKAS, https://tn10.kaspa.stream/transactions/954b4b9e8a458b51dbae6f6dda66de237c84c840651b700a44d3147333eda638
  gel terminé : 954b4b9e8a458b51dbae6f6dda66de237c84c840651b700a44d3147333eda638
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
[OK] course paiement/gel : coffre vide après gel (oui), paiement sous le plafond par achat (oui)

$ vault-cli etat
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Score DAA du réseau : 633688504
Solde du propriétaire : 988.88074 TKAS (11 UTXO)
Coffre : pas encore déployé

```

## 2026-11-26 17:10 UTC

```
$ node tests/juge-kaspa-x402/essai-testnet.mjs
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Porte-monnaie du relais : kaspatest:qz3mjp07l8e09zrjzfwckrz0cupuu84ae70mqsu7sn6ujcnvawqwugghhl3s4 (9399999 sompi)
Diagnostic /health : HTTP 200
  {"ok":true,"enabled":true,"gateway":"kaspa-x402-testnet","releaseVersion":"1.0.1","hostedExactSettlementEnabled":true,"exactProfile":"standard-native","chainBroadcastMode":"pnn","chainEvidenceSource":"pnn","chainTrustMode":"trusted-single-source","chainEvidenceAuthorities":1}
Diagnostic /canary : HTTP 200
  {"ok":true,"enabled":true,"exactHeads":{"total":0,"available":0,"claimed":0,"unavailable":0,"retired":0},"canary":{"checkedAt":"2026-11-26T17:00:54.943Z","trigger":"scheduled","ok":false,"checks":[{"name":"kaspa-chain","status":"ok","detail":"PNN chain health returned testnet-10 evidence","evidence":{"ok":true,"networkId":"testnet-10","endpoint":"wss://vector-10.kaspa.green","virtualDaaScore":"633766851"}},{"name":"schema-url","status":"ok","detail":"payment-required schema resolved","evidence":
Diagnostic /exact : HTTP 402 (offre 402 : {"accepts":[{"amount":"20000000","asset":"KAS","extra":{"binding":"kaspa-exact-v2","finality":"accepted","payToScriptPublicKey":"000020bee817fbf708b7ad2b12530bcc99e285805ab64faeea22f6d31e2bbcb164edf9ac","paymentFlow":"upfront","profile":"standard-native","transactionEncoding":"kaspa-sdk-safe-json-v2)
GET https://demo.kaspa-x402.org/exact
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
Connecté au testnet-10 : wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh
(nœud injoignable, essai 1/3 : réseau de test injoignable (aucun nœud n'a répondu en 20 s) : vérifiez votre connexion, ou indiquez un nœud avec NOEUD_WRPC ; nouvel essai)
Connecté au testnet-10 : wss://alpha-10.kaspa.stream/kaspa/testnet-10/wrpc/borsh
Error: "refusé localement : aucune pièce du coffre ne couvre ce montant (coffre vide ou gelé)"
Échec : vault-cli recharger-porte-monnaie : Error: "refusé localement : aucune pièce du coffre ne couvre ce montant (coffre vide ou gelé)"
VERDICT : ÉCHEC
(code de sortie 1)

```

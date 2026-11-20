
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

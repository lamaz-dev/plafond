
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

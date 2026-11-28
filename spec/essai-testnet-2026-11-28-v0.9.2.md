# Essai du cœur v0.9.2 et du sas v0.2.1 sur testnet-10, 28 novembre 2026

Exécuté par GitHub Actions (`testnet.yml`, commande `essai-lignee`, commit `ce8bf3e`) avec les clés
de test du dépôt. Journal brut : `testnet/journal.md`, entrée du 28 nov. 2026, 02:06 UTC.
Code de l'essai : `cli/src/essai_lignee.rs`. Chaque transaction est envoyée telle quelle au nœud,
sans contrôle local : c'est le réseau qui accepte ou refuse.

Réglages de l'essai : 0,5 TKAS par paiement, période de 600 unités DAA (une minute), deux pièces de
3 TKAS. Lignée du coffre : `3760fcd7a9ca149a376627ef90a3e0a2ff2be9b1dbf19d6a23d1f18839cc130d`.

| # | Étape | Résultat | Preuve sur le registre public |
|---|---|---|---|
| 1 | Création : genèse à deux pièces ; les deux pièces relues portent la lignée | ✅ | [4118270b…](https://tn10.kaspa.stream/transactions/4118270b7e00e6ac2aa12343203b1b35506cb34d21dd282e4fc93fc6b0320ea1) |
| 2 | Adresse du sas recalculée depuis la genèse ; dépôt ordinaire de 2 TKAS | ✅ | [69191e28…](https://tn10.kaspa.stream/transactions/69191e28452b7f0f120287f82c9e9c45e2529f34d0f32ead490bd0072646a752) |
| 3 | Versement **sans aucune signature** du dépôt dans la pièce 0 ; la pièce regonflée garde la lignée | ✅ accepté et relayé | [abcb253c…](https://tn10.kaspa.stream/transactions/abcb253cb03284a54371f68e8834ab88025dbc8157eaedf48c166076c69d1851) |
| 4a | Paiement de l'agent trop tôt (pièce qui vient d'être regonflée) | ✅ **refusé par le réseau** (« sequence locks conditions was not met ») | rejetée `bf31cd79…` |
| 4b | Paiement de l'agent à l'heure : 0,2 TKAS au vendeur, le reste garde la lignée | ✅ | [cccc2dd7…](https://tn10.kaspa.stream/transactions/cccc2dd7b9215de4357c3eea3e018f299fa47ae2f3661829925e2f4124ecdb42) |
| 5a | Retrait partiel dont les frais vont plus vite que le rythme (pièce trop jeune) | ✅ **refusé par le réseau** (verrou relatif) | rejetée `a401eb4b…` |
| 5b | Retrait partiel : 1 TKAS vers l'adresse de retour (pièce ordinaire), le reste garde la lignée | ✅ | [2ad150d7…](https://tn10.kaspa.stream/transactions/2ad150d7e48bf051899c355bf029b83d06fbba19b8fea1d9c12bd84e2803feb9) |
| 6a | **S3 réel** : poussière de 0,2 TKAS à l'adresse du coffre, second dépôt au sas, dépôt versé dans la poussière (sortie sans lignée) | ✅ **refusé** (« 0 is not a valid covenant output index for input 0 with 0 authorized outputs ») | poussière [1776ca7d…](https://tn10.kaspa.stream/transactions/1776ca7db4997da51e5d90ab4c840a1d77cbfac8291daf018abda78d86349902), dépôt [181cd53a…](https://tn10.kaspa.stream/transactions/181cd53a0732767461b0cdc72971afdfa96538ae3f0eef50d7f27a3b9043a15a), rejetée `2123deb6…` |
| 6b | S3 : idem, sortie déclarée dans la lignée du coffre | ✅ **refusé** (« do not correspond to the expected genesis hashing ») | rejetée `dcf32922…` |
| 6c | S3 : idem, poussière adoptée par une lignée neuve | ✅ **refusé** | rejetée `0fde06be…` |
| 6d | L'agent paie avec la poussière (sans lignée, puis en déclarant la lignée du coffre) | ✅ **refusé** deux fois | rejetées `d61730cf…`, `0c99ba0b…` |
| 6e | **W10 réel** : gel dont la pièce de retour naît marquée d'une lignée neuve | ✅ **refusé** (« script ran, but verification failed ») | rejetée `774cd13b…` |
| 7 | Fermeture : 2 pièces de la lignée, la poussière et le dépôt en attente, dans la même transaction ; plus rien au coffre ni au sas ; 5 pièces ordinaires à l'adresse de retour | ✅ | [4d0a1a9d…](https://tn10.kaspa.stream/transactions/4d0a1a9d0eb64557a84772405d9f3bfdfc04b23319615bdb9f06714a4eea94b6) |

Fonds de test rendus au propriétaire de test :
[d485725f…](https://tn10.kaspa.stream/transactions/d485725fcf23a1b885674110f7d4ad77ad66abf9c979499ce1fb7900254c7edb).

## Mesures

| Transaction | Masse calcul | Masse transitoire | Masse stockage | Frais payés |
|---|---|---|---|---|
| Versement sans clé (2 entrées, 1 sortie) | 1 883 g | 4 452 g | 0 g | 222 600 sompi (le minimum) |
| Paiement de l'agent | 2 835 g | 3 620 g | 51 149 g | 3 777 075 sompi |
| Retrait partiel | 2 835 g | 3 620 g | 12 026 g | 903 075 sompi |
| Fermeture (4 entrées) | 8 950 g | 10 840 g | 22 130 g | 1 877 176 sompi |

**Prix minimal du relais.** Le versement a été essayé à 1, 2, 5, 10 et 20 sompi par gramme : refusé
à chaque fois, avec le même message : « transaction has … fees which is under the required amount of
222600 for normalized transient mass 2226 ». Accepté à 222 600 sompi. Le nœud exige donc 100 sompi
par gramme de masse transitoire normalisée (la moitié de la masse transitoire sur ce réseau), ou de
masse de calcul si elle est plus grande. `masse::frais_relais` reproduit ce calcul.

Pour les transactions signées (paiement, retrait, fermeture), l'essai a payé au prix de la plus
grande masse, stockage compris : c'est plus que le minimum, qui n'a pas été cherché pour elles.

**Transactions sans signature.** Le versement (`absorb` + `recharger`) ne contient aucune signature.
Le nœud public l'a accepté par l'appel ordinaire de diffusion et elle a été inscrite dans un bloc
(la pièce regonflée a été relue avec son score d'inscription). Aucune règle de relais particulière
n'a été rencontrée.

**Attente du retrait partiel.** Avec 903 075 sompi de frais et ces réglages : 11 unités DAA.

**`maxFrais` du sas.** Fixé à 1 000 000 sompi (0,01 KAS) par défaut ; justification dans
`spec/red-team/coeur-v0.9.2-2026-11-28.md`.

## Ce que l'essai ne montre pas

- Le prix au gramme sur le réseau principal.
- Le comportement sous forte charge (file d'attente, frais en hausse).
- Les formes d'attaque non rejouées ici (elles le sont sur le banc local : 103 attaques).
- La taille du script dépend des réglages (544 octets ici, 550 avec les paramètres de référence).

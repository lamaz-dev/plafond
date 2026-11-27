# Cœur v0.6 : le bytecode compilé, opcode par opcode

> **v0.7 (26 nov. 2026).** Le cœur actuel ajoute l'adresse de retour (spec/borne-de-perte-v0.6.md §7) :
> 289 octets avec les paramètres de référence (+78 : l'empreinte de 32 octets et la règle de
> `ownerControl`), empreinte `b85e0c9d…` dans `contracts/EMPREINTES.txt`. Le chemin `pay`, analysé
> ci-dessous, est inchangé ; coût mesuré : 11 unités de calcul pour `pay` comme pour `ownerControl`.
> La lecture ci-dessous reste celle de la v0.6 (`contracts/archive/coeur-v0.6.sil`).

> **v0.8 (27 nov. 2026).** `contracts/coeur.sil` ajoute l'entrée sans clé `absorb` (preuve §8) :
> 333 octets avec les paramètres de référence (+44), empreinte `849d197b…`. Les entrées `pay` et
> `ownerControl` ont le même source que la v0.7 ; coût mesuré de `absorb` : 1 unité de calcul (aucune
> signature). Le sas (`contracts/sas.sil`) fait 190 octets, empreinte `5e7e5292…`. L'outil déploie
> toujours la v0.7 (`contracts/archive/coeur-v0.7.sil`, empreinte `b85e0c9d…` inchangée).

Compilateur SilverScript figé à `7eb04634` (v1.0.2 ; bytecode identique octet pour octet à `443d519e`, vérifié le 26 nov. 2026), paramètres de référence :
- propriétaire et agent : clés de test 1 et 2 ;
- capacité 200 000 000 sompi (2 TKAS) ;
- période 864 000 (un jour).

Résultat : **211 octets**, empreinte blake2b `6057a023…` (`contracts/EMPREINTES.txt`).

Reproduire :

```
cd cli && PLAFOND_EXPORT_BYTECODE=/tmp/coeur.hex cargo test --release coeur::bytecode
python3 ../tools/desassembler.py /tmp/coeur.hex
```

La table des opcodes (`tools/opcodes-kaspa-txscript-2.1.0.txt`) est extraite de `kaspa-txscript`
2.1.0, `src/opcodes/mod.rs`.

## Lecture commentée

| Octets | Opcodes | Ligne du source |
|---|---|---|
| 0–7 | `OpDup <6d66d856> OpEqual OpIf` | sélecteur d'entrée : `pay` |
| 8–14 | `OpDrop OpDup OpSize <65> OpNumEqualVerify OpDrop` | la signature fait exactement 65 octets (64 + type de hachage) |
| 15–50 | `OpDup <clé agent> OpCheckSig OpVerify` | `checkSig(agentSig, agentKey)` |
| 51–61 | `<864000> <2^32> OpLessThan` | `period < 4294967296` |
| 62–83 | `<C> <MAX> <R> OpDiv OpLessThanOrEqual OpBoolAnd OpVerify` | `capacity <= MAX / period` |
| 84–91 | `OpTxInputCount 1 OpNumEqual OpTxOutputCount 2 OpNumEqual OpBoolAnd OpVerify` | une entrée, deux sorties |
| 92–98 | `OpTxInputIndex OpTxInputSpk 1 OpTxOutputSpk OpOver OpEqual OpVerify` | sortie 1 = mon script |
| 99–104 | `0 OpTxOutputSpk OpOver OpEqual OpNot OpVerify` | sortie 0 ≠ mon script |
| 105–117 | `OpTxInputIndex OpTxInputAmount 1 OpTxOutputAmount OpSub OpDup <C> OpLessThanOrEqual OpVerify` | `spent = entrée − sortie 1`, `spent <= capacity` |
| 118–137 | `OpDup <R> OpMul <C> OpAdd 1 OpSub <C> OpDiv` | délai `(spent·R + C − 1) / C` |
| **138–147** | **`OpDup 0 <2^32> OpWithin OpVerify`** | **ajouté par le compilateur** : délai dans [0, 2^32) |
| 148 | `OpCheckSequenceVerify` | `this.ageDaa >= délai` |
| 149–152 | `OpDrop ×3, 1` | nettoyage de la pile, succès |
| 153–206 | `OpElse … <c9cea155> … OpCheckSig OpVerify …` | entrée `ownerControl` : signature du propriétaire |
| 207–210 | `OpElse OpReturn OpEndIf OpEndIf` | toute autre entrée échoue |

## Constats

1. **Le compilateur garde lui-même le verrou relatif.** Avant `OpCheckSequenceVerify`, il vérifie
   que le délai est compris dans [0, 2^32). Un délai trop grand fait échouer le script ; il n'est
   jamais tronqué à 32 bits.
   - **Conséquence :** notre garde `period < 2^32` n'est pas porteuse, contrairement à ce qu'écrivait
     la preuve v0.6 (§5). Elle double celle du compilateur et reste dans le contrat par prudence. Le
     test `delai_tronque_a_32_bits_impossible` passerait aussi sans elle.
   - **Confirmé par la séance Red Team du 26 nov. 2026 :** oui, pour toute utilisation de
     `this.ageDaa`. La grammaire n'admet `this.ageDaa` que sous la forme
     `require(this.ageDaa >= expression)` (`silverscript.pest`, règle `lock_requirement_statement`),
     et le compilateur n'émet `OpCheckSequenceVerify` qu'à un seul endroit
     (`compile_require_age_daa_statement`), toujours précédé de `OpDup 0 <2^32> OpWithin OpVerify`.
     Test : `coeur::tests::compilateur_garde_toujours_le_verrou_relatif`. Détail :
     `spec/red-team/rapport-2026-11-26.md`, §2.
   - **Ordre du calcul (R59).** Le délai est calculé dans l'ordre `spent × R`, `+ C`, `− 1`, `/ C`.
     Le moteur refuse tout dépassement des 64 bits signés, même intermédiaire : si `C × R + C`
     dépasse 2^63 − 1, un paiement proche de la capacité est refusé par le réseau. Sans danger pour
     les fonds ; l'outil refuse désormais ces réglages (`Coeur::verifier`).
2. **Rien d'autre que le source.** Chaque opcode correspond à une ligne du contrat. Les constantes
   sont inscrites telles quelles : C, R et MAX. Le calcul `MAX / period` se fait à l'exécution ; il
   pourrait être fait à la compilation, pour environ 9 octets de moins (piste d'allègement, sans
   effet sur la sécurité).
3. **Entrée inconnue = échec** (`OpReturn`) : aucun chemin d'exécution par défaut.
4. **Signature de taille fixe (65 octets).** Une signature sans type de hachage, ou avec un type
   différent du format attendu, échoue avant `OpCheckSig`.

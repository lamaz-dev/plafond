#!/usr/bin/env python3
"""Désassemble un script Kaspa (hex) avec la table d'opcodes de kaspa-txscript 2.1.0.

Usage : python3 tools/desassembler.py <fichier.hex>
Le bytecode du cœur s'exporte avec :
  PLAFOND_EXPORT_BYTECODE=/tmp/coeur.hex cargo test --release coeur::bytecode
"""
import sys, pathlib
table = {}
for ligne in (pathlib.Path(__file__).parent / "opcodes-kaspa-txscript-2.1.0.txt").read_text().splitlines():
    code, nom = ligne.split()
    table[int(code, 16)] = nom
# Nombres poussés par un seul opcode (absents de la table extraite) : 0x00 = 0, 0x51..0x60 = 1..16.
table[0x00] = "Op0 (pousse 0)"
for n in range(1, 17):
    table[0x50 + n] = f"Op{n} (pousse {n})"
b = bytes.fromhex(pathlib.Path(sys.argv[1]).read_text().strip())
i = 0
while i < len(b):
    op = b[i]; nom = table.get(op, f"?{op:02x}")
    if 1 <= op <= 0x4b:  # OpData1..OpData75 : pousse op octets
        donnee = b[i + 1:i + 1 + op]
        print(f"{i:4d}  {op:02x}  push {op:2d} : {donnee.hex()}" + (f"  (= {int.from_bytes(donnee, 'little', signed=False)} si nombre)" if op <= 8 else ""))
        i += 1 + op; continue
    if op in (0x4c, 0x4d, 0x4e):  # OpPushData1/2/4
        n_len = {0x4c: 1, 0x4d: 2, 0x4e: 4}[op]
        n = int.from_bytes(b[i + 1:i + 1 + n_len], "little")
        print(f"{i:4d}  {op:02x}  {nom} {n} : {b[i+1+n_len:i+1+n_len+n].hex()}")
        i += 1 + n_len + n; continue
    print(f"{i:4d}  {op:02x}  {nom}")
    i += 1

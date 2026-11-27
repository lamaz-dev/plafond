"""Démo testnet-10 de la passerelle d'entreprise : un agent paie, dépasse, puis l'administrateur l'arrête.

Prérequis : passerelle lancée avec "demo": true et "vendeur_demo": true (vendeur x402 local sur :8402).
    PASSERELLE_URL=http://127.0.0.1:8403 AGENT_CLE=plf_... ADMIN_CLE=plf_... python exemples/demo_passerelle.py

Le même client Python (VaultClient) sert pour le routeur et pour la passerelle : pour l'agent, rien ne change.
"""

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kaspa_vault import PaiementRefuse, VaultClient  # noqa: E402

URL = os.environ.get("PASSERELLE_URL", "http://127.0.0.1:8403")
VENDEUR = "http://127.0.0.1:8402"
vault = VaultClient(URL, os.environ["AGENT_CLE"])
ok = True


def titre(t):
    print(f"\n=== {t} ===")


def admin(methode, chemin, corps=None):
    req = urllib.request.Request(
        URL + chemin,
        data=json.dumps(corps).encode() if corps is not None else None,
        method=methode,
        headers={"Authorization": "Bearer " + os.environ["ADMIN_CLE"], "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


b = vault.budget()
print(f"Budget de l'agent : {b.disponible_kas} TKAS disponibles, {b.max_par_paiement_sompi / 1e8} TKAS max par paiement")

titre("1. L'agent achète une donnée (0,2 TKAS) à travers la passerelle")
try:
    r = vault.fetch(f"{VENDEUR}/meteo-kaspa", max_kas=0.5)
    print(f"Contenu : {r.contenu}")
    if r.paiement:
        print(f"Payé {r.paiement.montant_kas} TKAS depuis le coffre de l'agent : {r.paiement.explorateur}")
    else:
        ok = False
        print("ÉCHEC : aucun paiement")
except PaiementRefuse as e:
    ok = False
    print(f"ÉCHEC : achat refusé ({e.message})")

titre("2. Le vendeur demande 1 TKAS, au-dessus du plafond de l'agent")
try:
    vault.fetch(f"{VENDEUR}/rapport-premium")
    ok = False
    print("ÉCHEC : l'achat aurait dû être refusé")
except PaiementRefuse as e:
    print(f"Refusé avant tout paiement : {e.message}")

titre("3. Arrêt d'urgence par l'administrateur")
s, v = admin("POST", "/admin/arret", {"agent": "recherche"})
print(f"Arrêt : HTTP {s} {v}")
try:
    vault.fetch(f"{VENDEUR}/meteo-kaspa", max_kas=0.5)
    ok = False
    print("ÉCHEC : un agent arrêté a pu acheter")
except Exception as e:  # noqa: BLE001 - la passerelle répond 423
    print(f"Agent arrêté, achat refusé : {e}")
s, v = admin("POST", "/admin/reprise", {"agent": "recherche"})
print(f"Reprise : HTTP {s}")

titre("4. Journal d'audit chaîné")
s, v = admin("GET", "/admin/etat")
print(f"Tête du journal : {v.get('journal')}")

print("\nVERDICT : " + ("la passerelle a payé ce qui était permis, refusé le reste, et l'arrêt d'urgence a tenu." if ok else "ÉCHEC"))
sys.exit(0 if ok else 1)

"""Démo testnet-10 : un agent achète avec son coffre, puis tente de dépasser ses règles.

Prérequis : routeur lancé avec ROUTEUR_DEMO=1 et --avec-vendeur (vendeur x402 local sur :8402).
    ROUTEUR_URL=http://127.0.0.1:8403 ROUTEUR_CLE=... python exemples/demo_agent.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from kaspa_vault import PaiementRefuse, VaultClient  # noqa: E402

VENDEUR = "http://127.0.0.1:8402"
vault = VaultClient(os.environ.get("ROUTEUR_URL", "http://127.0.0.1:8403"), os.environ["ROUTEUR_CLE"])
ok = True


def titre(t):
    print(f"\n=== {t} ===")


b = vault.budget()
print(f"Budget de l'agent : {b.disponible_kas} TKAS disponibles, {b.max_par_paiement_sompi / 1e8} TKAS max par paiement")

titre("1. L'agent achète une donnée (0,2 TKAS)")
r = vault.fetch(f"{VENDEUR}/meteo-kaspa", max_kas=0.5)
print(f"Contenu : {r.contenu}")
if r.paiement:
    print(f"Payé {r.paiement.montant_kas} TKAS depuis le coffre : {r.paiement.explorateur}")
else:
    ok = False
    print("ÉCHEC : aucun paiement")

titre("2. Le vendeur demande 1 TKAS, au-dessus du plafond de 0,5")
try:
    vault.fetch(f"{VENDEUR}/rapport-premium")
    ok = False
    print("ÉCHEC : l'achat aurait dû être refusé")
except PaiementRefuse as e:
    print(f"Refusé avant tout paiement : {e.message}")

titre("3. Agent compromis : il contourne le logiciel et diffuse 1 TKAS directement")
v = vault.simuler_agent_compromis(1.0)
if v.get("accepte_par_le_reseau"):
    ok = False
    print(f"ÉCHEC : le réseau a accepté {v}")
else:
    print("Le réseau Kaspa REFUSE la transaction : elle viole le covenant du coffre.")
    print(f"Réponse du nœud : {v.get('raison_du_noeud', '')[:300]}")

b2 = vault.budget()
print(f"\nBudget restant : {b2.disponible_kas} TKAS")
print("VERDICT : " + ("le coffre a payé ce qui était permis et le réseau a bloqué le reste." if ok else "ÉCHEC"))
sys.exit(0 if ok else 1)

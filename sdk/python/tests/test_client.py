"""Tests du client contre un faux routeur local (aucun réseau, aucune dépendance)."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from kaspa_vault import ErreurCoffre, PaiementRefuse, VaultClient

CLE = "cle-de-test-0123456789abcdef0123456789"
RECU = []


class FauxRouteur(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _repondre(self, statut, corps):
        b = json.dumps(corps).encode()
        self.send_response(statut)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _autorise(self):
        return self.headers.get("Authorization") == f"Bearer {CLE}"

    def do_GET(self):
        if not self._autorise():
            return self._repondre(401, {"erreur": "clé d'API invalide"})
        if self.path == "/v1/coffre":
            return self._repondre(200, {"disponible_sompi": 150_000_000, "capacite_sompi": 200_000_000, "max_par_paiement_sompi": 50_000_000})
        self._repondre(404, {"erreur": "inconnu"})

    def do_POST(self):
        corps = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        RECU.append({"chemin": self.path, "corps": corps, "idem": self.headers.get("Idempotency-Key")})
        if not self._autorise():
            return self._repondre(401, {"erreur": "clé d'API invalide"})
        url = corps.get("url", "")
        if url.endswith("/meteo"):
            return self._repondre(200, {"statut_vendeur": 200, "contenu": "beau temps", "paiement": {"montant_sompi": 20_000_000, "transaction": "ab" * 32, "explorateur": "https://tn10.kaspa.stream/transactions/" + "ab" * 32}, "refus": None})
        if url.endswith("/gratuit"):
            return self._repondre(200, {"statut_vendeur": 200, "contenu": "libre", "paiement": None, "refus": None})
        if url.endswith("/cher"):
            return self._repondre(402, {"statut_vendeur": 402, "contenu": "", "paiement": None, "refus": "hors du budget du coffre"})
        if url.endswith("/rejoue"):
            return self._repondre(200, {"rejoue": True, "reponse": {"statut_vendeur": 200, "contenu": "déjà payé", "paiement": None}})
        if url.endswith("/interdit"):
            return self._repondre(403, {"erreur": "vendeur non autorisé"})
        self._repondre(404, {"erreur": "inconnu"})


class TestClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.serveur = HTTPServer(("127.0.0.1", 0), FauxRouteur)
        threading.Thread(target=cls.serveur.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.serveur.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.serveur.shutdown()

    def setUp(self):
        RECU.clear()
        self.vault = VaultClient(self.url, CLE)

    def test_achat_paye(self):
        r = self.vault.fetch("https://api.exemple.org/meteo", max_kas=0.5)
        self.assertEqual(r.contenu, "beau temps")
        self.assertEqual(r.paiement.montant_kas, 0.2)
        self.assertEqual(RECU[-1]["corps"]["max_sompi"], 50_000_000)
        self.assertTrue(RECU[-1]["idem"])  # clé d'idempotence toujours envoyée

    def test_ressource_gratuite(self):
        self.assertIsNone(self.vault.fetch("https://api.exemple.org/gratuit").paiement)

    def test_refus_leve_paiement_refuse(self):
        with self.assertRaises(PaiementRefuse) as e:
            self.vault.fetch("https://api.exemple.org/cher")
        self.assertIn("budget", e.exception.message)

    def test_reponse_rejouee(self):
        r = self.vault.fetch("https://api.exemple.org/rejoue", cle_idempotence="k1")
        self.assertTrue(r.rejouee)
        self.assertEqual(RECU[-1]["idem"], "k1")

    def test_politique_et_cle(self):
        with self.assertRaises(ErreurCoffre) as e:
            self.vault.fetch("https://api.exemple.org/interdit")
        self.assertEqual(e.exception.statut, 403)
        with self.assertRaises(ErreurCoffre) as e:
            VaultClient(self.url, "mauvaise").budget()
        self.assertEqual(e.exception.statut, 401)

    def test_budget(self):
        b = self.vault.budget()
        self.assertEqual(b.disponible_kas, 1.5)
        self.assertEqual(b.max_par_paiement_sompi, 50_000_000)

    def test_routeur_injoignable_et_cle_masquee(self):
        with self.assertRaises(ErreurCoffre) as e:
            VaultClient("http://127.0.0.1:9", CLE, delai=2).budget()
        self.assertEqual(e.exception.statut, 0)
        self.assertNotIn(CLE, repr(self.vault))

    def test_entrees_invalides(self):
        with self.assertRaises(ValueError):
            VaultClient("ftp://x", CLE)
        with self.assertRaises(ValueError):
            self.vault.fetch("https://api.exemple.org/meteo", max_kas=-1)


if __name__ == "__main__":
    unittest.main()

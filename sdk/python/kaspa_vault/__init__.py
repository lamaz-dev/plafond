"""Client Python du routeur kaspa-agent-vault.

Un agent achète une ressource payante (HTTP 402 / x402) avec une seule ligne :

    from kaspa_vault import VaultClient
    vault = VaultClient("http://127.0.0.1:8403", cle_api="...")
    reponse = vault.fetch("https://api.exemple.org/meteo")
    print(reponse.contenu, reponse.paiement)

Le routeur paie depuis un coffre AgentBudget sur Kaspa. Les limites (budget qui se recharge,
plafond par paiement) sont imposées par le réseau : même un agent ou un routeur compromis ne
peut pas les dépasser. Aucune dépendance hors bibliothèque standard.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Optional

__all__ = ["VaultClient", "Reponse", "Paiement", "Budget", "ErreurCoffre", "PaiementRefuse"]
__version__ = "0.1.0"

SOMPI_PAR_KAS = 100_000_000


class ErreurCoffre(Exception):
    """Erreur du routeur (clé invalide, vendeur non autorisé, réseau indisponible...)."""

    def __init__(self, statut: int, message: str):
        super().__init__(f"{statut} : {message}")
        self.statut = statut
        self.message = message


class PaiementRefuse(ErreurCoffre):
    """Le paiement a été refusé : hors budget, au-dessus du plafond, ou refusé par le vendeur."""


@dataclass(frozen=True)
class Paiement:
    montant_sompi: int
    transaction: str
    explorateur: str

    @property
    def montant_kas(self) -> float:
        return self.montant_sompi / SOMPI_PAR_KAS


@dataclass(frozen=True)
class Reponse:
    statut_vendeur: int
    contenu: str
    paiement: Optional[Paiement]
    rejouee: bool = False


@dataclass(frozen=True)
class Budget:
    disponible_sompi: int
    capacite_sompi: int
    max_par_paiement_sompi: int

    @property
    def disponible_kas(self) -> float:
        return self.disponible_sompi / SOMPI_PAR_KAS


def _kas_vers_sompi(kas: float) -> int:
    if kas < 0:
        raise ValueError("montant négatif")
    return int(round(kas * SOMPI_PAR_KAS))


class VaultClient:
    """Client du routeur. `cle_api` : la valeur de ROUTEUR_CLE (ne jamais la mettre dans le code)."""

    def __init__(self, url_routeur: str, cle_api: str, delai: float = 120.0):
        if not url_routeur.startswith(("http://", "https://")):
            raise ValueError("url_routeur doit commencer par http:// ou https://")
        self.url = url_routeur.rstrip("/")
        self._cle = cle_api
        self.delai = delai

    def __repr__(self) -> str:  # la clé n'apparaît jamais dans les journaux
        return f"VaultClient({self.url!r})"

    def _appel(self, methode: str, chemin: str, corps: Optional[dict] = None, entetes: Optional[dict] = None) -> tuple[int, Any]:
        donnees = None if corps is None else json.dumps(corps).encode()
        req = urllib.request.Request(self.url + chemin, data=donnees, method=methode)
        req.add_header("Authorization", f"Bearer {self._cle}")
        req.add_header("Content-Type", "application/json")
        for k, v in (entetes or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.delai) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {"erreur": e.reason}
        except urllib.error.URLError as e:
            raise ErreurCoffre(0, f"routeur injoignable : {e.reason}") from None

    def budget(self) -> Budget:
        """Budget disponible maintenant (garanti par le covenant)."""
        statut, v = self._appel("GET", "/v1/coffre")
        if statut != 200:
            raise ErreurCoffre(statut, v.get("erreur", "erreur inconnue"))
        return Budget(int(v["disponible_sompi"]), int(v["capacite_sompi"]), int(v["max_par_paiement_sompi"]))

    def fetch(self, url: str, max_kas: Optional[float] = None, cle_idempotence: Optional[str] = None) -> Reponse:
        """Achète `url`. Paie depuis le coffre si le vendeur répond 402, au plus `max_kas`.

        `cle_idempotence` : à fournir pour pouvoir relancer sans risque après une coupure
        (une même clé ne paie jamais deux fois). Générée automatiquement sinon.
        """
        corps: dict[str, Any] = {"url": url}
        if max_kas is not None:
            corps["max_sompi"] = _kas_vers_sompi(max_kas)
        cle = cle_idempotence or str(uuid.uuid4())
        statut, v = self._appel("POST", "/v1/fetch", corps, {"Idempotency-Key": cle})
        rejouee = bool(v.get("rejoue"))
        if rejouee:
            v = v.get("reponse", {})
        if statut == 402:
            raise PaiementRefuse(402, v.get("refus") or "paiement refusé")
        if statut != 200:
            raise ErreurCoffre(statut, v.get("erreur", "erreur inconnue"))
        p = v.get("paiement")
        paiement = Paiement(int(p["montant_sompi"]), p["transaction"], p["explorateur"]) if p else None
        return Reponse(int(v.get("statut_vendeur", 200)), v.get("contenu", ""), paiement, rejouee)

    def simuler_agent_compromis(self, montant_kas: float) -> dict:
        """Démo testnet seulement (routeur lancé avec ROUTEUR_DEMO=1) : diffuse un paiement SANS
        aucun contrôle local, pour montrer que le réseau Kaspa le refuse s'il viole le covenant."""
        statut, v = self._appel("POST", "/v1/demo/agent-compromis", {"montant_sompi": _kas_vers_sompi(montant_kas)})
        if statut != 200:
            raise ErreurCoffre(statut, v.get("erreur", "erreur inconnue"))
        return v

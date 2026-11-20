"""Outil LangChain : l'agent achète une ressource payante depuis son coffre.

    from kaspa_vault import VaultClient
    from kaspa_vault.langchain import outil_achat
    outils = [outil_achat(VaultClient(url, cle_api), max_kas=0.5)]

Nécessite `langchain-core` (importé seulement ici).
"""

from __future__ import annotations

from . import ErreurCoffre, PaiementRefuse, VaultClient


def outil_achat(vault: VaultClient, max_kas: float | None = None):
    try:
        from langchain_core.tools import tool
    except ImportError as e:  # pragma: no cover
        raise ImportError("pip install langchain-core") from e

    @tool("acheter_ressource")
    def acheter_ressource(url: str) -> str:
        """Récupère le contenu d'une URL payante (HTTP 402). Paie automatiquement depuis le coffre
        Kaspa de l'agent, dans la limite de son budget garanti par le réseau."""
        try:
            r = vault.fetch(url, max_kas=max_kas)
        except PaiementRefuse as e:
            return f"Achat refusé : {e.message}"
        except ErreurCoffre as e:
            return f"Erreur du coffre : {e.message}"
        recu = f" (payé {r.paiement.montant_kas} KAS, transaction {r.paiement.transaction})" if r.paiement else ""
        return r.contenu + recu

    return acheter_ressource

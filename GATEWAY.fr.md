# Passerelle Plafond

*[English](GATEWAY.md) · Français*

Un seul point de passage où tous les agents IA d'une organisation paient leurs API, chacun depuis son propre
coffre à covenant, derrière une adresse que l'équipe de sécurité surveille et peut arrêter.

La passerelle repose sur une règle : **une passerelle piratée ne doit pas coûter plus que ce que les coffres
permettent déjà.**

## Ce qu'elle garantit

| | |
|---|---|
| **Jamais la clé d'un propriétaire** | La passerelle ne charge que la clé de chaque agent et la clé *publique* de son propriétaire. Elle refuse de démarrer si une clé de propriétaire est présente dans son environnement. Si elle est piratée, la perte reste dans la limite du covenant de chaque coffre (`C × t / R`), et les fonds ne peuvent toujours revenir qu'à l'adresse de retour de chaque coffre. |
| **Aucune clé d'API stockée** | Le fichier de configuration ne garde que l'empreinte SHA-256 des clés. Une copie volée du fichier ne permet pas d'appeler la passerelle. Les clés sont comparées en temps constant. |
| **Arrêt d'urgence** | Une clé d'administration distincte arrête un agent ou tous, immédiatement. L'arrêt est écrit sur le disque et survit à un redémarrage. (C'est un arrêt local : la passerelle refuse de payer. Le gel d'un coffre sur la chaîne reste l'affaire de son propriétaire.) |
| **Journal d'audit chaîné** | Chaque ligne porte l'empreinte SHA-256 de la précédente. Une ligne modifiée, supprimée ou insérée casse la chaîne : la passerelle refuse de démarrer et `passerelle-verifier` désigne la ligne. La tête de chaîne est exposée pour être recopiée dans un SIEM : c'est ce qui empêche de réécrire tout le journal d'un coup. |
| **Rien payé sans trace** | La demande est journalisée *avant* le paiement. Si le journal ne peut pas être écrit, le paiement est refusé. Les paramètres d'URL ne sont jamais journalisés (ils peuvent contenir des secrets). |
| **Tout refusé par défaut** | Clé inconnue, agent arrêté, vendeur hors de la liste de l'agent, http, adresse interne ou de métadonnées cloud, URL ambiguë : refusés avant tout appel réseau. Hors démo, chaque agent doit avoir une liste de vendeurs explicite. |
| **Agents isolés** | Chaque agent a son coffre, sa liste de vendeurs, son plafond par requête, sa limite de débit et son cache d'idempotence. Un agent ne peut ni payer depuis le coffre d'un autre, ni rejouer ses réponses. |

Les requêtes sont traitées une par une : deux achats ne lisent jamais le même état de coffre en même temps.

## Installation

1. Installer chaque agent sur la machine de la passerelle avec le kit remis par la console du propriétaire :
   `vault-cli agent-installer kit.json` (un dossier par agent).
2. Créer une clé par agent et une clé d'administration. Chaque clé s'affiche une seule fois ; seule son
   empreinte va dans la configuration :
   ```bash
   vault-cli passerelle-cle
   ```
3. Écrire la configuration (`passerelle.json`), voir l'exemple dans [GATEWAY.md](GATEWAY.md#setup).
4. La lancer, derrière votre proxy TLS :
   ```bash
   vault-cli passerelle passerelle.json
   ```

## API

Les agents utilisent la même API que le routeur à un seul agent : le SDK Python (`sdk/python`) fonctionne sans
changement. Points d'entrée : `GET /v1/coffre`, `POST /v1/fetch`, et pour l'administration `GET /admin/etat`,
`POST /admin/arret`, `POST /admin/reprise`. Une clé d'agent n'atteint pas `/admin`, et la clé d'administration
ne peut pas payer.

## Vérifier le journal d'audit

```bash
vault-cli passerelle-verifier passerelle-journal.jsonl
```

## Limites actuelles

- Réseau de test (testnet-10) uniquement, comme le reste de Plafond. Pas audité.
- Les vendeurs doivent parler le profil x402 de Plafond (`covenant-budget`). Payer les vendeurs publics
  `exact` passe aujourd'hui par le relais kaspa-x402, pas encore par la passerelle elle-même.
- La passerelle garde les clés des agents en mémoire. La lancer sur une machine dédiée, derrière TLS, avec des
  dossiers d'agents lisibles par son seul utilisateur, fait partie du déploiement.

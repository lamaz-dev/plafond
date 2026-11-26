# Fantôme allègement

Rôle : rendre Plafond plus court et plus simple **sans rien perdre**, pour qu'il puisse devenir un
standard facile à relire et à réimplémenter. Lire d'abord `SOCLE.md`.

## Mesures à relever à chaque passage (tableau en tête du rapport)

| Mesure | Comment |
|---|---|
| Lignes de code de chaque contrat (hors commentaires et lignes vides) | `grep -vc '^\s*//\|^\s*$' contracts/<f>.sil` |
| Taille du bytecode de chaque contrat | `vault-cli empreintes` |
| Budget de calcul mesuré par entrée | tests `mesure_*` et `cent_appels_*` |
| Lignes de Rust par fichier de `cli/src/` | `wc -l` |
| Dépendances directes | `cli/Cargo.toml` |

Comparer au rapport précédent (`review-agents/rapports/*-allegement.md`).

## Ce qu'il cherche

1. Code mort, doublons, fonctions presque identiques (exemple : les fonctions `exec` de test répétées
   dans plusieurs modules).
2. Dans les contrats : une condition redondante (déjà impliquée par une autre ou par le consensus) —
   **à signaler seulement**, jamais retirée sans l'accord d'un humain, car une redondance peut être
   une défense en profondeur voulue (voir les commentaires du contrat).
3. Dépendances inutiles ; fonctionnalités jamais appelées.
4. Spécifications et README : phrases qui répètent, sections qui pourraient tenir en un tableau.

## Règle d'or

Chaque simplification proposée doit garder **tous** les tests verts et **toutes** les empreintes des
contrats inchangées, sauf proposition explicite de changement de contrat, isolée dans son propre
commit et signalée en tête du rapport.

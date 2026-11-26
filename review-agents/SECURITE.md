# Fantôme sécurité

Rôle : trouver ce qui permettrait de perdre plus que ce que Plafond annonce. Lire d'abord `SOCLE.md`.

## Ce qu'il fait à chaque passage

1. Lister les commits depuis le dernier rapport sécurité (`review-agents/rapports/*-securite.md`), ou les
   7 derniers jours s'il n'y en a pas.
2. Relire ces changements contre `spec/threat-model.md` et `spec/borne-de-perte.md` :
   - Un contrat (`contracts/*.sil`) a changé ? Chaque `require` est-il encore couvert par un test qui
     échoue si on le retire (mutation) ?
   - Le moteur de risque (`cli/src/risque.rs`) peut-il annoncer **moins** que ce que le script accepte ?
     C'est le constat le plus grave possible pour Plafond.
   - Une nouvelle entrée de l'API de la console (`cli/src/console.rs`) est-elle protégée (jeton, hôte,
     origine, compte ouvert) ?
   - Un secret peut-il apparaître dans un journal, une réponse JSON, un fichier non chiffré ?
3. Chercher une attaque nouvelle, hors de R1 à R51, sur au moins un des axes : fusion de transactions,
   rejeu d'une preuve ou d'un bon, frais, masse KIP-9, horodatage DAA, lignée KIP-20, réorganisation.
4. Pour chaque constat : un test qui le démontre, ou à défaut le scénario exact pas à pas.

## Ce qu'il ne fait pas

- Pas de refonte ni de « nettoyage » : c'est le rôle d'allègement.
- Pas de correction silencieuse : une correction va dans la pull request, avec le test qui la justifie,
  et une ligne nouvelle dans `spec/threat-model.md` si le risque est nouveau.

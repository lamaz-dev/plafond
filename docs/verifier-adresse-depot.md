# Comment vérifier une adresse de dépôt

Vous allez envoyer de l'argent pour recharger le budget d'un agent. On vous a donné une adresse.
**Ne payez jamais une adresse reçue seule.** Demandez la *fiche de dépôt* (un petit fichier) et
vérifiez-la : cela prend une minute et ne demande aucune clé.

## Ce qu'il vous faut

1. La **fiche de dépôt** (fichier `fiche.json`). N'importe qui peut vous la transmettre, même
   l'agent : elle se vérifie toute seule.
2. La **clé publique du propriétaire** du coffre, obtenue directement auprès de lui (pas dans le
   même message que la fiche).
3. L'outil `vault-cli`.

## La commande

```
vault-cli sas-verifier fiche.json --proprietaire <clé publique du propriétaire>
```

## Ce que vous devez lire

- **`ADRESSE VÉRIFIÉE : kaspa…`** : vous pouvez envoyer à cette adresse, et à elle seule.
  L'outil a recalculé l'adresse à partir des réglages du coffre, vérifié la signature du
  propriétaire, relu la création du coffre et ses pièces sur deux nœuds différents.
- **`REFUSÉ : …`** : n'envoyez rien. La raison est écrite (adresse qui n'est pas celle du coffre,
  fiche signée par quelqu'un d'autre, coffre fermé, nœuds en désaccord…). Prévenez le propriétaire.

Regardez aussi trois lignes du résultat :

- **Dépôt minimal** : en dessous, votre dépôt ne sera pas versé automatiquement ; il attendra que
  le propriétaire s'en occupe.
- **Pièces à la création** : le nombre de pièces du coffre. Le plafond annoncé est multiplié par
  ce nombre.
- **Note sur d'autres pièces à la même adresse** : elles n'appartiennent pas à ce coffre et ne
  reçoivent pas votre dépôt. Ce n'est pas un danger pour vous.

## Les quatre pièges que la vérification attrape

1. On a remplacé l'adresse par une autre.
2. L'agent a fabriqué « son » adresse de dépôt, qui ressemble à la vraie.
3. Le coffre a été fermé : l'ancienne adresse ne recharge plus rien.
4. Le coffre n'a pas le nombre de pièces qu'on vous a dit.

## Si vous avez votre propre nœud Kaspa

Indiquez-le : `NOEUD_WRPC=ws://… vault-cli sas-verifier …`. Il sera interrogé en premier.

## Si vous ne pouvez pas lancer l'outil

Ne payez pas sur la seule foi d'une adresse. Demandez au propriétaire de vous la confirmer par un
autre canal (téléphone, message signé). Le détail du calcul est dans `spec/verification-sas.md`.

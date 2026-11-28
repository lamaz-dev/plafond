# Vendeur : 5 vérifications obligatoires avant de livrer

*Pour un vendeur qui accepte un paiement venant d'un coffre Plafond (v0.9.2) sans utiliser notre
code. Si une seule échoue : ne pas livrer.*

1. **La pièce reçue est à moi, au bon prix, et c'est une pièce ordinaire.** La sortie 0 paie
   exactement mon adresse et exactement le prix. Elle ne porte **aucun identifiant de lignée**
   (champ covenant vide). Une pièce marquée peut être invisible ou inutilisable dans mon
   portefeuille.
2. **Le coffre est le vrai.** La pièce dépensée existe sur la chaîne, est confirmée, porte le script
   recalculé à partir des paramètres annoncés **et** la lignée annoncée. Un coffre, c'est une
   adresse plus une lignée : l'adresse seule ne suffit pas.
3. **Le réseau acceptera ce paiement.** Le reste (sortie 1) retourne au même coffre, dans la même
   lignée ; la dépense (prix + frais) ne dépasse pas le plafond par paiement ; l'âge de la pièce
   couvre cette dépense. Sinon le réseau refusera et je n'aurai rien.
4. **Le paiement est pour cette requête, maintenant.** L'autorisation est signée par la clé agent
   inscrite dans le coffre, elle nomme ma requête, mon adresse, le prix et l'identifiant de la
   transaction, et elle n'est pas expirée. Sinon c'est un paiement rejoué.
5. **Je livre après l'acceptation, pas avant.** Je diffuse moi-même la transaction, j'attends que
   mon nœud me montre la pièce (même identifiant de transaction, sortie 0), puis je livre. « Diffusé »
   ne veut pas dire « payé ».

Mise en œuvre de référence : `cli/src/x402.rs`, fonctions `preparer` (points 1, 3, 4), `controler`
(points 2, 3) et `verify_and_settle` (point 5). Il n'existe pas de fonction unique
`seller_verify()` : le point 2 demande une lecture du réseau, les autres non, et nous avons gardé
les deux moitiés séparées pour pouvoir tester la première hors ligne.

Ce que ces vérifications ne donnent pas : une protection contre une réorganisation profonde de la
chaîne après l'acceptation (attendre davantage pour les gros montants).

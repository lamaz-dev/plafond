#!/usr/bin/env bash
# Vérification reproductible de la borne de perte du cœur de Plafond (v0.6 à v0.9.1), en une commande.
#
#   ./verify-proof.sh                   # campagne standard (256 scénarios par propriété, quelques minutes)
#   FUZZ_CASES=4000 ./verify-proof.sh   # campagne longue
#
# Aucun réseau, aucune clé, aucun nœud : tout s'exécute contre le vrai moteur de script de Kaspa
# (kaspa-txscript), compilé localement, avec les deux règles du réseau copiées de rusty-kaspa
# (verrou relatif, sorties ≤ entrées). Prérequis : Rust stable (rustup).
set -uo pipefail
cd "$(dirname "$0")/cli"

export FUZZ_CASES="${FUZZ_CASES:-256}"
echec=0
etape() {
  local titre="$1"; shift
  printf '%-66s ' "$titre"
  if out=$("$@" 2>&1); then echo "PASS"; else echo "FAIL"; echo "$out" | tail -25; echec=1; fi
}
# Un test introuvable (renommé, supprimé) ne doit JAMAIS passer : on exige « 1 passed ».
teste() { local out; out=$(cargo test --release "$1" -- --exact "$1" 2>&1) || { echo "$out"; return 1; }; echo "$out" | grep -q "test result: ok. 1 passed" || { echo "$out"; echo "test introuvable ou non exécuté : $1"; return 1; }; }

echo "Plafond, cœur v0.6 à v0.9.1 : vérification de la borne de perte (FUZZ_CASES=$FUZZ_CASES)"
echo
etape "0. Compilation (contrat SilverScript + moteur kaspa-txscript)" cargo build -q --release --locked
etape "1. Empreintes : bytecode compilé = contracts/EMPREINTES.txt" \
  bash -c 'diff <(cargo run -q --release -- empreintes 2>/dev/null) ../contracts/EMPREINTES.txt'
etape "2. Moteur + réseau = modèle d'une ligne (7 familles de tricherie)" teste coeur::tests::coeur_moteur_et_consensus_egal_modele
etape "3. Théorème : agent avide, un coffre, toute fenêtre" teste coeur::tests::agent_avide_un_coffre_sous_la_borne
etape "4. Coffres frères, dépôts, retours : annonce et courbe tenues" teste coeur::tests::agent_avide_coffres_freres_sous_l_annonce_du_moteur
etape "5. Blanchiment entre frères : la courbe promise tient" teste coeur::tests::blanchiment_entre_freres_sous_la_courbe
etape "6. La borne C + C·D/R est atteinte : elle est serrée" teste coeur::tests::borne_simple_atteinte_et_jamais_depassee
etape "7. Deux paiements dans un même bloc : impossible" teste coeur::tests::enchainement_dans_un_meme_bloc_impossible
etape "8. Outil conforme, budget de calcul suffisant" teste coeur::tests::budget_de_calcul_suffisant_et_outil_conforme
etape "9. Sas v0.1 (cœur v0.8, archive) : dépôt au coffre ou au retour" teste sas::tests::le_depot_ne_peut_que_regonfler_le_coffre_ou_revenir
etape "10. Sas : chaque règle sabotée est détectée" teste sas::tests::chaque_regle_sabotee_est_detectee
etape "11. Sas : agent avide, rechargements et gênes sous la borne" teste sas::tests::sas_et_agent_avide_sous_la_borne
etape "12. Lignée et retrait partiel (v0.9.1) : légitimes, attaques" teste lignee::tests::coffre_a_lignee_legitimes_acceptees_attaques_refusees
etape "13. Lignée : chaque règle sabotée est détectée" teste lignee::tests::chaque_regle_sabotee_est_detectee
etape "14. Lignée : S3 ouvert en v0.8, fermé en v0.9" teste lignee::tests::s3_ouvert_en_v08_ferme_en_v09
etape "15. Lignée : le réseau refuse une lignée usurpée (KIP-20)" teste lignee::tests::le_reseau_refuse_une_lignee_usurpee
etape "16. Coffre entier sous la borne, frais des retraits compris" teste lignee::tests::coffre_entier_sous_la_borne
etape "17. Retrait partiel : une clé volée ne brûle pas le coffre en frais" teste lignee::tests::cle_volee_ne_brule_pas_le_coffre_en_frais
etape "18. Archives à l'identique ; v0.9.1 = v0.9 + une entrée" teste lignee::tests::versions_precedentes_archivees_a_l_identique
etape "19. Suite complète (dont l'ancien coffre v0.5.1, séquestre, ardoise)" cargo test -q --release

echo
if [ "$echec" = 0 ]; then
  echo "RÉSULTAT : PASS. Preuves écrites : spec/borne-de-perte-v0.6.md, spec/borne-de-perte-v0.9.md (lignée ; §9 : retrait partiel)"
else
  echo "RÉSULTAT : FAIL"
fi
exit "$echec"

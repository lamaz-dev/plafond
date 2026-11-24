#!/usr/bin/env bash
# Vérification reproductible de la borne de perte du cœur v0.6 de Plafond, en une commande.
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

echo "Plafond, cœur v0.6 : vérification de la borne de perte (FUZZ_CASES=$FUZZ_CASES)"
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
etape "9. Suite complète (dont l'ancien coffre v0.5.1, séquestre, ardoise)" cargo test -q --release

echo
if [ "$echec" = 0 ]; then
  echo "RÉSULTAT : PASS. Preuve écrite : spec/borne-de-perte-v0.6.md"
else
  echo "RÉSULTAT : FAIL"
fi
exit "$echec"

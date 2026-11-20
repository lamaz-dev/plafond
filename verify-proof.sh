#!/usr/bin/env bash
# Vérification reproductible de la borne de perte d'AgentBudget v0.5, en une commande.
#
#   ./verify-proof.sh              # campagne standard (256 scénarios par test, quelques minutes)
#   FUZZ_CASES=4000 ./verify-proof.sh   # campagne longue
#
# Aucun réseau, aucune clé, aucun nœud : tout s'exécute contre le vrai moteur de script de Kaspa
# (kaspa-txscript), compilé localement. Prérequis : Rust stable (rustup).
set -uo pipefail
cd "$(dirname "$0")/cli"

export FUZZ_CASES="${FUZZ_CASES:-256}"
echec=0
etape() {
  local titre="$1"; shift
  printf '%-66s ' "$titre"
  if out=$("$@" 2>&1); then echo "PASS"; else echo "FAIL"; echo "$out" | tail -25; echec=1; fi
}
teste() { cargo test -q --release "$1" -- --exact "$1"; }

echo "AgentBudget v0.5 : vérification de la borne de perte (FUZZ_CASES=$FUZZ_CASES)"
echo
etape "0. Compilation (contrat SilverScript + moteur kaspa-txscript)" cargo build -q --release
etape "1. Empreintes : bytecode compilé = contracts/EMPREINTES.txt" \
  bash -c 'diff <(cargo run -q --release -- empreintes 2>/dev/null) ../contracts/EMPREINTES.txt'
etape "2. Faille v0.4 reproduite (3 × la réserve en une période)" teste fuzz::faille_v04_demontree
etape "3. Même attaque sur v0.5 : fermée (≤ 2 × la réserve)" teste fuzz::attaque_temps_mis_de_cote_fermee
etape "4. Coffre non confirmé : paiement refusé" teste fuzz::coffre_non_confirme_refuse
etape "5. Théorème : agent avide et tricheur sous la borne" teste fuzz::agent_avide_ne_depasse_jamais_la_borne
etape "6. Moteur = modèle de référence (10 tricheries)" teste fuzz::coffre_moteur_egal_modele
etape "7. Seul le propriétaire ouvre ownerControl (gel)" teste fuzz::seul_le_proprietaire_ouvre_owner_control
etape "8. Paramètres aberrants : aucun fonds en danger" teste fuzz::parametres_aberrants_sans_danger_pour_les_fonds
etape "9. Suite complète (routeur, clé chiffrée, relais, séquestre)" cargo test -q --release

echo
if [ "$echec" = 0 ]; then
  echo "RÉSULTAT : PASS. Preuve écrite : spec/borne-de-perte.md"
else
  echo "RÉSULTAT : FAIL"
fi
exit "$echec"

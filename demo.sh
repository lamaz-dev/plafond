#!/usr/bin/env bash
# Démo de bout en bout, en une commande : ./demo.sh
#
# Ce script ne télécharge et n'exécute rien d'autre que ce dépôt et ses dépendances Rust (Cargo.lock).
# Il ne demande aucune phrase ni aucun mot de passe : la démo crée des clés jetables du réseau de test
# dans cli/demo-jetable/ (fichier lisible par votre seul compte). Lisez-le avant de le lancer.
set -euo pipefail
cd "$(dirname "$0")/cli"

ok()   { printf '  ✓ %s\n' "$1"; }
stop() { printf '\n  ✗ %s\n\n' "$1" >&2; exit 1; }

echo "1/4 Prérequis"
command -v cargo >/dev/null || stop "Rust absent : installez-le depuis https://rustup.rs puis relancez ./demo.sh"
ok "Rust : $(cargo --version)"
command -v cc >/dev/null || command -v clang >/dev/null || command -v gcc >/dev/null \
  || stop "compilateur C absent (requis par la cryptographie) : Linux « sudo apt install build-essential », macOS « xcode-select --install »"
ok "compilateur C présent"

echo "2/4 Compilation (première fois : quelques minutes)"
cargo build --release --locked >demo-compilation.log 2>&1 \
  || { tail -30 demo-compilation.log; stop "échec de compilation : envoyez cli/demo-compilation.log avec votre retour"; }
ok "binaire prêt : cli/target/release/vault-cli"

echo "3/4 Vérification hors ligne du contrat (aucun réseau, vrai moteur de script Kaspa)"
diff <(./target/release/vault-cli empreintes 2>/dev/null) ../contracts/EMPREINTES.txt >/dev/null \
  || stop "le contrat compilé ne correspond pas à l'empreinte publiée (contracts/EMPREINTES.txt)"
ok "contrat compilé = contrat publié (empreintes identiques)"
for t in fuzz::coffre_non_confirme_refuse fuzz::agent_avide_ne_depasse_jamais_la_borne; do
  FUZZ_CASES=64 cargo test --release --locked -q "$t" -- --exact "$t" 2>&1 | grep -q "test result: ok. 1 passed" \
    || stop "test du contrat en échec : $t (ne pas lancer la démo, signaler l'anomalie)"
done
ok "un agent qui tente de dépasser son budget est refusé (tests du contrat)"

echo "4/4 Démo sur le réseau de test (Ctrl+C pour quitter à la fin)"
exec ./target/release/vault-cli demo

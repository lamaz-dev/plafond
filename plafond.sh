#!/usr/bin/env bash
# Plafond : ouvre votre console (testnet-10). Le compte se crée ou s'ouvre dans la page.
# Vos fichiers restent dans le dossier « compte » (ou PLAFOND_DOSSIER) : ne le partagez pas.
set -euo pipefail
cd "$(dirname "$0")/cli"
command -v cargo >/dev/null || { echo "Rust absent : installez-le depuis https://rustup.rs puis relancez ./plafond.sh"; exit 1; }
cargo build --release --locked -q
export PLAFOND_DOSSIER="${PLAFOND_DOSSIER:-$(pwd)/../compte}"
exec ./target/release/vault-cli plafond

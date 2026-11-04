#!/usr/bin/env bash
# Install Shipyard on a machine that already runs Switch (and, optionally, Coolify).
#   curl -fsSL https://raw.githubusercontent.com/Shrinet82/shipyard/main/scripts/install.sh | bash
#   ./scripts/install.sh --answers answers.yaml      # no questions asked
# Installs Python, PyYAML, OpenSSL and git with apt, clones the repo to ~/shipyard, then runs `python3 -m shipyard init`.
set -euo pipefail
DIR="${SHIPYARD_DIR:-$HOME/shipyard}"
if ! command -v apt-get >/dev/null; then echo "This script uses apt. On another system install python3 (3.10+), PyYAML, openssl and git, then run: python3 -m shipyard init"; exit 1; fi
need=()
for p in python3 python3-yaml openssl git; do dpkg -s "$p" >/dev/null 2>&1 || need+=("$p"); done
if [ ${#need[@]} -gt 0 ]; then sudo apt-get update -qq && sudo apt-get install -y -qq "${need[@]}"; fi
if [ -d "$DIR/.git" ]; then git -C "$DIR" pull --ff-only -q; else git clone -q https://github.com/Shrinet82/shipyard "$DIR"; fi
cd "$DIR"
exec python3 -m shipyard init "$@" < /dev/tty

#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Python 3 não encontrado'; exit 1; }
command -v bash >/dev/null || { echo 'Bash não encontrado'; exit 1; }
chmod +x "$DIR/cyberops" "$DIR/pentest.sh"
mkdir -p "$HOME/.local/bin"
ln -sfn "$DIR/cyberops" "$HOME/.local/bin/cyberops"
echo 'OP Cybernetica I v1.1.0 instalado.'
echo 'Execute: cyberops --h ou cyberops open'
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo 'Adicione ao PATH: export PATH="$HOME/.local/bin:$PATH"'
fi

#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Python 3 não encontrado'; exit 1; }
command -v bash >/dev/null || { echo 'Bash não encontrado'; exit 1; }
chmod +x "$DIR/cyberpm" "$DIR/cyberpm.sh"
mkdir -p "$HOME/.local/bin"
ln -sfn "$DIR/cyberpm" "$HOME/.local/bin/cyberpm"
# Remove only the former symlink owned by this exact installation.
OLD_LINK="$HOME/.local/bin/cyberops"
if [[ -L "$OLD_LINK" && "$(readlink "$OLD_LINK")" == "$DIR/cyberops" ]]; then
  rm -- "$OLD_LINK"
fi
if command -v git >/dev/null && [[ -d "$DIR/.git" ]]; then
  OLD_REMOTE=$(git -C "$DIR" remote get-url origin 2>/dev/null || true)
  case "$OLD_REMOTE" in
    https://github.com/Luistn/Pentest-cyberops|https://github.com/Luistn/Pentest-cyberops.git)
      git -C "$DIR" remote set-url origin https://github.com/Luistn/Cyberpm.git;;
    git@github.com:Luistn/Pentest-cyberops|git@github.com:Luistn/Pentest-cyberops.git)
      git -C "$DIR" remote set-url origin git@github.com:Luistn/Cyberpm.git;;
  esac
fi
echo "Cyberpm v$(cat "$DIR/VERSION") instalado."
echo 'Execute: cyberpm --h ou cyberpm open'
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo 'Adicione ao PATH: export PATH="$HOME/.local/bin:$PATH"'
fi

#!/usr/bin/env bash
set -euo pipefail
LINK="$HOME/.local/bin/cyberops"
if [[ -L "$LINK" ]]; then rm "$LINK"; echo 'Atalho removido.'; else echo 'Nenhum atalho simbólico encontrado.'; fi
echo 'Arquivos, relatórios e configurações foram preservados.'

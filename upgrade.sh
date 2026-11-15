#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
runtime="${SHADOW_RUNTIME_DIR:-${SHADOW_DATA_DIR:-$HOME/.local/share/shadow}/runtime}"
[[ -x "$runtime/venv/bin/python" ]] || { printf 'Run ./install.sh first.\n' >&2; exit 1; }
printf 'Stop SHADOW sessions before upgrading. Backing up the local database.\n'
"$runtime/venv/bin/python" scripts/pre_upgrade_backup.py
exec "${SHADOW_PYTHON:-python3}" scripts/install_runtime.py --repair "$@"

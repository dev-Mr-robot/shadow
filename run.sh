#!/usr/bin/env bash
set -euo pipefail
runtime="${SHADOW_RUNTIME_DIR:-${SHADOW_DATA_DIR:-$HOME/.local/share/shadow}/runtime}"
[[ -x "$runtime/venv/bin/python" ]] || { printf 'Run ./install.sh first.\n' >&2; exit 1; }
exec "$runtime/venv/bin/python" -I -m shadow.bootstrap "$@"

#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
runtime="${SHADOW_RUNTIME_DIR:-${SHADOW_DATA_DIR:-$HOME/.local/share/shadow}/runtime}"
if [[ -f "$runtime/install.json" && -f scripts/uninstall_runtime.py ]]; then
 exec "${SHADOW_PYTHON:-python3}" scripts/uninstall_runtime.py
fi
project_dir="$(pwd -P)"
target="$project_dir/.venv"
resolved="$(realpath -m -- "$target")"
[[ "$target" == "$resolved" && ! -L "$target" ]] || { printf 'Refusing unexpected .venv target.\n' >&2; exit 1; }
launcher="${SHADOW_BIN_DIR:-$HOME/.local/bin}/shadow"
if [[ -L "$launcher" && "$(readlink -- "$launcher")" == "$target/bin/shadow" ]]; then rm -- "$launcher"; fi
rm -rf -- "$target"
printf 'Removed this checkout’s environment and matching launcher. Data, configuration, reports, research and source were preserved.\n'

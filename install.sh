#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ "${1:-}" == --help ]]; then
 printf 'Usage: ./install.sh [--user] [--no-link] [--repair]\nInstall an isolated runtime and global shadow command. System/PATH changes require consent.\n'; exit 0
fi
[[ "$(uname -s)" == Linux ]] || { printf 'Linux required.\n' >&2; exit 1; }
python="${SHADOW_PYTHON:-python3}"
if ! command -v "$python" >/dev/null; then
 printf 'Python is required. Install python3, python3-venv and ca-certificates using APT with system authorization? [y/N] '
 read -r answer
 [[ "$answer" == y || "$answer" == Y ]] || exit 1
 command -v apt-get >/dev/null || { printf 'Install Python 3.11+ with your distribution package manager.\n'; exit 1; }
 if [[ $EUID == 0 ]]; then apt-get update; apt-get install -y python3 python3-venv ca-certificates
 else sudo apt-get update; sudo apt-get install -y python3 python3-venv ca-certificates; fi
fi
exec "$python" scripts/install_runtime.py "$@"

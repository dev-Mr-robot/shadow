# One-command lifecycle

Install once with `./install.sh`, then open a new terminal and type `shadow` from any directory. The runtime is installed outside the source checkout under the user's SHADOW data directory, in its own `runtime/venv`. No activation is needed.

Installation detects Python/venv/SSL/SQLite support. Missing required APT packages are explained and installed only after consent and normal system authorization. Pip is bootstrapped in the private virtual environment from the official PyPA HTTPS bootstrap when necessary. Runtime dependencies use the packaged lock file.

The default launcher is `/usr/local/bin/shadow` with sudo authorization if required. Declining selects the user launcher; `--user` chooses it directly. When the selected directory is outside PATH, the installer requests authorization for managed startup-file entries and backs up existing profiles first. Open a new terminal after installation. Existing unrelated launchers are never replaced.

First launch creates/migrates the database and validates configuration, inventories hardware/tools and offers local AI setup. Optional Ollama installation uses its official installer after consent. Model downloads require a separate affirmative answer. Declining either leaves non-AI functions available. Use `shadow setup` to revisit.

`shadow doctor [--json]` diagnoses hardware, AI, installed tools, Python package compatibility, SQLite, configuration, permissions and PATH. `shadow doctor --repair` / `shadow setup --repair` review safe repair actions. Invalid configuration resets require confirmation and create original-byte backups. Database corruption requires a reviewed restore, never automatic deletion.

`./upgrade.sh` creates a consistent SQLite backup before installing updates and migrating. Use `shadow backup FILE` and `shadow restore FILE` for database maintenance. `./uninstall.sh` verifies the runtime marker and resolved path, removes only that runtime and matching launcher, and preserves all research/configuration/database/report/profile backups. An unrecognized runtime or symlink target is refused. No data deletion option is provided.

Supported distributions are Linux-first with APT-assisted setup on Kali/Ubuntu/Debian; other distributions receive explicit package guidance. Python 3.11+ is required. SHADOW never adds third-party OS repositories, changes firewall rules, silently downloads models or starts its own web application.

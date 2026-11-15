# Integrated validation record

2026-11-15, SHADOW 0.2.0. Synthetic fixtures are isolated test data and do not ship as application results.

- Ubuntu WSL / Python 3.14.4: **149 passed** after setup and expert integration (full suite), plus **2 passed** managed-uninstall boundary tests.
- Windows / Python 3.14.7: previous integrated baseline **131 passed, 5 platform skips**; later setup/expert work is validated on Linux.
- SQLite forward migrations through 0004_soc; persistence, backup/restore and migration-preservation coverage.
- AI streaming/cancellation, schema/native-tool plans, bounded context, explicit memory, KB citations, cross-process stream leases and approval boundaries tested.
- Recon scale: 50,000 unique assets plus 50,000 duplicate input entries; scope/IP pinning, rate/bounds, frozen approval and resume tests.
- SOC scale: 20,000 streamed events; parser/detection/lifecycle/incident/rule/retention/export coverage.
- HTTP/Burp, static analysis, evidence/finding validation, workflows, fixed tool recipes and TUI Pilot coverage.
- Live Windows Ollama gemma4:12b generated a real response and validated native-tool plan; combined smoke169.47s. Linux loopback offline correctly reported.
- Offensive/SOC PDFs rendered and visually inspected; immutable export hash checks pass.
- Clean Linux wheel installed with 34 pinned runtime dependencies, no web-server or test dependencies, init/upgrade/help succeeded.
- Shell syntax, installer help and data-preserving legacy uninstall checks pass. Managed installer acceptance passed in an isolated fresh Linux home: automatic dependency install, new interactive Bash, cwd=/tmp, only shadow typed, TUI/first-run/SQLite verified. Managed uninstaller: 2 tests passed for data preservation and ownership refusal.

No live external-target penetration test was run. Native Kali/Debian and Python3.11 need separate hosts; WSL is not a substitute for every distribution. No large model was downloaded automatically.

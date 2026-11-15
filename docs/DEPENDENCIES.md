# Dependency plan

Runtime: Python3.11+, Typer, Textual, Rich, HTTPX, Pydantic, psutil, SQLAlchemy, Alembic, pypdf, defusedxml and reportlab, plus their pinned dependency closure. `requirements.lock.txt` is generated from package metadata including transitive extras, not a broad development-environment freeze. Test extras are pytest and pytest-asyncio.

No Node.js, JavaScript application, HTTP server framework, desktop framework or graphical launcher is required. Obsolete web-only packages were removed from both development environments after checking the CLI dependency closure. The previous web project, its build/configuration and dashboard image were removed. Useful standalone Python reference logic and existing data/configuration were preserved outside the release.

Ollama is a separately installed local inference service, not a paid/cloud dependency. SHADOW only permits its configured HTTP loopback origin and disables redirects/environment proxies. Models are selected explicitly and never pulled automatically. Local embeddings are optional; failure/absence is labeled as lexical retrieval.

Optional trusted system dependencies: `nvidia-smi` for hardware metadata, bubblewrap plus Nmap for fixed Linux scans, and separately installed tools for output import/version workflows. The installer never runs sudo or package-manager/system configuration commands. Version identity is not inferred solely from filenames.

Report generation uses reportlab without fetching remote assets; PDF reading uses bounded pypdf extraction. DOCX uses bounded ZIP/XML parsing rather than a large office runtime. These parsers are not hard-isolated processes; hostile samples should be examined in a disposable environment. Static classic-PCAP support is metadata triage, not full protocol reassembly.

Update pins in an isolated environment, run unit/CLI/TUI/migration/Linux/install/clean-runtime checks, inspect advisories and render report fixtures before release. Version pins improve reproducibility; they do not prove that dependencies are vulnerability-free.

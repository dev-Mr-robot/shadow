# Terminal-only repository cleanup

Completed2026-11-15 in response to the explicit CLI-only override.

Inspected application source, tests, scripts, configuration, generated outputs, dependencies and workspace helper files before removal. `outputs/shadow-cli` is the sole active application.

Removed the obsolete `outputs/shadow` application: React/TypeScript/Vite source, npm manifests/dependencies/builds, CSS/dashboard assets, FastAPI server, website configuration/startup scripts and superseded web-specific documentation/API harness. Removed `outputs/shadow-dashboard.png` and the helper that targeted that obsolete project. The old server had already been stopped.

Standalone reusable Python core files were retained as non-application reference material under `work/preserved-python-core`; their implemented behavior and relevant test coverage live in the active CLI services. The tested Phase1 terminal source/behavior and its release archive were preserved. Existing databases, tokens, configuration, research and report data under `work` were not deleted. No user data was found inside the removed application tree.

Removed obsolete FastAPI/uvicorn/starlette/multipart/telemetry-interface/dotenv/office-parser packages from the isolated Windows and Linux development environments after confirming the CLI uses neither them nor their API harness. Shared HTTPX/SQLAlchemy/Pydantic and document/report dependencies remain. Removed generated Windows batch activation helpers from the development environment; no application batch or graphical launcher exists in the release.

The release contains Python CLI/TUI/services, terminal-oriented report documents, data/migration logic, tests and Linux shell scripts. Static HTML report exports are optional document artifacts, not a website, dashboard, server or required interface. Nothing in the application opens a browser or GUI.

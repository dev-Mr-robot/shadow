# Integrated development status

2026-11-15. SHADOW 0.2.0 is an integrated terminal-only offensive/defensive workstation. Independent workstreams were merged into the preserved SQLAlchemy/Alembic foundation; the SOC was then integrated into the same services, AI and TUI.

## Implemented and integrated

- Shared records, forward migrations through 0004_soc, consistent backup/confirmed restore and migration-preservation tests.
- Local AI streaming, semantic typed plans/native tool calling/schema fallback, context/follow-ups, clarification, summaries, cross-process stream leases and explicit memory CRUD.
- Local KB/RAG, citations, embeddings/reindex, bounded document formats and labeled lexical fallback.
- Streaming recon, indexed inventories, frozen approval targets, DNS/IP pinning, rate/concurrency bounds, checkpoints/resume, priority explanations, history/diffs and exports.
- Bug bounty engagements, authorization/scope/rules/notes, HTTP/Burp/API evidence, structured findings, duplicate candidates and source/date-tagged local advisories.
- Passive source/config/log/binary/classic-PCAP research and reviewed typed local workflow pipelines.
- Immutable MD/PDF/HTML report documents, fixed Nmap adapter, no-network version recipes, bounded capture/separate stderr, cancellation, output imports and stale-owner recovery.
- SOC streaming parsers/indexed events, deterministic indicator rules, alert lifecycle/false positives/notes/correlation, incident timelines/playbooks, local IOC intelligence and versioned sourced ATT&CK subset/import.
- SOC AI mode, local queries and reports, detection engineering/Sigma subset, network/endpoint metadata views, retention previews and all twelve SOC sections in Textual.
- CLI-only cleanup: obsolete web application/dependencies/builds/assets removed; Python reference core, terminal tests, configuration and database data preserved.

## Actual verification

- Phase 1 baseline: 31 Ubuntu passes; 27 Windows passes with four Linux-only skips; clean foundation wheel installation passed.
- Latest full Windows unified suite: **131 passed, 5 expected platform skips**. No ignored test failures. This covers AI/recon/offensive/SOC/workflows/CLI/TUI/migrations/security controls.
- Unified Ubuntu integration baseline: **136 passed**; clean 0.2.0 wheel with all 34 runtime pins installed and initialized successfully. Installer and expert verification are recorded below.
- Recon scale fixture: 50,000 unique assets plus duplicate reimport on both OS environments. SOC scale fixture: 20,000 synthetic events streamed and retention-confirmation checked.
- Live local Ollama: gemma4:12b returned **SHADOW ready.**, then produced a validated security_question plan through native tool calling with zero actions. Combined smoke elapsed169.47s; no external target contacted. This is not a model quality/performance benchmark.
- Offensive and SOC report PDFs rendered with pdftoppm and visually inspected; export/hash/text checks pass.
- Fixed during integration: TUI focus/tab races, startup message clobbering, a missing widget import, CLI argument declarations, workflow test-spy default, and legacy revision expectations updated to current migrations without removing coverage.

## Remaining depth, external dependencies and known limits

- Linux loopback Ollama is unavailable; Windows discovery/generation passed. The large installed model is memory-sensitive and slow to cold-start.
- Security tool binaries are absent. Real target scans were not performed. Only vetted fixed Nmap execution and no-network version recipes exist; other integrations import output.
- SOC detections use bounded fixed time buckets and heuristic confidence. Bucket boundaries/unknown baselines can create misses or false positives. Indicators never prove attack success.
- Initial ATT&CK dataset is a small sourced/versioned subset; reviewed official STIX import expands it. Sigma supports one literal selection (equals/contains), not arbitrary Sigma correlation/query syntax.
- Raw EVTX, live endpoint/sensor deployment, automated containment, external threat-intelligence transmission and encrypted PCAP payload inspection are absent. Supported exports and local metadata are analyzed instead.
- Online CVE feeds, dynamic malware/debugger execution, broad scanner recipes, deep protocol reassembly and endpoint clustering remain future depth, not hidden nonfunctional controls.
- Document parsing has bounded input/output but no hard parser process isolation. Native Kali/Debian/Ubuntu and Python3.11 acceptance still need dedicated environments. Ubuntu WSL/Python3.14 and Windows/Python3.14 are tested here.
- System resolver threads can outlive cancellation; subsequent HTTP work is cancelled. Data is unencrypted and audit logs are not tamper-proof against the OS account owner.

The usable integrated release is the current target; deeper coverage is tracked explicitly rather than represented as complete. No production fixture events or fake metrics ship in application data.

## One-command installation expansion

Implemented a checkout-independent private runtime, managed global/user launcher, automatic virtualenv/pinned dependencies, explained and approved system/PATH changes with profile backups, first-run environment/model setup, optional AI fallback, robust doctor and approved config/dependency repairs. Updates create SQLite backups; uninstallation verifies runtime ownership and preserves user data. Fresh-home Ubuntu WSL installation passed: automatic private venv/pip + 34 pinned dependencies, database migration, approved isolated-home PATH setup, pip check, new interactive Bash with cwd=/tmp and only `shadow` typed, first-run optional-AI decline, terminal UI appearance and SQLite quick_check. No actual host profile/system packages were modified. Setup regression tests: 4 passed on Ubuntu. Managed uninstall boundary tests: 2 passed, preserving research/config and rejecting unrecognized runtimes.

## Expert system expansion

Added 15 modular specialist profiles and shared expert investigation/learning/research services, CLI commands and an Experts TUI tab. Evidence packets contain actual record/chunk IDs, document hashes/import dates and explicit freshness uncertainty. Structured model outputs validate citations and cannot promote unconfirmed records to confirmed findings. Offline taxonomy routing/checklists are explicitly labeled; they do not pretend to perform model reasoning. Cases and lessons preserve conversation context; durable personal memory remains explicit. Current research uses local imported sources only. Dynamic debugger/reverse-engineering execution, new online CVE feeds and a comprehensive teaching curriculum are not implemented by these profiles.

Expert verification: 8/8 tests pass on Windows and Ubuntu; the Experts TUI shared-service offline investigation test also passes on Ubuntu. Final combined Ubuntu suite: **149 passed in 73.18s**, plus **2 passed** managed-uninstall boundary tests.

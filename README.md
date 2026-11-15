# SHADOW 0.2.0

Local-first security intelligence for the Linux terminal. Run `shadow` for the Textual research workspace, or use Typer commands for scripting. The entire application works from a terminal. Python 3.11+, Rich, Textual, Ollama, HTTPX, SQLite, SQLAlchemy and Alembic.

## What works

- Natural-language chat, specialist modes, local streaming, validated semantic intent/action plans, clarification, conversational follow-ups and summaries.
- Persistent conversations, approved action results and explicit research memory with inspect/search/edit/delete.
- Engagement authorization, scope/exclusions, program rules, notes and active-workspace selection.
- Streaming subdomain/IP imports, normalization/deduplication, indexed inventory, search/filter/pagination, evidence-based review reasons and JSON/CSV/TXT export.
- Approval-gated DNS/root HTTP probes with frozen target snapshots, pinned IP/Host/SNI, rate/concurrency/time/body limits, checkpoints, resume and historical comparisons.
- Static raw HTTP/Burp/API analysis: headers, query/body parameters, cookies, CORS, cache, JWT decoding, JSON/XML, multipart metadata and response comparison.
- Hashed evidence, structured Nmap imports, scoped findings, evidence/verification labels, justified CVSS, CWE and local advisory source/date tracking.
- Immutable Markdown/PDF and standalone HTML report documents generated without opening another application. HTML exports are documents, never an administration interface.
- Local document KB/RAG with PDF/DOCX/MD/TXT/HTML/JSON/CSV import, local embeddings, chunk citations, reindexing and explicitly labeled lexical fallback.
- Passive Python/config/log/binary/classic-PCAP triage and typed, reviewed local workflows.
- Fixed Nmap TCP-connect execution adapter, approved no-network version recipes, tool-output imports, time/output limits, logs and cancellation. Other tools are import/availability integrations; arbitrary tool execution is not implemented.
- SOC log ingestion, deterministic detections, alert lifecycle, incident timelines/playbooks, local IOC intelligence, sourced ATT&CK records, network metadata and terminal reports.
- Database backup/restore, schema upgrades and Linux installation/maintenance scripts.

No placeholder AI answers, fabricated metrics or simulated scan results are used in production. Heuristic leads are never automatically confirmed vulnerabilities. See [development status](docs/DEVELOPMENT_STATUS.md) for tests and limitations.

## Install

Install once from a Linux terminal (Python 3.11+). The installer explains required system packages and requests authorization before APT/sudo or shell-profile changes.

```bash
tar -xzf shadow-cli-0.2.0.tar.gz
cd shadow-cli
./install.sh
```

After installation, open any new terminal and type only:

```bash
shadow
```

The isolated runtime lives under `~/.local/share/shadow/runtime`, independently of your working directory. The default installer offers `/usr/local/bin/shadow` with sudo authorization. `./install.sh --user` installs `~/.local/bin/shadow` and, when necessary, offers backed-up Bash/login-shell PATH changes. An unrelated existing launcher is preserved. No virtual-environment activation or manual pip command is needed. `--no-link` is an explicit packaging option that omits the global command.

First launch initializes private directories, configuration and SQLite, detects CPU/RAM/GPU, checks Ollama/models and lists missing optional tools. It offers the official Ollama Linux installer and asks separately before a large model download. Declining AI setup leaves the local analysis/SOC/reporting workspace usable.

```bash
shadow doctor
shadow doctor --json
shadow doctor --repair
shadow setup
shadow setup --tools
shadow models
shadow settings set --model YOUR_INSTALLED_MODEL --context 4096
```

`doctor` reports corrupt configuration/database and dependency/PATH/permission problems. Repairs require review; invalid configuration is backed up before an approved reset. Corrupt databases are never silently replaced. `./upgrade.sh` first backs up SQLite, updates the isolated runtime and applies forward migrations. `shadow backup FILE` and `shadow restore FILE` support consistent database backups and confirmed restores. `./uninstall.sh` removes only a verified runtime and its matching launcher, preserving research, reports, databases, configuration and shell-profile backups. Keep the source archive for updates/maintenance; ordinary launch does not need the source directory.

The observed host has an RTX 3050 with 6 GiB VRAM. A local `gemma4:12b` produced a real response and native-tool semantic plan, but the combined cold smoke check took about 169 seconds. That is functional verification, not a performance or reasoning-quality guarantee. A smaller quantized local model is a better first benchmark. WSL's loopback Ollama was unavailable; Windows availability does not configure the Linux service automatically.

See [installation and maintenance](docs/INSTALLATION.md) for lifecycle details.

## Expert investigation and learning

```bash
shadow expert --list
shadow expert "I think this endpoint has an IDOR" --offline
shadow expert "Correlate these authentication observations" --specialist soc
shadow learn "TLS certificate validation" --level intermediate --offline
shadow research topic "API authorization" --offline
shadow research cases
```

The Experts TUI tab uses the same services. Fifteen specialist profiles share actual evidence, knowledge chunks, conversations and reports. Structured local-model analysis cites validated record IDs and separates observations, competing hypotheses, missing evidence and validation recommendations. Without a model, explicit deterministic taxonomy routing and curated checklists remain available; they are labeled as offline assistance. Knowledge import adds retrieval material, never model training. Research currently searches local imported sources; it does not claim to fetch fresh CVE feeds or external pages.

## First engagement

```bash
shadow bounty create --name "Owned lab" --scope lab.example.test \
  --scope 192.168.56.0/24 --exclude 192.168.56.20 \
  --authorization "Written authorization for my isolated lab"
shadow bounty list
shadow bounty use ENGAGEMENT_ID
shadow recon import subs.txt
shadow recon show --sort priority
shadow recon stats
shadow chat "Which of the imported assets should I investigate next?"
```

Scope uses exact hostnames, IPs and CIDRs; parent domains do not imply wildcard authorization. Imports are passive and retain only authorized assets. Active HTTP probing requires **both** the hostname and destination IP/CIDR to be explicitly authorized. Exclusions win. This intentionally prevents a DNS change or shared/CDN address from becoming implicit authorization.

```bash
shadow recon analyze --concurrency 8 --rate 4 --timeout 8
# Inspect the saved plan; only a separate approval starts DNS/HTTP operations:
shadow recon approve RUN_ID --digest DISPLAYED_DIGEST
shadow recon runs
shadow recon compare FIRST_RUN SECOND_RUN
shadow recon export assets.json --format json
```

Only GET `/` on HTTPS:443 and HTTP:80 is probed. Redirect destinations and discovered links are recorded but never followed. Compressed bodies are deliberately omitted rather than decompressed. Ctrl+C cancels a CLI run; the TUI has an explicit stop control. A fresh approved preview resumes unfinished assets. `recon cancel` rejects an unstarted preview.

## Evidence, analysis and reports

```bash
shadow analyze request.txt --kind http
shadow http analyze burp-export.xml
shadow http compare first-response.txt second-response.txt
shadow evidence import nmap.xml --source nmap
shadow finding add finding.json
shadow finding list
shadow report generate --format md --output assessment.md
shadow report generate --format pdf --output assessment.pdf
shadow report list
shadow report export REPORT_ID --output another-copy.pdf
```

Confirmed/remediated findings require technical evidence; numeric CVSS requires a vector or documented justification. These are operator attestations, not independent proof. Reports preserve hypotheses/false positives and missing fields honestly. Existing output files are never overwritten. Evidence stores parsed text and the original bytes' SHA-256, not original file bytes; retain originals separately when required.

See [command examples and JSON schemas](docs/USAGE.md) for finding/advisory/workflow examples.

## Memory and knowledge

```bash
shadow conversation list
shadow chat --conversation CONVERSATION_ID
shadow conversation summarize CONVERSATION_ID
shadow memory save "The lab API requires two authorized test accounts."
shadow memory list
shadow memory edit MEMORY_ID "Updated research note"
shadow memory remove MEMORY_ID
shadow kb import notes.pdf
shadow kb search "authorization testing"
shadow settings set --embedding-model YOUR_LOCAL_EMBEDDING_MODEL
shadow kb reindex DOCUMENT_ID
```

Messages persist locally; do not paste credentials. Durable research memories are explicit only. Conversational proposals display a concrete preview and require separate approval. Model-generated shell text is never executed. Native tool calling is capability-aware; unsupported models use strictly validated structured-output fallbacks. `shadow chat --no-routing` provides conversation without proposed application actions when a model cannot produce valid plans.

## Tools and passive workflows

```bash
shadow tools
shadow tool version nmap
shadow tool preview 192.168.56.10 --ports 22,80,443
shadow tool run JOB_ID
shadow tool cancel JOB_ID
shadow tool import nuclei nuclei.json
shadow research analyze sample.py --kind python
shadow analyze capture.pcap --kind pcap
shadow workflow import workflow.json
shadow workflow preview WORKFLOW_ID
shadow workflow run PREVIEW_ID --digest DISPLAYED_DIGEST
```

Nmap execution requires Linux bubblewrap and an installed Nmap under `/usr`; there is no unsandboxed fallback, script flag or arbitrary argument interface. Its fixed recipe performs TCP connect scanning only; it does not claim version/exploit confirmation. Tool-version recipes require approval and a no-network sandbox. A matching executable name is not proof of vendor identity, especially Python versus ProjectDiscovery `httpx`.

Custom workflows allow only typed local HTTP/static inspection, lexical KB search and report generation. They have no shell/model/scanner/network step. Previews bind input hashes and authorization state; changed files/scopes invalidate approval. No online CVE lookup, dynamic malware execution, debugger automation or general workflow programming language is included.

## Terminal controls

The initial screen is AI Research. Enter submits ordinary English; Send/Stop controls govern the current turn. Select an engagement and resume a saved conversation at the top. Review each proposed action before approving it. Other tabs provide recon, HTTP/API, engagement/findings/reports, knowledge/memory and fixed tool execution. CLI commands expose additional research and workflow operations.

F1–F5 open overview, inventory, model settings, authorization inventory and roadmap; Tab/Shift+Tab/arrows navigate widgets. `q` or Ctrl+Q exits; typing in a field does not invoke `q`. Errors, offline services, missing models and absent tools are visible states. No browser or graphical application is required.

## Data, backup and maintenance

Defaults: `~/.config/shadow/config.json`, `~/.local/share/shadow/shadow-cli.sqlite3`, and rotating logs under the data directory. Override roots with `SHADOW_CONFIG_DIR` and `SHADOW_DATA_DIR`. Linux permissions are restricted; data is not encrypted. The trusted OS account can alter local logs/database; audit records are not tamper-proof.

```bash
shadow backup /existing/private/directory/shadow-backup.sqlite3
shadow restore /existing/private/directory/shadow-backup.sqlite3
./upgrade.sh
./uninstall.sh
```

Restore requires confirmation and keeps a pre-restore safety snapshot. Stop other sessions before restore/upgrade. Uninstall removes only this checkout's generated environment and exact matching launcher; it preserves data, configuration, reports, research and source. No system settings or shell profiles are edited.

## Tests

```bash
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

See [validation](docs/VALIDATION.md), [architecture](docs/ARCHITECTURE.md), [security](docs/SECURITY.md) and [development status](docs/DEVELOPMENT_STATUS.md). Native Kali/Debian and minimum-Python compatibility still require dedicated acceptance runs; Ubuntu WSL and Windows are the environments exercised here.

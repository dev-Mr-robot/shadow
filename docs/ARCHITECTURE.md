# Integrated terminal architecture

SHADOW has one Python application, one SQLAlchemy/SQLite data layer, and two terminal entry surfaces: Typer and Textual. No separate website frontend/backend exists. Runtime entry point: `shadow.main:main`. The initial TUI is the conversational research workspace.

```text
Typer commands / Textual workspace
  -> typed service API
  -> semantic intent and context (Ollama, when requested)
  -> validated application action proposal
  -> immutable concrete preview + user approval
  -> deterministic scoped capability / adapter
  -> bounded parser + persistent evidence
  -> local explanation, citations and reports
```

## Implemented modules

| Module | Responsibility |
|---|---|
| main / *_cli | Direct commands, consistent runtime and terminal output |
| tui / workspace_ui | Keyboard navigation, chat, approvals, recon, HTTP, engagements/reports, KB/memory |
| config / runtime / diagnostics | Validated private local configuration, lifecycle logs, real hardware/tool discovery |
| database / migrations | SQLAlchemy repository, Alembic forward upgrades, audit and authorization |
| intelligence | Bounded local inference, semantic plans, context/history, clarification/results, summaries, stream leases and explicit memories |
| knowledge | Static bounded extraction, local chunks/vectors, citations and labeled lexical fallback |
| recon | Streaming imports, compiled scope policy, indexed inventory, frozen approved targets, rate/concurrency/time/body limits, checkpoints/history/diff |
| research | Static HTTP/Burp/API inspection, evidence hashes, finding invariants, source-tagged advisory cache, passive source/config/log/binary/PCAP triage |
| reporting | Immutable report snapshots and exclusive MD/HTML/PDF document exports |
| integrations | Fixed Nmap recipe, no-network version recipes, sandbox, stdout/stderr capture, cancellation and stale-owner recovery |
| actions | Separate deterministic preview/approval boundary for semantic proposals |
| workflows | Typed passive local pipelines; no arbitrary shell, model or network steps |
| backup | Consistent SQLite backups and confirmed restore with safety snapshot |

## Persistence and migrations

`0001_foundation` creates engagements and audit events. `0002_workspaces` adds indexed JSON-body workspace records for conversations, messages, memory, documents/chunks, evidence, findings, reports, action previews/results, stream leases, jobs and workflows. `0003_recon` adds indexed assets, runs, frozen run targets and immutable observation snapshots. The Phase 1-to-current upgrade is tested without loss of authorization data.

Every record has an application-owned UUID, creation/update timestamps and bounded typed service validation. Generic record storage does not imply model access to arbitrary tables. SQLAlchemy statements bind values; only fixed application SQL is used. SQLite WAL and short transactions support ongoing work. Destructive downgrade is disabled. Run one schema upgrade at a time; cross-process package upgrades are not orchestrated.

## Conversation and action contracts

`ConversationService` supplies new/history/context/plan/stream/summarize plus explicit memory CRUD. Compact planner context puts engagement/recon counts first, then bounded evidence IDs and current results, so large imports do not crowd out essential state. Response context reserves room for prior dialogue and retrieves cited chunks. Conversation stream leases use deterministic IDs and atomic SQLite acquisition, PID/create-time ownership, expiry and token-matched release.

Capability negotiation reads model metadata; native `plan_research` function arguments or schema/JSON fallback output must validate against Pydantic before use. No regex-only intent router or arbitrary shell action exists. The separate `ActionRunner` binds concrete details to a digest/expiry and consumes approval once. A Nmap proposal creates a command preview; command execution requires its own approval. Approved results are stored with application provenance for later references. Imported content always remains untrusted user-context data, never a system instruction or approval.

## Recon and scale

Imports read bounded lines and batch inserts, deduplicating through a unique engagement/host index. Exact scope hosts are compiled into sets instead of quadratic domain comparisons. Network run previews freeze target rows on disk and bind the asset/scope/rules/authorization digest. Execution requires a separate approval; later imports cannot expand an approved target list.

DNS and root HTTP probes share configurable concurrency/rate/time limits; HTTP connects to one authorized pinned address with original Host/SNI. Both hostname and destination IP/CIDR authorization are required. Redirects/links are observations, never followed. Encoded bodies are omitted, raw body capture is capped. Per-asset checkpoints survive cancellation; history compares only observations actually recorded in each run. Pagination/export avoid materializing the entire inventory.

## Extensibility and limits

Services are separated by capability and can gain deeper adapters without changing the terminal entry points. Current professional-tool execution is intentionally narrow: fixed Nmap TCP connect scans and version-only recipes. Other integrations import output and report availability. Online CVE feeds, general scanner recipes, interactive debugger execution and dynamic malware analysis remain absent rather than hidden behind nonfunctional controls. Static research and passive typed workflows provide working advanced functionality while those boundaries remain explicit.

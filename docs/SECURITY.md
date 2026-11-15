# Security boundaries

SHADOW is a single-user local terminal application. It opens no application web port and has no graphical interface. The OS account, installed Python packages, configured Ollama service and system tool binaries are trusted. Model text, imported evidence, documents, targets and workflow definitions are untrusted.

## Execution and scope

- Semantic output must validate as a bounded Pydantic plan. There is no shell capability, eval bridge or autonomous execution loop.
- Concrete previews bind exact parameters, input/target state, digest and expiry; separate explicit approval is consumed once. Clarifications have no actions.
- Exact host/IP/CIDR scope and exclusions govern imports and operations. Parent domains do not imply wildcard authorization. Active HTTP requires separately authorized destination IP/CIDR as well as hostname. Scope changes invalidate plans and are checked during active probing.
- Recon has frozen disk-backed targets, bounded concurrency/rate/retries/time/raw body size, no redirects/crawling, and cancellation/checkpointing. System DNS resolver threads may outlive coroutine cancellation, though later HTTP work is cancelled.
- Nmap supports only the fixed unprivileged TCP-connect recipe: no NSE, version probing, arbitrary flags, sudo or model shell. Linux bubblewrap confines filesystem/user/process access; host networking remains available for the scoped scan. It is not an egress firewall or malware VM. Missing sandbox/tool fails closed.
- Approved fixed version recipes use a no-network bubblewrap namespace. Executable output is evidence, not proof of vendor identity. Other tool integrations are output-review adapters.
- Passive workflows are schema-bound local inspection/lexical-search/report steps. They cannot run scanners, model requests, arbitrary Python or shell. Approved file hashes and scope signatures are rechecked before use.

## Data and AI

Local directories/files have restrictive Linux permissions; SQLite data is unencrypted. Configuration validates loopback origins, rejects ambiguous URLs and saves atomically. Direct config/database/log symlinks are refused; hostile parent directories and same-account mutation remain outside the protection boundary.

Conversation history persists; do not paste secrets. Durable research memories require explicit saves/approval and support inspect/edit/delete. Summaries are model-generated and may lose nuance; full persisted messages remain available. Per-conversation leases prevent independent terminal instances from interleaving streams. Imported evidence and retrieved chunks are kept out of system instructions and cannot grant scope or approvals. Prompt-injection defenses are mitigations, not guarantees about model output quality.

Evidence stores text/metadata and original-byte hashes, not original bytes. Findings default to hypotheses. Confirmed/remediated labels require supplied evidence; CVSS requires justification. These are operator assertions, not independent verification. Reports escape untrusted content, never fetch embedded links/images, preserve labels and use exclusive output writes. Report snapshots are immutable records.

PDF extraction runs in a thread with file/page/text limits, without a hard parser process sandbox. ZIP expansion/XML entities are bounded/blocked for DOCX/Burp/XML. Crafted parser inputs can still consume resources. Static binary/PCAP analysis never executes samples but is not a substitute for a malware-analysis VM.

## Operations and residual risks

Ollama and optional tool binaries are separately administered. SHADOW cannot control their own configurations or protect against a malicious replacement. No hidden online advisory requests are made; CVE research imports source/date-tagged claims only. Local model generation, embeddings and approved target traffic are explicit capabilities.

Audit/lifecycle logs are local and not tamper-proof against the account owner. No encryption-at-rest or multi-user authentication is claimed. Database restore requires confirmation and keeps a safety snapshot; stop other sessions before restore/package/schema upgrade. Native distribution installation and minimum-Python coverage remain acceptance work. Do not expose the data directory or run the application as root.

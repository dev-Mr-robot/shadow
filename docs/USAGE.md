# Working command examples

All commands operate in the terminal. Use `--help` on every group/command to inspect supported options. Example identifiers and addresses below are illustrative; they are not imported into production data.

## Findings

Select an engagement, then save a local JSON file:

```json
{
  "name": "Authorization boundary needs validation",
  "asset": "https://lab.example.test/api/items/123",
  "severity": "Informational",
  "verification": "hypothesis",
  "description": "Record the actual observation and the uncertainty here.",
  "evidence": "Paste authentic technical evidence, not an invented example.",
  "reproduction": "Describe the authorized test accounts and steps.",
  "impact": "Unverified until the boundary is tested.",
  "remediation": "Document recommendations justified by the evidence."
}
```

`shadow finding add finding.json` supplies the active engagement ID. Affected host must be in scope. `shadow finding update ID patch.json` preserves engagement ownership. Confirmed/remediated status requires evidence or linked evidence imports; CVSS requires `cvss_justification`, and CWE uses `CWE-NUMBER`. `workflow_status` is `needs_investigation`, `potential_vulnerability`, `verified_vulnerability`, `reported`, or `resolved`; the last three require confirmed/remediated verification.

## Passive workflows

```json
{
  "version": 1,
  "name": "Local evidence review",
  "steps": [
    {"capability": "http_inspect", "input_file": "request.txt"},
    {"capability": "static_analyze", "input_file": "sample.py", "kind": "python"},
    {"capability": "kb_search", "query": "authorization methodology"},
    {"capability": "report_generate", "format": "md"}
  ]
}
```

Paths resolve relative to the definition file. HTTP messages must identify authorized target hosts; raw responses need an explicit `target` in the step. Importing reads only the definition. `shadow workflow preview ID` reads bounded inputs and displays hashes, ordered steps and report destination. `shadow workflow run PREVIEW --digest DIGEST` asks for exact approval and rechecks file/scope state. Shell, DNS, scanners, model requests and arbitrary Python steps are rejected.

## SOC logs, alerts and incidents

```bash
shadow soc ingest auth.log --format syslog --year 2026
shadow soc ingest events.jsonl --format jsonl
shadow soc ingest windows-export.xml --format windows_xml
shadow soc stats
shadow soc logs --type auth_failure --since 2026-11-15T00:00:00Z
shadow soc detect
shadow soc alerts list --severity High
shadow soc alerts show ALERT_ID
shadow soc alerts related ALERT_ID
shadow soc alerts update ALERT_ID --status TRIAGED --note "Document actual investigation"
shadow soc incident create "Investigation title" --alert ALERT_ID --type brute_force
shadow soc incident timeline INCIDENT_ID
shadow soc incident update INCIDENT_ID --status TRIAGED --note "Observed evidence"
shadow soc report INCIDENT_ID --format md --output incident.md
shadow soc report INCIDENT_ID --format pdf --output incident.pdf
shadow soc ask "Explain the actual recent alerts and cite event IDs."
```

Format values are `auto`, `json`, `jsonl`, `suricata`, `zeek`, `csv`, `syslog`, `windows_xml` (use the underscore value for `--format`). Raw EVTX is not parsed: export it to a supported format first. Large datasets should use JSONL/CSV/text; Windows XML and JSON arrays are bounded to16MiB. Timestamp assumptions are stored per event.

Alert/incident lifecycle advances NEW → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED. False-positive alert closure is an explicit exception requiring a note. Contained is operator-recorded workflow status, never proof that SHADOW isolated a host. Incident action logs are metadata only.

## Detection engineering

```json
{
  "name": "Review a locally defined command indicator",
  "event_type": "process",
  "field": "fields.process",
  "contains": ["organization-specific indicator"],
  "severity": "Medium",
  "confidence": 0.5,
  "threshold": 1,
  "window_seconds": 300,
  "group_by": "host"
}
```

```bash
shadow soc rule import rule.json
shadow soc rule list
shadow soc rule test RULE_ID EVENT_ID
shadow soc rule edit RULE_ID patch.json
shadow soc rule enable RULE_ID --disabled
shadow soc rule export RULE_ID rule-copy.json
shadow soc rule history
shadow soc rule coverage
```

Rule expressions are bounded literals, not executable Python or arbitrary regex. The Sigma YAML subset supports `condition: selection` with one literal equals/contains field; unsupported conditions/modifiers are rejected. Imported rule versions and execution history remain inspectable. Fixed time buckets can miss patterns at a bucket boundary; tuning requires real baseline/false-positive review.

## Local intelligence and ATT&CK

```bash
shadow soc ioc add ip 198.51.100.10 --source "My reviewed local feed" --date 2026-11-15 --confidence 0.5
shadow soc ioc enrich 198.51.100.10
shadow soc ioc import indicators.json
shadow soc attack search T1110.001
shadow soc attack import enterprise-attack.json --source https://github.com/mitre/cti --version YOUR_REVIEWED_COMMIT_OR_RELEASE
shadow soc network
shadow soc sensors
shadow soc pcap local-capture.pcap
shadow soc settings --retention-days 90 --event-limit 200000
shadow soc retention 2026-01-01T00:00:00Z
```

IOC feed JSON is a list with `type`, `value`, `source`, `source_date` and optional `confidence`, `reputation`, `actor_reference`. No private logs or indicators are sent to an external provider. Source-supplied reputation is not independent verification. ATT&CK ships a small sourced/versioned subset and can import a reviewed official STIX bundle; it does not pretend to bundle the entire catalog. Packet analysis is classic-PCAP metadata; encrypted contents are not inferred. Retention first shows an exact count and requires confirmation; take a backup first.

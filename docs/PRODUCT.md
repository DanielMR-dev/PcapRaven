# Product Definition

## Identity and Status

PcapRaven is a new, independent, offline-first network forensics and
threat-hunting command-line application written in Rust.

Phase 0 product definition and engineering foundation, Phase 1 workspace
tooling, Phase 2 capture reader, Phase 3 packet normalization, Phase 4
bidirectional flow reconstruction, Phase 5 flow statistics and exact
temporal metrics, Phase 6 initial functional CLI with streaming
capture and flow inspection, Phase 7 bounded DNS protocol analysis,
Phase 8 bounded HTTP/1.x protocol analysis, Phase 9 bounded visible
TLS 1.2 / TLS 1.3 handshake metadata analysis, Phase 10 unified protocol
observations and structured evidence foundation, Phase 11 detection engine architecture,
Phase 12 explainable periodic beaconing detection, Phase 13 explainable DNS anomaly and possible tunneling detection,
Phase 14 explainable repeated low-volume flow behavior and finding correlation,
Phase 15 finding classification, filtering, and MITRE ATT&CK mapping provenance,
Phase 16 deterministic reporting architecture (Table, JSON, NDJSON, CSV), safe output files, unified `analyze` CLI,
and Phase 17 synthetic fixtures, golden reports, and end-to-end integration testing are complete.
Phase 18 robustness and performance verification is complete. Phase 19 release
code-health audit and targeted behavior-preserving internal refactoring is
current and in progress; it adds no product feature semantics. Phases 20
through 28 are future and not implemented.

## Problem Statement

Packet captures contain valuable evidence but are difficult to inspect at
scale. Analysts often need several tools and ad hoc scripts to connect packet
metadata, bidirectional communications, protocol behavior, and security
signals. Those workflows can be hard to reproduce and can expose sensitive
captures to network services.

PcapRaven is intended to provide a local, reproducible workflow that ingests
PCAP and PCAPNG files, normalizes traffic, reconstructs bidirectional flows,
extracts selected protocol metadata, and produces explainable observations and
heuristic findings. It will help an analyst prioritize investigation; it will
not replace analyst judgment.

## Intended Users

- Incident responders examining packet captures from affected environments.
- Threat hunters looking for suspicious temporal or protocol behavior.
- Network defenders triaging captures without uploading them to a service.
- Researchers who need deterministic, machine-readable analysis artifacts.

## Goals

- Analyze PCAP and PCAPNG captures locally and offline by default.
- Treat captures as untrusted input and fail safely on malformed content.
- Normalize packet metadata into stable domain concepts.
- Reconstruct bidirectional flows and calculate explainable statistics.
- Extract DNS, HTTP/1.x, and TLS handshake metadata without claiming access to
  encrypted application payloads.
- Separate capture ingestion, protocol parsing, flow analysis, detection,
  reporting, and command-line concerns.
- Produce deterministic human-readable and machine-readable output.
- Tie each security finding to concrete evidence and affected traffic.
- Describe heuristic results with calibrated language, severity, and
  confidence.
- Support robust testing with synthetic fixtures, property tests, fuzzing, and
  a regression corpus.

## Non-Goals

- Live capture, packet injection, active scanning, or traffic modification.
- Network prevention, blocking, or automated incident response.
- Uploading captures, telemetry, cloud enrichment, or network access by
  default.
- Payload decryption, key recovery, malware classification, or attribution.
- Claiming that a heuristic proves malware, command-and-control activity, or a
  specific adversary.
- Full support for every link type, encapsulation, protocol, or application
  version in v1.0.0.
- A graphical user interface, server, daemon, or hosted service in v1.0.0.
- Compatibility with NetSentinel APIs, data formats, architecture, or source
  code.

## Product Principles

### Offline and Private

PcapRaven performs no external network requests by default. It has no
telemetry and does not upload captures. Capture contents and derived metadata
may be sensitive and remain local unless the user explicitly moves or shares
requested output outside the application.

### Explainable

Normalized observations remain distinct from detector conclusions. A finding
states what was observed, which detector produced the finding, why the detector
matched, and which evidence supports the result.

### Deterministic

Given the same PcapRaven version, options, and input bytes, analysis and
machine-readable output should be stable. Any unavoidable environmental or
nondeterministic values must be excluded from deterministic result content or
clearly identified.

### Conservative

Malformed records should produce bounded diagnostics and permit continued
analysis when safe. Unsupported input is not equivalent to malicious input.
Heuristic behavior is described as possible or suspicious, not as proof.

## Implemented CLI Contract (Phase 16)

The functional CLI is implemented in `pcapraven-cli` and provides:

```text
pcapraven analyze <capture> [--max-records <N>] [--max-flows <N>] [--max-flow-instances <N>] [--max-observations <N>] [--tcp-idle-timeout <SECONDS>] [--udp-idle-timeout <SECONDS>] [--min-severity <LEVEL>] [--min-confidence <LEVEL>] [--detector <ID>] [--mitre <ID>]
pcapraven validate <capture> [--max-records <N>]
pcapraven flows <capture> [--max-records <N>] [--max-flows <N>] [--max-flow-instances <N>] [--tcp-idle-timeout <SECONDS>] [--udp-idle-timeout <SECONDS>]
pcapraven dns <capture> [--max-records <N>]
pcapraven http <capture> [--max-records <N>]
pcapraven tls <capture> [--max-records <N>]
pcapraven findings <capture> [--max-records <N>] [--max-flows <N>] [--max-flow-instances <N>] [--max-observations <N>] [--tcp-idle-timeout <SECONDS>] [--udp-idle-timeout <SECONDS>] [--min-severity <LEVEL>] [--min-confidence <LEVEL>] [--detector <ID>] [--mitre <ID>]
pcapraven --help
pcapraven --version
pcapraven --format <table|json|ndjson|csv> <subcommand> <capture>
pcapraven --output <path> <subcommand> <capture>
pcapraven --quiet <subcommand> <capture>
```

### Implemented Command Summary

| Command | Current Implemented Behavior |
| --- | --- |
| `analyze` | Unified forensic capture analysis across metadata, flows, protocol observations, and analytical security findings. Supported formats: `table`, `json`, `ndjson`. (`csv` returns exit code 2 as hierarchical multi-section analysis cannot be flattened into a single flat CSV). |
| `validate` | Streams capture records through the safe reader, validating container integrity, sections, interfaces, linktypes, and timestamp resolutions. Emits factual metadata and diagnostics. |
| `flows` | Streams capture records through packet normalization and flow reconstruction, emitting closed bidirectional flow records and factual traffic/temporal statistics. |
| `dns` | Streams capture records through packet normalization and DNS parser, emitting normalized DNS observations. |
| `http` | Streams capture records through packet normalization and HTTP/1.x parser, emitting normalized cleartext HTTP observations. |
| `tls` | Streams capture records through packet normalization and TLS parser, emitting normalized visible TLS handshake metadata observations. |
| `findings` | Runs detection engine heuristics and cross-detector correlators over normalized flows and observations, applying multi-criteria filters (`--min-severity`, `--min-confidence`, `--detector`, `--mitre`), emitting findings and referenced evidence closure. |

### Implemented Exit Codes

- `0`: Successful complete command execution.
- `1`: Fatal input, I/O, or analysis failure before any useful result was produced.
- `2`: Usage or configuration error (invalid flags, missing arguments, limit errors, collision on existing `--output` file, or unsupported `analyze --format csv`).
- `3`: Useful result produced, but analysis/validation was partial (e.g. flow exclusions, degraded temporal metrics, capture recovery/truncation, partial protocol parse, or packet budget reached).

### Implemented Formats

- `table`: Formatted interactive human-readable output (default).
- `json`: Pretty-printed single structured JSON document following the frozen `v1.0` schema.
- `ndjson`: Stream-oriented newline-delimited JSON where each line is a self-describing tagged envelope (`{"schema_version": "v1.0", "kind": "...", "record_type": "...", "data": { ... }}`).
- `csv`: Flat, tabular comma-separated values with strict LF (`\n`) terminators and CSV formula injection protection.

### Implemented Global Options

| Option | Implemented Contract |
| --- | --- |
| `--output <path>` | Atomically creates the destination file with `create_new(true)`. Returns exit code 2 if the file already exists. Flushes explicitly and cleans up on write failure. |
| `--format <format>` | Selects `table`, `json`, `ndjson`, or `csv`. |
| `--quiet` | Suppresses non-error stderr diagnostics; requested stdout result is unaffected. |
| `--min-severity <level>` | Filters findings by minimum severity (`info`, `low`, `medium`, `high`, `critical`). |
| `--min-confidence <level>` | Filters findings by minimum confidence (`low`, `medium`, `high`). |
| `--detector <id>` | Filters findings by exact detector ID (e.g., `dns.possible_tunneling`). |
| `--mitre <id>` | Filters findings by MITRE ATT&CK technique or tactic ID (e.g., `T1071.004`). |

## v1 Success Criteria

Version 1.0.0 is reached only after all phases in [the roadmap](ROADMAP.md) are
complete. A successful v1 safely handles the documented capture subset,
provides the target inspection and finding workflows, emits supported formats,
and passes the quality and robustness gates in [Testing](TESTING.md).

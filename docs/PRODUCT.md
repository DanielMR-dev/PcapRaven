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
Phase 12 explainable periodic beaconing detection, and Phase 13 explainable DNS anomaly and possible tunneling detection are complete. Further
threat detection heuristics, correlation, and advanced reporting remain targets for later roadmap phases.

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

## Current Implemented CLI Contract

The functional CLI is implemented in `pcapraven-cli` and provides:

```text
pcapraven validate <capture> [--max-records <N>]
pcapraven flows <capture> [--max-records <N>] [--max-flows <N>] [--max-flow-instances <N>] [--tcp-idle-timeout <SECONDS>] [--udp-idle-timeout <SECONDS>]
pcapraven dns <capture> [--max-records <N>]
pcapraven http <capture> [--max-records <N>]
pcapraven tls <capture> [--max-records <N>]
pcapraven --help
pcapraven --version
pcapraven --quiet <subcommand> <capture>
```

### Implemented Command Summary

| Command | Current Implemented Behavior |
| --- | --- |
| `validate` | Streams capture records through the safe reader, validating container integrity, sections, interfaces, linktypes, and timestamp resolutions. Emits factual summary to stdout. |
| `flows` | Streams capture records through packet normalization and flow reconstruction, immediately emitting closed bidirectional flow records and factual traffic/temporal statistics to stdout in tabular format. |
| `dns` | Streams capture records through packet normalization and DNS parser, immediately emitting normalized DNS observations to stdout in tabular format. |
| `http` | Streams capture records through packet normalization and HTTP/1.x parser, immediately emitting normalized cleartext HTTP observations to stdout in tabular format. |
| `tls` | Streams capture records through packet normalization and TLS parser, immediately emitting normalized visible TLS handshake metadata observations to stdout in tabular format. |

### Implemented Exit Codes

- `0`: Successful complete command execution.
- `1`: Fatal input, I/O, or analysis failure before any useful result was produced.
- `2`: Usage or configuration error (invalid flags, missing arguments, limit errors).
- `3`: Useful result produced, but analysis/validation was partial (e.g. flow exclusions, degraded temporal metrics, capture recovery/truncation, partial protocol parse).

### Implemented Stream Separation

- `stdout`: Requested factual summary or table only. No ANSI color.
- `stderr`: Nonfatal diagnostics (budgeted to 100 lines default, suppressed summary unless `--quiet`) and fatal errors.

## Target v1 CLI Contract

The expanded CLI described below is a target for later roadmap phases. Higher-level
commands (`analyze`, `findings`) and machine-readable formats (`json`, `ndjson`, `csv`)
are not yet implemented.

```text
pcapraven analyze <capture>
pcapraven flows <capture>
pcapraven dns <capture>
pcapraven http <capture>
pcapraven tls <capture>
pcapraven findings <capture>
pcapraven validate <capture>
```

### Target Command Intent

| Command | Intended result |
| --- | --- |
| `analyze` | Run the available analysis pipeline and emit a unified result. |
| `flows` | Inspect reconstructed bidirectional flows and statistics. |
| `dns` | Inspect normalized DNS observations. |
| `http` | Inspect normalized HTTP/1.x metadata observations. |
| `tls` | Inspect normalized TLS handshake metadata observations. |
| `findings` | Run and display applicable security findings. |
| `validate` | Validate capture structure and report recoverable and fatal input problems. |

### Target Formats

- `table` for interactive human-readable output.
- `json` for one structured document.
- `ndjson` for stream-oriented structured records.
- `csv` for flat, command-appropriate records.

Not every domain shape can be represented losslessly in CSV. Commands that
offer CSV must define a stable, documented row schema and reject ambiguous
requests rather than silently discard required information.

### Target Global Options

| Option | Intended contract |
| --- | --- |
| `--output <path>` | Write requested result output to a file instead of stdout. Refuse unsafe ambiguity or unintended overwrite according to the future CLI specification. |
| `--format <format>` | Select `table`, `json`, `ndjson`, or `csv` where supported. |
| `--no-color` | Disable color and presentation escape sequences. Machine formats never contain color. |
| `--quiet` | Suppress non-error diagnostics; requested result output is unaffected. |
| `-v`, `-vv` | Increase diagnostic verbosity without changing result semantics. |
| `--min-severity <level>` | Filter findings below the selected severity. |
| `--min-confidence <level>` | Filter findings below the selected confidence. |

Severity and confidence filters apply to findings, not raw observations.
Invalid combinations must produce a usage error rather than being ignored.

## v1 Success Criteria

Version 1.0.0 is reached only after all phases in [the roadmap](ROADMAP.md) are
complete. A successful v1 safely handles the documented capture subset,
provides the target inspection and finding workflows, emits supported formats,
and passes the quality and robustness gates in [Testing](TESTING.md).

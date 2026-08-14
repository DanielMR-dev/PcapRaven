# Product Definition

## Identity and Status

PcapRaven is a new, independent, offline-first network forensics and
threat-hunting command-line application written in Rust.

Phase 0 product definition and engineering foundation and Phase 1 workspace
tooling are complete. Phase 2 currently provides a bounded library-only
PCAP/PCAPNG container reader. The repository still does not contain a working
analysis application or functional CLI; protocol normalization and later
analysis phases remain future work.

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
- Protocol decoding, normalized packet/domain records, flow reconstruction,
  detection, reporting, or functional CLI behavior during Phase 2. The Phase 2
  reader is limited to capture-container metadata, bounded packet bytes, and
  capture-level diagnostics; the binary remains a compile-only skeleton.

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

## Target v1 CLI Contract

The CLI described here is a target for later roadmap phases. None of these
commands or options is implemented in Phase 2; the binary skeleton accepts no
arguments and emits no output.

```text
pcapraven analyze <capture>
pcapraven flows <capture>
pcapraven dns <capture>
pcapraven http <capture>
pcapraven tls <capture>
pcapraven findings <capture>
pcapraven validate <capture>
```

### Command Intent

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

### I/O Contract

- Stdout is reserved for requested result output.
- Diagnostics and logs use stderr through the logging policy in
  [Architecture](ARCHITECTURE.md#logging-policy).
- Machine-readable stdout must not be contaminated by progress, warnings, or
  logs.
- Output file failures must not fall back to stdout silently.
- User-controlled strings must be encoded or escaped for the selected format
  and safe terminal presentation.
- Partial analysis must be visibly represented through diagnostics and result
  metadata; it must not appear indistinguishable from complete analysis.

### Exit Status Categories

Exact numeric exit codes will be finalized with the CLI in Phase 6. The v1
contract will distinguish at least success, usage/configuration failure, input
or I/O failure, and analysis completed with a policy-relevant partial or
validation outcome. The presence of a security finding is not, by itself, an
application failure.

## v1 Success Criteria

Version 1.0.0 is reached only after all phases in [the roadmap](ROADMAP.md) are
complete. A successful v1 safely handles the documented capture subset,
provides the target inspection and finding workflows, emits supported formats,
and passes the quality and robustness gates in [Testing](TESTING.md).

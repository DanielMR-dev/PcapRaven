---
name: cli-contract
description: Use for PcapRaven command-line interface design, argument validation, streaming orchestration, stdout/stderr boundaries, and exit status contracts.
---

# CLI Contract Skill

This skill governs the design, implementation, review, and verification of
the `pcapraven-cli` orchestration boundary and command-line interface.

## Core Responsibilities

- `pcapraven-cli` is the sole binary orchestrator in the workspace.
- It owns argument parsing, filesystem interaction, streaming library execution,
  stdout/stderr separation, exit-code translation, and bounded human inspection rendering.
- Analysis libraries (`pcapraven-pcap`, `pcapraven-protocols`, `pcapraven-flows`)
  must remain independent and never open files, parse CLI arguments, or make exit decisions.

## Invariants and Rules

### 1. Implemented Commands
- `pcapraven validate <capture>`, `pcapraven flows <capture>`, `pcapraven dns <capture>`, `pcapraven http <capture>`, `pcapraven tls <capture>`, `pcapraven findings <capture>`, and `pcapraven analyze <capture>` are implemented.
- Multi-format output (`--format <table|json|ndjson|csv>`) and safe file output (`--output <PATH>`) are supported across subcommands.
- `pcapraven analyze --format csv` is unsupported and rejected with exit code 2.
- `pcapraven --help` and `pcapraven --version` are fully functional.

### 2. Argument and Limits Validation
- Local capture paths only. No URLs, S3, cloud storage, stdin, glob expansion, or live capture.
- Configured limits (`--max-records`, `--max-flows`, `--max-flow-instances`, `--tcp-idle-timeout`,
  `--udp-idle-timeout`) are validated against library builder safety bounds.
- Invalid configuration or usage errors immediately exit with code 2.

### 3. Exit Code Contract
- `0`: Successful complete command execution.
- `1`: Fatal input, I/O, or analysis failure before any useful result.
- `2`: Usage or configuration error (e.g. invalid arguments, malformed limits).
- `3`: Useful result produced, but analysis/validation was partial (e.g. flow exclusions,
  degraded temporal metrics, capture recovery/partial termination).

### 4. Output Stream Separation
- `stdout`: Strictly requested factual result output only (validation summary or flow table).
  No diagnostics, warnings, or debug messages.
- `stderr`: Strictly diagnostics, warnings, and fatal error messages.
  No flow table rows or validation summaries.
- Zero ANSI escape sequences / color codes.

### 5. Diagnostic Bounding and Quiet Mode
- Stderr nonfatal diagnostic output is bounded by a strict display budget (default 100 lines).
- When the budget is exceeded, a single summary line reports suppressed messages unless quiet.
- `--quiet` suppresses nonfatal stderr diagnostics and suppression summaries completely,
  while preserving fatal errors, exit codes, and stdout result content identically.

### 6. Streaming Pipeline & Memory Non-Retention
- Normal execution must stream records incrementally via `CaptureReader::next_record()`.
- Never retain all `CaptureRecord`, `NormalizedPacket`, or completed `FlowRecord` instances in memory.
- Closed flows stream to stdout immediately as lifecycle boundaries trigger.

### 7. Truthful Finalization
- Clean end-of-input finalizes active flows with `FlowEndReason::EndOfInput`.
- Early/abnormal termination with useful flow state finalizes active flows with
  `FlowEndReason::AnalysisStopped` via `reconstructor.finish_partial()`.
- Abnormal termination must never masquerade as clean `EndOfInput`.

### 8. Factual Flow Presentation
- Flow table presents transport-level facts only (numeric ports, canonical endpoints A/B).
- Never guess client/server roles, application protocol names (e.g. port 443 as HTTPS), or
  threat classifications (no "suspicious", "C2", or severity/confidence columns).
- Durations and temporal metrics are displayed exactly without floating-point conversion.

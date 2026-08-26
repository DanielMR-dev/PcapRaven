---
name: cli-contract
description: Use for PcapRaven command-line interface design, argument validation, streaming orchestration, stdout/stderr boundaries, and exit status contracts.
---

# CLI Contract Skill

This skill governs the design, implementation, review, and verification of
the `pcapraven-cli` orchestration boundary and command-line interface.
The canonical compatibility specification is
`docs/CLI_V1_CONTRACT.md`; this skill provides the engineering and review
procedure and must not become a competing specification.

## Core Responsibilities

- `pcapraven-cli` is the sole binary orchestrator in the workspace.
- It owns argument parsing, filesystem interaction, streaming library execution,
  stdout/stderr separation, exit-code translation, and bounded human inspection rendering.
- Analysis libraries (`pcapraven-pcap`, `pcapraven-protocols`, `pcapraven-flows`)
  must remain independent and never open files, parse CLI arguments, or make exit decisions.

## Invariants and Rules

### 1. Frozen Commands and Options
- The seven frozen product commands are `validate`, `flows`, `dns`,
  `http`, `tls`, `findings`, and `analyze`.
- The only global options are `-q/--quiet`, `--format`, and
  `-o/--output`. The findings/analyze filters are command-specific.
- Resource options remain command-specific: `--max-records`,
  `--max-flows`, `--max-flow-instances`, `--max-observations`,
  `--tcp-idle-timeout`, and `--udp-idle-timeout`.
- The exact command/format matrix, aliases, defaults, accepted values, and
  placements are owned by `docs/CLI_V1_CONTRACT.md`.
- `pcapraven analyze --format csv` is unsupported and rejected with exit code
  2. `pcapraven --help`, `pcapraven help`, `pcapraven --version`, and
  their frozen aliases remain functional.

### 2. Argument and Limits Validation
- Local capture paths only. No URLs, S3, cloud storage, stdin, glob expansion, or live capture.
- Configured limits (`--max-records`, `--max-flows`, `--max-flow-instances`, `--tcp-idle-timeout`,
  `--udp-idle-timeout`) are validated against library builder safety bounds.
- Parser storage types are `u64` for `--max-records`, `usize` for
  `--max-flows`, `--max-flow-instances`, and `--max-observations`, and
  `u32` for both idle timeouts. Preserve the downstream conversion and
  architecture-dependent `usize` behavior documented by the canonical
  contract.
- Findings/analyze filters are `--min-severity`, `--min-confidence`,
  `--detector`, and `--mitre`. Canonical values are documented there;
  undocumented domain-parser tolerance is not a public compatibility promise.
- Invalid configuration or usage errors immediately exit with code 2.

### 3. Exit Code Contract
- `0`: Successful complete command execution.
- `1`: Fatal input, I/O, or analysis failure before any useful result.
- `2`: Usage or configuration error (e.g. invalid arguments, malformed limits).
- `3`: Useful result produced, but analysis/validation was partial (e.g. flow exclusions,
  degraded temporal metrics, capture recovery/partial termination).

### 4. Output Stream Separation
- `stdout`: Strictly the requested report, help, or version result. No
  diagnostics, warnings, progress, or debug messages.
- `stderr`: Strictly diagnostics, warnings, and fatal error messages.
  Usage text is also on stderr for parser/configuration failures. No report
  rows or report payload is written there.
- Zero ANSI escape sequences / color codes.

### 5. Diagnostic Bounding and Quiet Mode
- Stderr nonfatal diagnostic output is bounded by a strict display budget (default 100 lines).
- When the budget is exceeded, a single summary line reports suppressed messages unless quiet.
- `--quiet` suppresses nonfatal stderr diagnostics and suppression summaries completely,
  while preserving fatal errors, exit codes, and stdout result content identically.

### 6. Streaming Pipeline & Bounded Memory Policy
- Capture records are streamed incrementally via `CaptureReader::next_record()`.
- Never bulk-retain raw `CaptureRecord` streams, unbounded packet payloads, or unbounded `NormalizedPacket` instances.
- When evaluating detectors, finding correlation, or generating unified analysis reports, finite bounded vectors of canonical `FlowRecord`s and `ProtocolObservation`s may be retained subject to configured capacity limits (`--max-flows`, `--max-flow-instances`, `--max-observations`).
- Capture payload bytes are released immediately upon normalization.

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

### 9. Output Files and Input Sources
- `--output/-o` uses exclusive create-new semantics. Never overwrite an
  existing file, create parent directories, or add a force option.
- Existing-file collisions are exit 2; creation and render/flush failures are
  exit 1. A newly created file is removed when a later render or flush fails
  where removal is possible. Successful file output leaves stdout empty.
- `CAPTURE` is a local filesystem path. Do not add implicit stdin, URL,
  cloud-object, live-interface, or glob input.
- Preserve the standard `--` option terminator behavior for positional
  capture paths.

### 10. Frozen Compatibility Policy
- After Phase 21, removing or renaming a command or public option, removing a
  short alias, changing option scope, canonical values, defaults, format
  compatibility, exit categories, stream placement, quiet semantics, output
  collision behavior, requiredness, or local-only input is an incompatible
  change.
- A release-blocking security correction that requires such a break must
  explicitly reopen the Phase 21 decision with user approval. Do not hide it
  in a later phase.
- Consult `docs/CLI_V1_CONTRACT.md` for the authoritative exact wording and
  compatibility list.

### 11. Contract Verification Procedure
- Read `docs/CLI_V1_CONTRACT.md` before changing CLI declarations or
  orchestration.
- Generate candidate help, usage, and error output outside the canonical
  snapshot tree; inspect it byte-for-byte before accepting snapshots.
- Keep CLI surface snapshots in `tests/cli_contract/` and report payload
  goldens in `tests/golden/`. Do not substitute one for the other.
- Maintain `crates/pcapraven-cli/tests/contract.rs` for the frozen surface,
  including help/version, scope, aliases, placement, format matrix, defaults,
  exit states, streams, quiet mode, diagnostics, and output files.
- Run the workspace architecture inventory, formatting, lint, locked tests,
  schema contract, unchanged report goldens, documentation, fixture,
  robustness, security/supply-chain, and cross-platform checks required by
  `phase-validation`.
- If production CLI source changes, apply the conditional Phase 18
  performance rerun requirement before acceptance.

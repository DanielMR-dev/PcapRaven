# PcapRaven v1 CLI Contract

## Scope

This document is the detailed compatibility contract for the PcapRaven
command-line boundary. It freezes the existing command names, public options,
option scope, aliases, defaults, accepted canonical values, format matrix,
help and version behavior, exit statuses, stream semantics, diagnostics, and
safe output-file lifecycle.

Product purpose and high-level command behavior remain owned by
[PRODUCT.md](PRODUCT.md). Report formats and machine-readable schemas remain
owned by [REPORTING.md](REPORTING.md). This document references the existing
report schema version where necessary but does not finalize or duplicate that
schema.

## Compatibility Status

Phase 21 freezes the implemented CLI surface before later release and schema
work. The contract is versioned with the repository and is not a promise that
PcapRaven is already v1.0.0 or release-ready.

## Binary Name

The binary is named pcapraven. The user-facing version output is generated from
the package version and has the form:

pcapraven <package-version>

The contract does not freeze platform-specific package names or release
artifacts.

## Command Inventory

The seven product commands are:

| Command | Contract |
| --- | --- |
| validate CAPTURE | Validate local capture structure and factual metadata. |
| flows CAPTURE | Reconstruct bidirectional flows and report factual traffic and temporal statistics. |
| dns CAPTURE | Inspect normalized DNS observations. |
| http CAPTURE | Inspect cleartext HTTP/1.x message headers. |
| tls CAPTURE | Inspect visible TLS 1.2 and TLS 1.3 handshake metadata. |
| findings CAPTURE | Inspect analytical findings and apply the finding filters. |
| analyze CAPTURE | Run the unified multi-layer capture analysis and report flows, observations, findings, and evidence. |

The standard Clap help route help and help COMMAND is visibly advertised by
the root help output and is retained as a supported help route. It is not an
eighth product command and does not add product analysis behavior.

## Global Options

Exactly these three options are global:

| Option | Meaning |
| --- | --- |
| -q, --quiet | Suppress nonfatal diagnostics on stderr. |
| --format FORMAT | Select table, json, ndjson, or csv output. |
| -o, --output PATH | Write the requested report to PATH using the safe output-file lifecycle. |

The current parser accepts representative global-option placements before the
product subcommand, after the subcommand, and after the CAPTURE positional
where the option is syntactically reachable. The contract tests cover these
placements for format, quiet, and output. An invocation should provide each
global option at most once. The current parser rejects representative
same-scope duplicate format, quiet, and output occurrences; those are
usage/configuration failures covered by the contract test. Duplicate handling
across unusual mixed placements is intentionally unspecified and is not an
extension point.

The finding filters are not global options. They belong only to findings and
analyze as specified below.

## validate Contract

Invocation:

validate CAPTURE [--max-records N]

CAPTURE is a required local filesystem path. The command validates the
container and emits factual validation metadata and bounded diagnostics.

## flows Contract

Invocation:

flows CAPTURE [--max-records N] [--max-flows N]
[--max-flow-instances N] [--tcp-idle-timeout SECONDS]
[--udp-idle-timeout SECONDS]

The command reports reconstructed bidirectional flows and factual traffic and
temporal statistics. It does not infer client/server roles or application
protocols from ports.

## dns Contract

Invocation:

dns CAPTURE [--max-records N]

The command reports normalized DNS observations produced from the local
capture.

## http Contract

Invocation:

http CAPTURE [--max-records N]

The command reports bounded cleartext HTTP/1.x observations and selected
metadata. It does not decrypt or infer encrypted application payloads.

## tls Contract

Invocation:

tls CAPTURE [--max-records N]

The command reports visible TLS 1.2 and TLS 1.3 handshake metadata. It does not
decrypt TLS application data.

## findings Contract

Invocation:

findings CAPTURE [resource options] [finding filters]

Resource options are max-records, max-flows, max-flow-instances,
max-observations, tcp-idle-timeout, and udp-idle-timeout. Finding filters are
min-severity, min-confidence, detector, and mitre.

The command reports heuristic findings and their referenced evidence. A
finding is not a claim of confirmed malware or command-and-control activity.

## analyze Contract

Invocation:

analyze CAPTURE [resource options] [finding filters]

The resource options and finding filters are the same as for findings. The
command reports the unified analysis across capture metadata, flows, protocol
observations, findings, and evidence.

CSV is intentionally unsupported for this hierarchical command. analyze with
format csv is a usage/configuration failure with exit code 2 and no report on
stdout.

## Argument Scope Matrix

| Option | validate | flows | dns | http | tls | findings | analyze |
| --- | --- | --- | --- | --- | --- | --- | --- |
| max-records | yes | yes | yes | yes | yes | yes | yes |
| max-flows | no | yes | no | no | no | yes | yes |
| max-flow-instances | no | yes | no | no | no | yes | yes |
| max-observations | no | no | no | no | no | yes | yes |
| tcp-idle-timeout | no | yes | no | no | no | yes | yes |
| udp-idle-timeout | no | yes | no | no | no | yes | yes |
| min-severity | no | no | no | no | no | yes | yes |
| min-confidence | no | no | no | no | no | yes | yes |
| detector | no | no | no | no | no | yes | yes |
| mitre | no | no | no | no | no | yes | yes |

Using a command-specific option on another command is a usage/configuration
failure with exit code 2. For example, validate --min-severity low and
dns --max-flows 10 are rejected.

## Resource Option Types and Validation

The parser storage types and downstream safety rules are:

| Option | Parser type | Effective default | Accepted configured range | Downstream rule |
| --- | --- | --- | --- | --- |
| max-records | u64 | 100,000 records | 1 through 10,000,000 | Converted to usize before construction of ReaderLimits; zero and values above the reader hard cap are rejected. |
| max-flows | usize | 65,536 active flows | 1 through 1,000,000 | Validated by FlowReconstructionConfig. |
| max-flow-instances | usize | 1,000,000 instances | 1 through 10,000,000 | Validated by FlowReconstructionConfig. |
| max-observations | usize | 100,000 observations | 1 through 1,000,000 | Validated by ProtocolObservationCollection. |
| tcp-idle-timeout | u32 | 300 seconds | 1 through 2,592,000 seconds | The upper bound is 30 days and zero is rejected. |
| udp-idle-timeout | u32 | 60 seconds | 1 through 2,592,000 seconds | The upper bound is 30 days and zero is rejected. |

The configured values are optional CLI arguments. When absent, the effective
library defaults in the table apply.

max-records is parsed as u64 and then converted to usize. A value that cannot
be represented by the target architecture is rejected with a configuration
error before reader construction. The other usize options are parsed directly
as usize. Their valid hard-cap ranges fit within a 32-bit usize, but lexical
acceptance of values above the target architecture's usize range is
architecture-dependent. These rules do not claim the final packaged
cross-platform runtime acceptance owned by a later phase.

Malformed numeric values, zero, values above a hard cap, and failed
max-records conversion are exit-code-2 configuration failures. No numeric
option causes an unbounded allocation or work request.

## Finding Filter Contract

min-severity accepts these documented canonical lowercase values:

info, low, medium, high, critical

min-confidence accepts these documented canonical lowercase values:

low, medium, high

The filters are thresholds. Severity and confidence remain separate
properties of a finding.

The current domain conversion code also accepts case-insensitive spellings and
surrounding whitespace, and Severity additionally accepts informational as an
alias for info. Those spellings are retained implementation tolerance, not
guaranteed v1 CLI compatibility. The canonical values above are the only
documented public spellings.

detector accepts a validated namespaced DetectorId. Its current grammar is at
most 96 bytes, has at least two nonempty dot-separated segments, begins each
segment with a lowercase ASCII letter or digit, and permits only lowercase
ASCII letters, digits, hyphens, and underscores after each segment's first
character. Detector matching is exact.

## MITRE Filter Contract

mitre accepts a validated MITRE ATT&CK technique or sub-technique identifier:

T####

or:

T####.###

Examples are T1071 and T1071.004. The identifier is ASCII, uses uppercase T,
and has no surrounding whitespace. Tactic identifiers such as TA0011 are not
accepted. Phase 21 does not add tactic filtering.

## Output Format Matrix

The format tokens are exactly table, json, ndjson, and csv.

| Command | table | json | ndjson | csv |
| --- | --- | --- | --- | --- |
| validate | supported | supported | supported | supported |
| flows | supported | supported | supported | supported |
| dns | supported | supported | supported | supported |
| http | supported | supported | supported | supported |
| tls | supported | supported | supported | supported |
| findings | supported | supported | supported | supported |
| analyze | supported | supported | supported | rejected with exit 2 |

Report payload details and schema evolution are owned by REPORTING.md. The
existing schema version remains v1.0; Phase 21 does not add, remove, rename,
or retype report fields.

## Default Values

The default format is table. Omitting format is byte-equivalent to explicitly
selecting format table for the same deterministic input and command, including
exit state and diagnostics.

quiet defaults to false. output defaults to stdout. The resource defaults are
listed in Resource Option Types and Validation. There is no literal CLI
default value for max-records; the effective default comes from ReaderLimits.

## Help Contract

The following help outputs are byte-exact contract artifacts:

- pcapraven --help
- pcapraven validate --help
- pcapraven flows --help
- pcapraven dns --help
- pcapraven http --help
- pcapraven tls --help
- pcapraven findings --help
- pcapraven analyze --help

The short -h alias produces the same bytes as --help for the root and each
product command. The visibly advertised standard help route help and
help COMMAND produces the corresponding root or command help.

Successful help writes only stdout, no diagnostics to stderr, and exits 0.
The exact text is maintained in tests/cli_contract/help and verified by the
contract integration test.

## Version Contract

The long --version and short -V aliases produce exactly:

pcapraven <CARGO_PKG_VERSION>\n

where the value is resolved dynamically from the package version at build
time. Version output is written only to stdout, stderr is empty, and the
process exits 0. A literal version-output snapshot is deliberately not
stored.

## Exit Code Contract

| Exit code | Meaning |
| --- | --- |
| 0 | The command completed successfully with a complete result, or displayed help/version. |
| 1 | A fatal input, analysis, output, or I/O failure occurred before a useful result was available. |
| 2 | The invocation or configuration is invalid: parser errors, missing or unknown arguments, invalid values, limit failures, unsupported command/format combinations, or an existing output-file collision. |
| 3 | A useful result was produced, but processing was partial or degraded. |

The contract test exercises all four statuses. If the process cannot print a
parser diagnostic because of an output failure, the entry point returns 1;
ordinary parser and configuration failures remain 2.

## stdout / stderr Contract

stdout contains only the requested report or help/version result. It contains
no diagnostic, warning, progress, debug, or ANSI escape sequence.

stderr contains diagnostics, suppression summaries, usage text, and fatal
errors. It contains no report rows or report payload. Nonfatal capture
diagnostics are prefixed with diagnostic: . Suppression summaries are
prefixed with warning: . Fatal messages are prefixed with error: .

When output is sent to PATH successfully, report bytes go to that file and
stdout remains empty. Help and version always use stdout.

## Quiet Mode

quiet and -q suppress nonfatal diagnostics and suppression summaries. They do
not suppress requested report bytes, help, version, fatal errors, or the exit
status. A partial result remains exit 3 with the same stdout under quiet mode,
while stderr becomes empty when no fatal error occurs. Fatal errors remain
visible on stderr under quiet mode.

## Diagnostic Bounding

The default display budget is 100 nonfatal diagnostic lines per command.
Additional nonfatal diagnostics are suppressed and represented by at most one
summary line:

warning: suppressed <N> additional diagnostic messages (budget: 100)

The budget bounds displayed diagnostics; it does not turn malformed input into
a successful or complete result. quiet suppresses both the individual
nonfatal lines and the summary.

## Output File Lifecycle

The output path is opened with exclusive create-new semantics. An existing
file is never overwritten: the command returns exit 2, leaves the existing
bytes unchanged, and emits an error diagnostic.

A new output file is not created when its parent directory is missing or
cannot be opened; that is exit 1. The application does not create parent
directories. Rendering and flushing are explicit. If rendering or flushing a
new file fails, the newly created file is removed when possible and the
command returns exit 1. There is no force-overwrite option and no implicit
temporary, stdin, network, or directory output mode.

## Unsupported Invocation Contract

CAPTURE is a local filesystem path. PcapRaven does not implicitly read a
capture from stdin, a URL, HTTP, HTTPS, S3, cloud object storage, a live
interface, or shell-style glob expansion.

Unknown commands, missing required CAPTURE values, unknown options, malformed
values, and command-specific options used outside their scope are usage
failures with exit 2. The standard option terminator -- is supported: after it,
the next positional value can be treated as CAPTURE even when its spelling
resembles an option.

## Compatibility Rules

During Phases 22 through 28, this contract is frozen. The following are
incompatible v1 CLI changes unless the Phase 21 decision is explicitly
reopened and approved:

- removing or renaming a command;
- changing the required CAPTURE positional;
- removing or renaming a public option;
- removing a public short alias;
- changing option scope;
- changing an accepted canonical value;
- changing a default;
- changing the command/format matrix;
- changing an exit-code category;
- moving result output from stdout;
- moving diagnostics or errors from stderr;
- changing quiet semantics;
- changing output collision or overwrite semantics;
- making an optional argument required;
- changing local-capture input into implicit network behavior.

A release-blocking security defect that requires an incompatible CLI change
must be documented, explicitly reopen this decision, and receive user
approval. It must not be hidden in later-phase work. Additive compatibility
and eventual post-v1 versioning policy are future decisions, not Phase 21
implementation.

## Explicitly Unfrozen / Out of Scope

Phase 21 does not finalize the machine reporting schema. Phase 22 owns the
final reporting-schema audit. The existing reporting schema version v1.0 and
format compatibility may be referenced, but no schema field, type, enum
token, NDJSON envelope, or CSV schema is changed here.

Phase 21 does not define packaged binary targets, release artifacts, release
automation, or a v1.0.0 claim. It does not add commands, formats, capture
sources, detector semantics, MITRE mappings, dependencies, or workspace
packages.

## Phase 21 Verification

The frozen surface is verified by:

- byte-exact help snapshots in tests/cli_contract/help;
- byte-exact usage and error snapshots in tests/cli_contract/usage and
  tests/cli_contract/errors;
- the dynamic version and CLI-boundary integration test in
  crates/pcapraven-cli/tests/contract.rs;
- the existing report golden matrix, which remains in tests/golden and is
  unchanged;
- the existing reporting schema contract, which remains unchanged;
- the architecture inventory, workspace checks, MSRV check, formatting,
  linting, documentation, fixture, robustness, fuzz-smoke, security, and
  supply-chain gates;
- the cross-platform workspace-check matrix on Ubuntu, Windows, and macOS.

The contract test is intentionally separate from report-payload goldens. It
checks the CLI surface without reproducing the existing 49-scenario report
matrix.

## Phase Status

Phase 21 is the CLI v1 contract-freeze phase. Acceptance requires the Phase 20
prerequisite, the artifacts and tests above, passing PR-head CI on all required
platforms, and an independent source-read-only Reviewer with zero CRITICAL and
HIGH findings. Until that gate is complete, later phases remain future and
unimplemented.

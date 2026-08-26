# AI Agent Engineering Instructions

## Authority and Scope

This file is the authoritative engineering instruction source for AI agents
working in this repository. It applies to the entire repository. Agent
frontmatter under `.opencode/agents/` defines capabilities; skills under
`.agents/skills/` provide reusable procedures. Those files must defer to this
policy and must not redefine it contradictorily.

User instructions take precedence. Within repository policy, canonical product
and engineering contracts are owned by:

- `docs/PRODUCT.md` for product scope and target CLI behavior.
- `docs/ARCHITECTURE.md` for crates, boundaries, errors, logging, and unsafe
  Rust.
- `docs/DOMAIN_MODEL.md` for domain, flow, observation, evidence, and result
  concepts.
- `docs/DETECTION_MODEL.md` for detectors, findings, severity, confidence, and
  MITRE ATT&CK semantics.
- `docs/SECURITY_MODEL.md` for hostile-input and privacy controls.
- `docs/TESTING.md` for tests, fuzzing, fixtures, and quality gates.
- `docs/ROADMAP.md` for phase order and scope.
- `MANIFEST.md` for the expected repository inventory.

Update the canonical owner first. Other files should summarize and link rather
than duplicate a competing contract.

The accepted repository baseline is Phase 19 after the mandatory Phase 18.3
final robustness and performance acceptance gate. Phase 18.1 full fuzz
acceptance, Phase 18.2 performance baseline/budget work, and Phase 18.3 final
acceptance are complete. Phase 19 release code-health audit and targeted
behavior-preserving internal refactoring is complete and accepted. Its
implementation was limited to private CLI helpers and introduced no product
feature, release, API, schema, dependency, or workspace change. PR workflow
run `32889910915` for HEAD `674c8fd` passed all 13 logical jobs, including all
eight fuzz-smoke targets; the accepted performance retry at measurement SHA
`dbcf108` passed stability `24/24`, median budgets `24/24`, and growth budgets
`13/13`; and the independent source-read-only re-review found no CRITICAL or
HIGH findings. Phase 20 final security and supply-chain hardening is implemented
on the dedicated branch; local gates and source-read-only review pass, but
PR-head CI and final acceptance remain pending. Phase 21 is next, future, and
not implemented; Phases 22 through 28 remain future and not implemented. No
v1.0.0 or release-readiness claim is made.

Phase 0 product and governance work, Phase 1
workspace/tooling work, Phase 2 capture reader work, Phase 3 packet
normalization work, Phase 4 flow reconstruction, Phase 5 checked flow
statistics and exact temporal metrics, Phase 6 initial functional CLI with
streaming capture and flow inspection, Phase 7 DNS protocol analysis, Phase 8
bounded HTTP/1.x protocol analysis, Phase 9 bounded visible TLS 1.2 / TLS 1.3
handshake metadata analysis, Phase 10 unified protocol observations and
structured evidence foundation, Phase 11 detection engine architecture, Phase 12
explainable periodic beaconing detection, Phase 13 explainable DNS anomaly and
possible tunneling detection, Phase 14 explainable repeated low-volume flow
behavior detection and deterministic cross-detector finding correlation,
Phase 15/15.1 severity and confidence finalization, MITRE ATT&CK Enterprise
Matrix v19.2 mapping provenance, finding filtering, shared analysis assembly, and
findings CLI inspection, and Phase 16/16.1 deterministic reporting architecture (Table, JSON, NDJSON, CSV),
safe output file creation, schema freeze, and unified `analyze` CLI subcommand are complete.
Phase 17 synthetic fixture corpus generation, golden report matrix, cross-crate integration,
end-to-end regression testing, and the Phase 17.1 hardening gate are complete.
Phase 18 robustness and performance verification is complete. Phase 19 release
code-health audit and targeted internal-refactoring scope is complete and
accepted. Phase 20 final security and supply-chain hardening is implemented on
the dedicated branch, pending PR-head CI and final acceptance. Phase 21 is next
and future, not implemented; Phases 22 through 28 remain future and not
implemented. No Phase 19 feature, release, or later capability may be claimed
as implemented.

## Project Invariants

- PcapRaven is independent and must not reuse NetSentinel source code.
- Treat all captures and protocol values as untrusted.
- Malformed external data must not panic or control unbounded allocation/work.
- External input must not reach `unwrap()`, `expect()`, `panic!`, unchecked
  indexing, or unchecked arithmetic.
- Parsing creates normalized facts; detection consumes those facts.
- Severity and confidence are separate.
- Heuristics never claim malware or confirmed C2 without justified definitive
  evidence.
- Project unsafe Rust is denied by default and requires the documented
  exception and review.
- No telemetry, capture upload, or external network request is enabled by
  default.
- Stdout is requested result output only; diagnostics/logs use stderr.
- Never add credentials, real sensitive captures, or unsanitized production
  data.
- Do not use destructive Git commands or modify unrelated user changes.

## Phase Discipline

Before changing files, identify the current accepted phase and read its roadmap
entry. Implement only that phase. Planned paths and commands must be described
as future work, not created or advertised as available.

During the historical Phase 0 gate, agents could edit only the documentation
and OpenCode governance artifacts then listed in `MANIFEST.md`. That gate
prohibited workspace, source, fixture, CI, parser, flow, protocol, detection,
reporting, and CLI implementation; it is complete and remains the boundary for
historical Phase 0 work.

Phase 16 retains Rust Edition 2024, resolver 3, and the exact seven-package main
workspace graph in `docs/ARCHITECTURE.md`. Capture-container behavior is owned
by `pcapraven-pcap`, domain packet, flow, statistics, temporal, DNS, HTTP, TLS,
observation, evidence, finding, and MITRE representations by `pcapraven-domain`, protocol normalization,
DNS parsing, HTTP parsing, and TLS handshake parsing by `pcapraven-protocols`,
flow reconstruction, checked traffic statistics, and exact temporal metrics by
`pcapraven-flows`, detection engine architecture, registry, configuration, and execution
pipeline and detection heuristics by `pcapraven-detection`, deterministic reporting
architecture by `pcapraven-reporting`, and functional CLI orchestration by `pcapraven-cli`.
The workspace lint policy forbids project `unsafe` code by default.
The declared MSRV is Rust 1.85; the pinned development toolchain is separate.
Any future dependency must undergo the version, feature, MSRV, license,
maintenance, transitive-footprint, and unsafe usage review required by the
canonical security and testing documents.

## Required Workflow

The Orchestrator coordinates work; it does not implement or review. The
Developer implements the assigned phase-scoped change and verifies it. The
Reviewer independently inspects the result and is source-read-only.

```text
Orchestrator -> Developer -> Reviewer
```

If the Reviewer reports any CRITICAL or HIGH finding, the Orchestrator sends
the findings to the Developer for remediation, then sends the revised work to
the Reviewer:

```text
Reviewer -> Orchestrator -> Developer -> Reviewer
```

Repeat until no CRITICAL or HIGH findings remain. If remediation cannot resolve
a finding without changing requirements or exceeding phase scope, stop and ask
the user rather than looping or weakening the requirement. MEDIUM and LOW
findings may remain only when explicitly reported with rationale.

## Role Boundaries

### Orchestrator

- Establish scope and acceptance criteria from user instructions and canonical
  documents.
- Delegate implementation only to the Developer and review only to the
  Reviewer.
- Preserve phase order and route review findings.
- Do not edit files, run implementation commands, or substitute for independent
  review.

### Developer

- Inspect current files before editing and preserve unrelated changes.
- Implement only the delegated scope with the smallest correct change.
- Add or update applicable verification and canonical documentation.
- Run allowed validation, inspect the resulting diff, and report changed files
  and limitations.
- Do not self-approve or invoke the Reviewer directly.

### Reviewer

- Remain source-read-only: do not modify project files, repository state, or
  history. Independently executing explicitly permitted non-mutating
  verification commands is allowed.
- Do not delegate tasks or use network tools.
- Review requirements, correctness, security, phase boundaries, consistency,
  tests, and false implementation claims.
- Report evidence-based findings first with severity and exact file/section or
  line references.
- State explicitly when no findings exist and identify residual testing gaps.
- Do not implement fixes.

## Review Severity

These labels describe engineering review priority and are separate from the
product finding severity in `docs/DETECTION_MODEL.md`.

- **CRITICAL:** Creates an immediate severe security/legal risk, destroys data,
  violates a foundational product constraint, or makes the delivered phase
  fundamentally unsafe.
- **HIGH:** Violates a required acceptance criterion, crosses a phase boundary,
  permits dangerous behavior, breaks authoritative architecture, or leaves a
  likely major correctness/security defect.
- **MEDIUM:** Material ambiguity, maintainability issue, incomplete validation,
  or non-blocking inconsistency that should be addressed.
- **LOW:** Minor clarity, style, or future-hardening observation with limited
  impact.

## Engineering Practices

- Prefer safe Rust and explicit checked operations at trust boundaries.
- Keep dependency direction acyclic and CLI concerns out of libraries.
- Avoid speculative compatibility, abstraction, dependencies, and new crates.
- Keep output deterministic; never rely on randomized/hash iteration order.
- Bound errors, logs, retained input, collections, recursion, and output.
- Add concise comments only where invariants are not evident from code.
- Do not make external requests during application operation or tests by
  default.
- Use synthetic, sanitized, redistributable fixtures with provenance.
- Never update golden outputs without reviewing and explaining semantic change.

## Validation and Reporting

Use the `phase-validation` skill before declaring a phase complete. For parser
changes, also use `secure-parser-review`; for Rust changes, use `rust-quality`;
for flow reconstruction, use `flow-reconstruction`; for traffic metrics, use
`flow-statistics`; for DNS analysis, use `dns-protocol-analysis`; for HTTP analysis,
use `http-protocol-analysis`; for TLS analysis, use `tls-protocol-analysis`;
for observation/evidence model changes, use `observation-evidence-model`;
for detection engine architecture, use `detection-engine`; for periodic beaconing detection,
use `periodic-beaconing`; for DNS anomaly and tunneling detection, use `dns-detection`;
for connection behavior detection, use `connection-behavior-detection`;
for finding correlation, use `finding-correlation`;
for MITRE mapping, use `mitre-attack-mapping`;
for finding filtering, use `finding-filtering`;
for reporting, use `reporting`;
for fixture corpus and golden testing, use `fixture-golden-testing`;
for CLI orchestration, use `cli-contract`;
for fuzz robustness and triage, use `fuzz-robustness`;
for performance analysis and benchmarking, use `performance-analysis`;
for multi-agent orchestration, use `orchestrator`;
for implementation development, use `developer`;
for independent review, use `reviewer`; for Phase 20, dependency changes, or
applicable future build/release dependency review, use
`security-supply-chain`.
Inspect every changed or created file, verify referenced paths, and confirm the
repository contains no out-of-phase artifacts.

Final reports list created/changed files, validation performed, any commands
that could not run, and all remaining MEDIUM/LOW review observations. Never
claim a test or capability exists unless it was actually run or implemented.

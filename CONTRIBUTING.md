# Contributing to PcapRaven

## Current Phase

PcapRaven is currently in Phase 0. Contributions in this phase must be limited
to product definition, architecture, documentation, security and testing
policy, repository governance, and agent configuration. Do not add a Cargo
workspace, Rust source, CI workflow, fixtures, parser, protocol handling, flow
logic, detector, reporter, or functional CLI until the relevant roadmap phase
begins.

Review [the roadmap](docs/ROADMAP.md), [architecture](docs/ARCHITECTURE.md), and
[repository manifest](MANIFEST.md) before proposing a change.

## Contribution Process

1. Open or reference an issue for substantial scope or architecture changes.
2. Keep the change within the current accepted phase and make the smallest
   coherent update.
3. Update the canonical document when changing a contract; update links and
   summaries without creating a second contradictory policy.
4. Check every changed link, term, phase claim, and planned/current status.
5. Request independent review focused on behavior, security, phase leakage,
   and missing verification.
6. Resolve all CRITICAL and HIGH review findings before acceptance.

Suspected vulnerabilities must follow [SECURITY.md](SECURITY.md), not the
public contribution process.

## Documentation Standards

- Use "PcapRaven" for the product and `pcapraven` for the planned executable.
- Clearly label future behavior as planned or targeted.
- Do not claim support, passing tests, releases, or commands that do not exist.
- Keep terminology consistent with the domain and detection models.
- Use relative links for repository documents and verify exact path case.
- Explain security tradeoffs and incomplete-data behavior explicitly.
- Keep examples synthetic and free of credentials or real capture data.
- Do not introduce unresolved placeholder policies into accepted documents.

## Architecture and Security

All future capture input is hostile. Contributions must preserve the mandatory
invariants in [Security Model](docs/SECURITY_MODEL.md), one-way crate boundaries
in [Architecture](docs/ARCHITECTURE.md), parser/detector separation, bounded
resource use, and the unsafe-code exception policy.

Architecture changes must update the relevant canonical documentation in the
same contribution. Compatibility shims or additional crates require a concrete
need and explicit review; they must not be introduced speculatively.

## Testing and Quality

Phase 0 validation is documentation-only and is described in
[Testing](docs/TESTING.md#phase-0-validation). Cargo commands are not currently
runnable because the workspace intentionally does not exist.

Once introduced in Phase 1, the baseline gates will be formatting, Clippy with
warnings denied, workspace tests, and documentation generation as listed in
[Future CI Quality Gates](docs/TESTING.md#future-ci-quality-gates). New behavior
must add the level of unit, fixture, integration, end-to-end, property, fuzz, or
regression coverage appropriate to its roadmap phase.

## Fixtures and Sensitive Data

Do not commit real organizational captures, credentials, personal data, or
third-party traffic without explicit authorization and redistribution rights.
Future fixtures should be minimal, synthetic, locally generated, sanitized,
and redistributable according to the [fixture policy](docs/TESTING.md#fixture-policy).

## Licensing Contributions

PcapRaven is licensed under Apache-2.0. Unless explicitly stated otherwise,
intentional contributions submitted for inclusion are provided under that same
license as described in Section 5 of [LICENSE](LICENSE). Do not contribute code,
documentation, fixtures, or generated artifacts you do not have the right to
license.

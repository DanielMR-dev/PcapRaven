# Contributing to PcapRaven

## Current Phase

Phase 0, Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6, Phase 7, and Phase 8
are complete. Phase 8 contributions implemented bounded cleartext HTTP/1.x message
header parsing and CLI inspection (`http`) in `pcapraven-protocols` and `pcapraven-cli`.
Do not add TLS handshake decoding, threat detection, reporting, or advanced CLI commands
until their respective roadmap phases begin. Phase 9 (TLS handshake metadata analysis) is next.

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

All capture input is hostile. Contributions must preserve the mandatory
invariants in [Security Model](docs/SECURITY_MODEL.md), one-way crate boundaries
in [Architecture](docs/ARCHITECTURE.md), parser/flow/detector separation, bounded
resource use, and the unsafe-code exception policy.

Architecture changes must update the relevant canonical documentation in the
same contribution. Compatibility shims or additional crates require a concrete
need and explicit review; they must not be introduced speculatively.

## Testing and Quality

Phase 6 validation uses the reader, normalizer, flow reconstruction, and CLI
integration tests, baseline quality commands, fuzz-target builds, and architecture checker
described in [Testing](docs/TESTING.md#phase-6-quality-gates). The pinned development
toolchain is separate from the Rust 1.85 MSRV. The libraries are self-contained;
the CLI orchestrates streaming execution and human inspection output.

The baseline gates are formatting, Clippy with warnings denied, workspace tests,
documentation generation, Cargo metadata, and the architecture checker. Locked
MSRV check/build/test and cross-platform checks run in CI. New behavior must add
the level of unit, fixture, integration, end-to-end, property, fuzz, or regression
coverage appropriate to its roadmap phase.

## Fixtures and Sensitive Data

Do not commit real organizational captures, credentials, personal data, or
third-party traffic without explicit authorization and redistribution rights.
Fixtures should be minimal, synthetic, locally generated, sanitized, and
redistributable according to the [fixture policy](docs/TESTING.md#fixture-policy).

## Licensing Contributions

PcapRaven is licensed under MIT. Unless explicitly stated otherwise, intentional
contributions submitted for inclusion are provided under that same license as
described in [LICENSE](LICENSE). Do not contribute code, documentation, fixtures,
or generated artifacts you do not have the right to license.

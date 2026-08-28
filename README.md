# PcapRaven

PcapRaven is an offline-first network forensics and threat-hunting CLI written
in Rust. Its intended purpose is to analyze PCAP and PCAPNG captures, normalize
network traffic, reconstruct bidirectional flows, extract selected DNS,
HTTP/1.x, and TLS handshake metadata, and produce explainable heuristic security
findings.

## Project Status

Phase 0 product and governance work, **Phase 1: Cargo workspace, crate
skeletons, baseline CI, and tooling**, **Phase 2: Safe PCAP/PCAPNG capture reader**,
**Phase 3: Ethernet + IPv4/IPv6 + TCP/UDP normalization**, **Phase 4: Deterministic
bidirectional flow reconstruction**, **Phase 5: Checked flow statistics and
exact temporal metrics**, **Phase 6: Initial functional CLI + capture/flow inspection**,
**Phase 7: Bounded DNS protocol analysis + normalized DNS observations + DNS CLI inspection**,
**Phase 8: Bounded HTTP/1.x metadata analysis + normalized HTTP observations + HTTP CLI inspection**,
**Phase 9: Bounded visible TLS 1.2 / TLS 1.3 handshake metadata analysis + normalized TLS observations + TLS CLI inspection**,
**Phase 10: Unified protocol observations + structured evidence foundation**,
**Phase 11: Detection engine architecture**,
**Phase 12: Explainable periodic beaconing detection over exact flow temporal metrics**,
**Phase 13: Explainable DNS anomaly and possible tunneling detection**,
**Phase 14: Explainable repeated low-volume flow behavior and deterministic cross-detector C2-like correlation**,
**Phase 15: Severity, confidence, finding filtering, and MITRE ATT&CK mapping provenance**,
**Phase 16: Deterministic reporting architecture (Table, JSON, NDJSON, CSV), safe output files, and unified `analyze` CLI**,
and **Phase 17: Synthetic fixture corpus, golden reports, and integration/E2E regression testing**
are complete. Phase 18.1 full fuzz acceptance, Phase 18.2 performance
baseline/budget work, and Phase 18.3 final performance acceptance are complete.
Phase 19 release code-health audit and targeted behavior-preserving internal
refactoring is complete and accepted. Its implementation was limited to
private CLI helpers. PR workflow run `32889910915` for HEAD `674c8fd` passed all
13 logical jobs, including all eight fuzz-smoke targets; the accepted
performance retry passed stability `24/24`, median budgets `24/24`, and growth
budgets `13/13`; and the independent source-read-only re-review found no
CRITICAL or HIGH findings. **Phase 20: Final security and supply-chain
hardening** is complete and accepted. **Phase 21: CLI v1 contract-freeze
acceptance** is complete and accepted. **Phase 22: Reporting schema v1 final
audit** is complete and accepted. **Phase 23: Cross-platform runtime
acceptance** is NEXT / NOT IMPLEMENTED; Phases 24 through 28 remain FUTURE /
NOT IMPLEMENTED. This status does not claim v1.0.0 or release readiness.

- `pcapraven-pcap` provides the streaming capture reader.
- `pcapraven-domain` defines normalized packet, flow, DNS, HTTP, TLS, observation, evidence, finding, and MITRE ATT&CK mapping domain models, traffic statistics, exact temporal metrics, unified protocol observations, explicit flow associations, structured evidence records, exact rational `EvidenceRatio`, and schema anchors.
- `pcapraven-protocols` provides bounded packet normalization, bounded DNS wire-format parsing, bounded HTTP/1.x message header parsing, and bounded TLS 1.2 / TLS 1.3 handshake metadata parsing.
- `pcapraven-flows` provides stateful bidirectional flow reconstruction, checked traffic statistics accumulation, and exact rational temporal metric calculations.
- `pcapraven-detection` provides the detection engine execution pipeline, deterministic detector registry, correlation pipeline, preflight parameter validation, explainable behavioral detectors including `PeriodicBeaconingDetector` (`behavior.periodic_beaconing`), `DnsLongQueryNameDetector` (`dns.long_query_name`), `DnsPossibleTunnelingDetector` (`dns.possible_tunneling`), `RepeatedLowVolumeFlowDetector` (`behavior.repeated_low_volume_flows`), finding correlators including `PossibleC2MultiSignalCorrelator` (`behavior.possible_c2_multi_signal`), and multi-criteria `FindingFilter`.
- `pcapraven-reporting` provides deterministic multi-format serialization (`table`, `json`, `ndjson`, `csv`), CSV formula injection defense, and schema version anchors.
- `pcapraven-cli` provides the functional CLI with streaming capture validation, flow inspection, DNS inspection, HTTP inspection, TLS inspection, findings inspection, and unified forensic analysis (`analyze`) with multi-format output and safe file creation.

### Implemented CLI Commands (Phase 16; frozen by Phase 21)

```text
# Unified forensic capture analysis across metadata, flows, observations, and findings:
pcapraven analyze <capture.pcap>
pcapraven analyze --format json --output report.json <capture.pcap>

# Validate capture container integrity and factual metadata:
pcapraven validate <capture.pcap>
pcapraven validate --format json <capture.pcap>

# Inspect reconstructed network flows and factual traffic statistics:
pcapraven flows --format csv <capture.pcap>

# Inspect normalized DNS observations:
pcapraven dns --format ndjson <capture.pcap>

# Inspect cleartext HTTP/1.x message headers:
pcapraven http <capture.pcap>

# Inspect visible TLS 1.2 / TLS 1.3 handshake metadata:
pcapraven tls <capture.pcap>

# Inspect analytical security findings with filtering:
pcapraven findings --min-severity low --min-confidence medium --detector dns.possible_tunneling --mitre T1071.004 <capture.pcap>

# Global flags, formats, and help:
pcapraven --help
pcapraven --version
pcapraven --format <table|json|ndjson|csv> <subcommand> <capture.pcap>
pcapraven --output <report.json> <subcommand> <capture.pcap>
pcapraven --quiet analyze <capture.pcap>
```

The synthetic corpus and read-only golden verification gate are documented in
[Phase 17 Quality Gates](docs/TESTING.md#phase-17-quality-gates).

The Phase 20 dependency, RustSec, license, provenance, CI, fuzz-toolchain, and
runtime security evidence is recorded in
[SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md). Runtime operation remains offline by
default; security database refreshes are explicit development/CI operations.

PcapRaven is a new and independent project. It is not a rewrite of NetSentinel
and does not reuse NetSentinel source code.

## Product Direction

The planned application will:

- Analyze captures locally with no telemetry, upload, or external network
  request by default.
- Treat every capture as untrusted input and enforce bounded, panic-free
  processing.
- Keep parsing, normalization, flow analysis, detection, reporting, and CLI
  orchestration separate.
- Attach concrete packet, flow, observation, and measurement evidence to every
  finding.
- Keep severity separate from confidence and describe heuristics as possible or
  suspicious behavior rather than proof of malware or command-and-control.

See [Product Definition](docs/PRODUCT.md) for goals and non-goals, and see the
[CLI v1 Contract](docs/CLI_V1_CONTRACT.md) for the frozen command-line
compatibility surface.

## Project Documentation

- [Product definition and target CLI](docs/PRODUCT.md)
- [Frozen v1 CLI compatibility contract](docs/CLI_V1_CONTRACT.md)
- [Workspace architecture and crate boundaries](docs/ARCHITECTURE.md)
- [Domain, flow, observation, and evidence model](docs/DOMAIN_MODEL.md)
- [Detection, finding, severity, and confidence model](docs/DETECTION_MODEL.md)
- [MITRE ATT&CK mapping provenance and validation](docs/MITRE_ATTACK_MAPPING.md)
- [Deterministic multi-format reporting architecture](docs/REPORTING.md)
- [Phase 22 reporting schema v1 audit evidence](docs/REPORTING_SCHEMA_V1_AUDIT.md)
- [Security and hostile-capture threat model](docs/SECURITY_MODEL.md)
- [Testing, property-testing, fuzzing, and fixture strategy](docs/TESTING.md)
- [Roadmap through v1.0.0](docs/ROADMAP.md)
- [Repository structure](MANIFEST.md)

Workspace tooling includes `scripts/check_workspace_architecture.py`, the
workspace quality commands in [Testing](docs/TESTING.md#phase-17-quality-gates),
the independent fuzz targets under `fuzz/`, and the CI workflow in
`.github/workflows/ci.yml`.

## Development

The development toolchain is controlled by `rust-toolchain.toml`; the project
MSRV remains Rust 1.85. Run the baseline checks from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo metadata --format-version 1 --no-deps --locked
python3 scripts/check_workspace_architecture.py
```

## Contributing and Security

Phase-aware contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
Please do not open a public issue for a suspected vulnerability; follow the
private process in [SECURITY.md](SECURITY.md).

## License

PcapRaven is licensed under the [MIT License](LICENSE).

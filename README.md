# PcapRaven

PcapRaven is an offline-first network forensics and threat-hunting CLI written
in Rust. Its intended purpose is to analyze PCAP and PCAPNG captures, normalize
network traffic, reconstruct bidirectional flows, extract selected DNS,
HTTP/1.x, and TLS handshake metadata, and produce explainable heuristic security
findings.

## Early Development Status

Phase 0 product and governance work, **Phase 1: Cargo workspace, crate
skeletons, baseline CI, and tooling**, **Phase 2: Safe PCAP/PCAPNG capture reader**,
**Phase 3: Ethernet + IPv4/IPv6 + TCP/UDP normalization**, **Phase 4: Deterministic
bidirectional flow reconstruction**, and **Phase 5: Checked flow statistics and
exact temporal metrics** are complete.

- `pcapraven-pcap` provides the streaming capture reader.
- `pcapraven-domain` defines normalized packet and flow domain models, traffic statistics, and exact temporal metrics.
- `pcapraven-protocols` provides bounded protocol normalization.
- `pcapraven-flows` provides stateful bidirectional flow reconstruction, checked traffic statistics accumulation, and exact rational temporal metric calculations.

The `pcapraven` binary remains a compile-only skeleton: it accepts no arguments,
emits no output, and performs no analysis. Functional CLI commands (Phase 6),
application decoders (DNS/HTTP/TLS), detection, and reporting remain targets
for later roadmap phases and are not currently available.

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

See [Product Definition](docs/PRODUCT.md) for goals, non-goals, and the intended
v1 CLI contract.

## Project Documentation

- [Product definition and target CLI](docs/PRODUCT.md)
- [Workspace architecture and crate boundaries](docs/ARCHITECTURE.md)
- [Domain, flow, observation, and evidence model](docs/DOMAIN_MODEL.md)
- [Detection, finding, severity, and confidence model](docs/DETECTION_MODEL.md)
- [Security and hostile-capture threat model](docs/SECURITY_MODEL.md)
- [Testing, property-testing, fuzzing, and fixture strategy](docs/TESTING.md)
- [Roadmap through v1.0.0](docs/ROADMAP.md)
- [Repository structure](MANIFEST.md)

Workspace tooling includes `scripts/check_workspace_architecture.py`, the
workspace quality commands in [Testing](docs/TESTING.md#phase-5-quality-gates),
the independent fuzz targets under `fuzz/`, and the CI workflow in
`.github/workflows/ci.yml`.

## Development

The development toolchain is controlled by `rust-toolchain.toml`; the project
MSRV remains Rust 1.85. The CLI is not implemented yet. Run the baseline checks
from the repository root:

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

# PcapRaven

PcapRaven is a planned offline-first network forensics and threat-hunting CLI
written in Rust. Its intended purpose is to analyze PCAP and PCAPNG captures,
normalize network traffic, reconstruct bidirectional flows, extract selected
DNS, HTTP/1.x, and TLS handshake metadata, and produce explainable heuristic
security findings.

## Early Development Status

Phase 0 product and governance work is complete, and **Phase 1: Cargo
workspace, crate skeletons, baseline CI, and tooling** is complete. The
repository now contains the virtual workspace, seven documented compile-only
crates, a pinned toolchain, an architecture checker, and baseline CI. The
`pcapraven` binary is only a skeleton: it accepts no arguments, emits no output,
and performs no analysis. Phase 2, the safe capture reader, is next.

Capture parsing, protocol normalization, flow analysis, detection, reporting,
and functional CLI commands remain targets for later roadmap phases and are not
currently available.

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

Phase 1 tooling includes `scripts/check_workspace_architecture.py`, the
workspace quality commands in [Testing](docs/TESTING.md#phase-1-quality-gates),
and the CI workflow in `.github/workflows/ci.yml`.

## Development

The development toolchain is controlled by `rust-toolchain.toml`; the project
MSRV remains Rust 1.85. Phase 1 has no functional PCAP analyzer. Run the six
baseline checks from the repository root:

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

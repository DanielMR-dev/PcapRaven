# PcapRaven

PcapRaven is a planned offline-first network forensics and threat-hunting CLI
written in Rust. Its intended purpose is to analyze PCAP and PCAPNG captures,
normalize network traffic, reconstruct bidirectional flows, extract selected
DNS, HTTP/1.x, and TLS handshake metadata, and produce explainable heuristic
security findings.

## Early Development Status

PcapRaven is currently in **Phase 0: product definition, architecture, and
engineering foundation**. There is no Cargo workspace, executable, capture
parser, protocol analyzer, flow engine, detector, or reporter in this
repository yet. The commands and capabilities described in the documentation
are targets for later roadmap phases and are not currently available.

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

## Phase 0 Documentation

- [Product definition and target CLI](docs/PRODUCT.md)
- [Workspace architecture and crate boundaries](docs/ARCHITECTURE.md)
- [Domain, flow, observation, and evidence model](docs/DOMAIN_MODEL.md)
- [Detection, finding, severity, and confidence model](docs/DETECTION_MODEL.md)
- [Security and hostile-capture threat model](docs/SECURITY_MODEL.md)
- [Testing, property-testing, fuzzing, and fixture strategy](docs/TESTING.md)
- [Roadmap through v1.0.0](docs/ROADMAP.md)
- [Repository structure](MANIFEST.md)

## Contributing and Security

Phase-aware contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).
Please do not open a public issue for a suspected vulnerability; follow the
private process in [SECURITY.md](SECURITY.md).

## License

PcapRaven is licensed under the [Apache License 2.0](LICENSE).

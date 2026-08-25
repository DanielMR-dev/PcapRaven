# Security Policy

## Supported Versions

PcapRaven has completed Phase 0, Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6,
Phase 7, Phase 8, Phase 9, Phase 10, Phase 11, Phase 12, Phase 13, Phase 14, Phase 15,
Phase 16, Phase 17, and Phase 18; Phase 19 release code-health audit and targeted
behavior-preserving internal refactoring is complete and accepted. It has no
released or supported software versions yet. Phase 20 is next, future, and not
implemented; Phases 21 through 28 remain future and not implemented. This policy covers
vulnerabilities in repository configuration, documentation, the bounded PCAP/PCAPNG reader,
protocol normalizer, flow reconstructor and metrics engine, DNS, HTTP/1.x, and TLS 1.2 / TLS 1.3 protocol parsers,
unified protocol observations, structured evidence foundation, detection engine architecture,
periodic beaconing detection, DNS anomaly and possible tunneling detection, repeated low-volume flow behavior detection,
cross-detector finding correlation, severity and confidence classification, MITRE ATT&CK mapping provenance, finding filtering,
deterministic multi-format reporting architecture (Table, JSON, NDJSON, CSV), CSV formula injection defenses, safe output file creation,
functional CLI orchestration, the manifest-backed synthetic corpus and its SHA-256
provenance, read-only golden verification, and future code as it is introduced.
Supported release ranges will be published before v1.0.0.

## Reporting a Vulnerability

Do not report suspected vulnerabilities in a public issue, discussion, pull
request, capture attachment, or chat transcript.

Use GitHub private vulnerability reporting for this repository:

<https://github.com/DanielMR-dev/PcapRaven/security/advisories/new>

If private reporting is unavailable, do not disclose the report publicly.
Contact the repository owner through a private GitHub channel and request a
secure reporting route without including vulnerability details or sensitive
captures in the initial message.

Include, when available:

- The affected revision, version, platform, and configuration.
- The vulnerability class and potential impact.
- Minimal reproduction steps or a minimal synthetic reproducer.
- Relevant logs with credentials, personal data, and capture content removed.
- Whether the issue is known to be actively exploited or publicly disclosed.
- A safe method and preferred timing for follow-up.

Do not submit production packet captures unless explicitly requested through
the private report. Prefer a minimized synthetic capture and describe its
provenance.

## Response and Disclosure

Maintainers will make a best effort to acknowledge reports, assess impact,
coordinate remediation, and keep the reporter informed. Because this project
has no funded support commitment, no fixed response or remediation SLA is
promised.

Please allow reasonable time for validation, remediation, regression testing,
and release coordination before public disclosure. Maintainers will credit
reporters who request credit and will respect requests for anonymity.

Good-faith research that avoids privacy violations, service disruption,
unauthorized access, and unnecessary data exposure is welcome. This statement
does not authorize testing against systems or data you do not own or have
permission to test, and it is not legal advice.

## Technical Security Model

The project's hostile-capture assumptions, mandatory parser invariants,
resource limits, privacy posture, output safety, and unsafe-code policy are in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

---
name: fixture-golden-testing
description: Synthetic PCAP fixture corpus, schema freeze verification, golden reports matrix, and end-to-end regression testing in PcapRaven.
---

# Fixture Corpus and Golden Regression Testing Skill

This skill governs the synthetic fixture corpus, golden report matrices, cross-crate integration, and end-to-end regression testing in PcapRaven (Phase 17).

## Core Invariants

1. **100% Synthetic Captures:** All PCAP and PCAPNG captures under `tests/fixtures/pcaps/` are generated deterministically via `scripts/generate_fixtures.py`.
2. **Strict Documentation Address Spaces:** All synthetic captures must strictly use:
   - IPv4: RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
   - IPv6: RFC 3849 documentation prefix (`2001:db8::/32`).
   - Domains: RFC 2606 / RFC 6761 reserved domains (`example.com`, `example.org`, `example.net`, `.example`, `.test`, `.invalid`, `.localhost`).
3. **Privacy Non-Retention & Sanitization:** Never commit production captures, proprietary traffic, credentials, customer identifiers, or private keys.
4. **Fixture Checksum Invariant:** Every fixture in `tests/fixtures/pcaps/` is tracked with its SHA-256 digest in `tests/fixtures/pcaps/checksums.sha256`.
5. **Deterministic Golden Reports:** Golden output files under `tests/golden/` provide byte-for-byte regression anchors across all commands (`validate`, `flows`, `dns`, `http`, `tls`, `findings`, `analyze`) and formats (`table`, `json`, `ndjson`, `csv`).
6. **Golden Update Policy:**
   - Golden files must NEVER be modified blindly to pass broken tests.
   - Any modification requires explicit human justification, clear documentation of the semantic fact change, and verification against the frozen `v1.0` schema.
7. **Cross-Crate Integration:**
   - `crates/pcapraven-cli/tests/corpus.rs` verifies that all corpus captures parse safely, respect memory bounds, and trigger expected detector and correlator findings.
   - `crates/pcapraven-cli/tests/golden.rs` verifies that CLI stdout matches golden files byte-for-byte.

## Verification Workflow

```text
# 1. Regenerate fixtures and verify checksums
python3 scripts/generate_fixtures.py

# 2. Run corpus integration tests
cargo test -p pcapraven-cli --test corpus

# 3. Run golden comparison tests
cargo test -p pcapraven-cli --test golden
```

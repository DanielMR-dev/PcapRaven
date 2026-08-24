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
4. **Fixture Integrity Invariant:** Every fixture is tracked by true SHA-256 in
   both `tests/fixtures/pcaps/manifest.json` and `checksums.sha256`; read-only
   verification regenerates expected bytes in memory and rejects missing or
   unexpected captures. Discovery and file reads take an explicit trusted
   repository root plus relative path, reject every static symlink component,
   and use explicit finite caps. Structural discovery must succeed before any
   canonical expected-file read or CLI scenario execution.
5. **Deterministic Golden Reports:** Golden output files under `tests/golden/` provide byte-for-byte regression anchors across all commands (`validate`, `flows`, `dns`, `http`, `tls`, `findings`, `analyze`) and formats (`table`, `json`, `ndjson`, `csv`). An absent stream path means exact empty output, not ignored output.
6. **Golden Update Policy:**
   - Golden files must NEVER be modified blindly to pass broken tests.
   - Any modification requires explicit human justification, clear documentation of the semantic fact change, and verification against the frozen `v1.0` schema.
7. **No Blind Canonical Writes:** `scripts/check_goldens.py` is read-only.
   `scripts/stage_goldens.py` requires an explicit destination outside
   `tests/golden/`, preflights canonical fixture inputs, and creates review
   candidates only.
8. **PCAPNG Reality:** PCAPNG fixtures must use the actually supported subset:
   section headers, section-local IDBs, EPBs and/or SPBs.
9. **Cross-Crate Integration:**
   - `crates/pcapraven-cli/tests/corpus.rs` executes every manifest capture through `CARGO_BIN_EXE_pcapraven` with exact exit and expected-behavior checks, in addition to focused safety regressions.
   - `crates/pcapraven-cli/tests/golden.rs` verifies exact stdout and stderr semantics for every scenario.

## Verification Workflow

```text
# 1. Verify bounded checker support
python3 scripts/test_verification_support.py

# 2. Read-only verify fixtures, canonical manifest, and true SHA-256
python3 scripts/generate_fixtures.py --check

# 3. Read-only verify canonical golden bytes and exact exit states 0/1/2/3
python3 scripts/check_goldens.py

# 4. Run corpus integration tests
cargo test -p pcapraven-cli --test corpus

# 5. Run golden comparison tests
cargo test -p pcapraven-cli --test golden
```

Use `python3 scripts/generate_fixtures.py --write` only for an intentional
synthetic corpus change. It never writes goldens. Any golden candidate requires
manual semantic/schema review; never copy candidates merely because a test failed.

---
name: tls-protocol-analysis
description: Use for PcapRaven bounded TLS protocol analysis design, implementation, and review involving TLS 1.2 and TLS 1.3 handshake metadata, candidate classification, selected extension retention, privacy non-retention, framing metadata, and terminal-safe rendering.
---

# TLS Protocol Analysis Review

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`,
   `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, and the current roadmap phase.
2. Confirm TLS protocol analysis implementation is allowed. Phase 9 establishes
   bounded visible TLS 1.2 / TLS 1.3 handshake parsing and observation extraction;
   Phase 10 (DNS / HTTP / TLS correlation), threat detections, and MITRE ATT&CK
   remain out of scope.
3. Verify that input to the TLS parser consists strictly of normalized domain
   records (`NormalizedPacket`) with bounded application payloads.

## TLS Parser Checklist

- **Candidate Classification:**
  - Classify cleartext TCP packets on port 443 as candidates.
  - Exclude UDP port 443 and non-443 traffic deterministically (`NotTlsCandidate`).
  - Handle candidate packets without application payload or non-TLS record data safely (`CandidateWithoutRecord`).
- **Framing & Stream Bounds:**
  - Packet-local inspection only: no cross-packet TCP stream reassembly.
  - Adjacent multi-record handshake assembly within the *same* packet bounded by `maximum_handshake_message_bytes`.
  - Max record fragment bounds: 16,384 bytes for plaintext handshake records, 18,432 bytes for opaque records.
- **Privacy Non-Retention Invariants (MANDATORY):**
  - NEVER retain 32-byte ClientHello / ServerHello random values (only inspect for HRR sentinel).
  - NEVER retain Session ID bytes (only retain `session_id_length`).
  - NEVER retain Key Share public key bytes (only retain named group IDs).
  - NEVER retain Pre-Shared Key identities or binders (only retain boolean presence flag).
  - NEVER retain Early Data payloads (only retain boolean presence flag).
  - NEVER retain Certificate DER, certificate lists, or ciphertext payloads.
  - NEVER decrypt TLS, load private keys, or accept `SSLKEYLOGFILE`.
- **Extension Decoders:**
  - Enforce finite limits on extensions, supported versions, groups, signature schemes, ALPNs, and server name bytes.
  - Enforce duplicate extension detection per Hello message (`Malformed`).
  - SNI (0): server name host_name parsed and stored as `TlsByteString` with terminal-safe escaping.
  - Supported Versions (43): client offers vector of versions; server selects single version.
  - Supported Groups (10): client offers vector of named groups.
  - Signature Algorithms (13): client offers vector of signature schemes.
  - ALPN (16): length-prefixed protocol strings stored as `TlsByteString`.
  - Key Share (51): retain group IDs only; zero key exchange bytes retained.
- **Output Safety & Escaping:**
  - Render string fields via `display_escaped()` using deterministic `\xHH` / `\\` notation to prevent ANSI escape sequence injection into terminal output.
  - Stdout output must be strictly terminal-safe with zero ANSI escape codes.
- **Diagnostics & Error Boundaries:**
  - Diagnostic emission per packet is capped by `maximum_diagnostics_per_packet`.
  - Malformed or partial TLS packets must never panic, crash, or abort the entire capture analysis.

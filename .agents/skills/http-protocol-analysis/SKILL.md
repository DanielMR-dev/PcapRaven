---
name: http-protocol-analysis
description: Use for PcapRaven bounded HTTP/1.x protocol analysis design, implementation, and review involving HTTP/1.0 and HTTP/1.1 message headers, candidate classification, selected header retention, sensitive header masking, framing metadata, and terminal-safe rendering.
---

# HTTP Protocol Analysis Review

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`,
   `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, and the current roadmap phase.
2. Confirm HTTP protocol analysis implementation is allowed. Phase 8 establishes
   bounded HTTP/1.x parsing and observation extraction; Phase 9 (TLS handshake
   metadata), detections, and generic evidence models remain out of scope.
3. Verify that input to the HTTP parser consists strictly of normalized domain
   records (`NormalizedPacket`) with bounded application payloads.

## HTTP Parser Checklist

- **Candidate Classification:**
  - Classify cleartext TCP packets on port 80 as candidates.
  - Exclude non-candidate traffic deterministically (`NotHttpCandidate`).
  - Handle candidate packets without application payload or non-start midstream data safely (`CandidateWithoutMessage`).
- **Framing & Stream Bounds:**
  - Packet-local inspection only: no cross-packet TCP stream reassembly.
  - No body retention, no chunked body decoding, no decompression.
  - HTTP/2 connection preface (`PRI * HTTP/2.0\r\n`) emits `Unsupported` and marks `Partial`.
- **Wire Message Invariants:**
  - Canonical line endings: require `\r\n`. Bare `\r` or bare `\n` emit `Malformed` diagnostics.
  - Start-line:
    - Requests: `method SP request-target SP HTTP-version`. Valid tokens, bounded lengths.
    - Responses: `HTTP-version SP status-code SP [reason-phrase]`. Exactly 3-digit status code (100..=999).
  - Version: strictly `HTTP/1.0` or `HTTP/1.1`. Other versions emit `Unsupported` diagnostics.
  - Preflight section counts against `maximum_header_fields` and `maximum_header_section_bytes`.
- **Header Field Handling:**
  - Prohibit whitespace before the colon separator (`Malformed`).
  - Reject line folding (obs-fold) with `Unsupported` diagnostic.
  - Reject control characters (< 0x20 except HTAB, and 0x7F) in header values with `Malformed` diagnostic.
  - Enforce mandatory `Host` header in HTTP/1.1 requests (`Malformed` if missing).
  - Reject duplicate `Host` headers in HTTP/1.1 requests (`Malformed`).
  - Parse `Content-Length` as non-negative decimal; duplicate identical values allowed, conflicting values mark `Invalid` and emit `Malformed`.
  - Check conflicting framing (both `Transfer-Encoding` and `Content-Length` present) and emit `Malformed`.
  - Sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`): record boolean presence flags only; never retain or serialize header values.
- **Output Safety & Escaping:**
  - Render string fields via `display_escaped()` using deterministic `\xHH` / `\\` notation to prevent ANSI escape sequence injection into terminal output.
  - Stdout output must be strictly terminal-safe with zero ANSI escape codes.
- **Diagnostics & Error Boundaries:**
  - Diagnostics must use safe static message templates with numeric structured offsets.
  - Diagnostic emission per packet is capped by `maximum_diagnostics_per_packet`.
  - Malformed or partial HTTP packets must never panic, crash, or abort the entire capture analysis.

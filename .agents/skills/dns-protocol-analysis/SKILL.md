---
name: dns-protocol-analysis
description: Use for PcapRaven bounded DNS protocol analysis design, implementation, and review involving DNS wire format, candidate classification, backward pointer compression, EDNS(0) metadata, and terminal-safe rendering.
---

# DNS Protocol Analysis Review

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`,
   `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, and the current roadmap phase.
2. Confirm DNS protocol analysis implementation is allowed. Phase 7 establishes
   bounded DNS parsing and observation extraction; Phase 8 (HTTP/1.x), Phase 9
   (TLS handshake metadata), and detections remain out of scope.
3. Verify that input to the DNS parser consists strictly of normalized domain
   records (`NormalizedPacket`) with bounded application payloads.

## DNS Parser Checklist

- **Candidate Classification:**
  - Classify packets on UDP or TCP port 53 as candidates.
  - Exclude non-candidate traffic deterministically (`NotDnsCandidate`).
  - Handle candidate packets without application payload safely (`CandidateWithoutMessage`).
- **Framing & Stream Bounds:**
  - UDP: exactly one DNS message per payload.
  - TCP: 2-byte big-endian frame length prefix. Handle multiple framed messages up to
    `maximum_messages_per_packet`. Truncated frames within a packet emit nonfatal
    `Incomplete` diagnostics without cross-packet reassembly.
- **Wire Message Invariants:**
  - Header: 12-byte minimum (`ID`, `FLAGS`, `QDCOUNT`, `ANCOUNT`, `NSCOUNT`, `ARCOUNT`).
  - Preflight section counts against `maximum_questions_per_message` and
    `maximum_resource_records_per_message`.
  - Section bounds: strictly validate that RDATA offsets and lengths do not exceed
    the wire message boundary.
- **Compression & Loop Prevention:**
  - Strict backward-pointer rule: pointer target offset must be strictly less than
    the current pointer location offset (`target_offset < pointer_location_offset`).
  - Prohibit self-loops, forward pointers, and out-of-bounds pointer targets.
  - Bound pointer traversal hops to `maximum_name_pointer_hops`.
  - Bound individual label length to 63 octets and expanded wire length to 255 octets.
  - Reject `01xxxxxx` and `10xxxxxx` label prefixes deterministically.
  - Bound aggregate retained domain name bytes per message to
    `maximum_total_retained_name_bytes_per_message`.
- **RDATA Decoding:**
  - Decode standard record types: A (IPv4), AAAA (IPv6), CNAME, NS, PTR, MX.
  - Decode EDNS(0) OPT pseudo-records in the Additional section (UDP payload size,
    extended RCODE, version, DO bit, option TLVs).
  - Treat unknown/unsupported RR types as opaque byte slices with bounded lengths.
- **Output Safety & Escaping:**
  - Domain names must be rendered via `display_escaped()` using deterministic `\DDD`
    escaping for control characters, non-ASCII octets, backslashes, and dots within labels.
  - Stdout output must be strictly terminal-safe with zero ANSI escape codes.
- **Diagnostics & Error Boundaries:**
  - Diagnostics must use safe static message templates with numeric structured offsets.
  - Diagnostic emission per packet is capped by `maximum_diagnostics_per_packet`.
  - Malformed or partial DNS packets must never panic, crash, or abort the entire
    capture analysis.

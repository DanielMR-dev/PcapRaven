---
name: secure-parser-review
description: Use for PcapRaven capture or protocol parser design and changes involving untrusted binary/text input, malformed records, bounds, resource limits, recovery, property tests, or fuzzing.
---

# Secure Parser Review

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`,
   `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, and the current roadmap phase.
2. Confirm parser implementation is allowed. Phase 2 capture parsing and Phase 3
   packet normalization are accepted; flow reconstruction and statistics do not
   authorize new protocol parsers; application decoding begins only with its
   dedicated roadmap phases.
3. Identify each attacker-controlled length, count, offset, text value, nesting
   level, and loop bound.

## Trust-Boundary Checklist

- Check format minima, enclosing bounds, available bytes, configured limits,
  conversions, and arithmetic before slicing or allocation.
- Ensure no external value reaches panic paths, unchecked indexing, unchecked
  arithmetic, or attacker-sized preallocation.
- Verify every parser loop consumes input or performs a strictly bounded state
  transition.
- Bound recursion, nesting, collection cardinality, retained bytes, text,
  diagnostics, and total work.
- Distinguish malformed, unsupported, and incomplete/truncated input.
- Recover only at a trustworthy format-defined boundary; otherwise fail safely.
- Keep partial-result state explicit and prevent detectors from treating missing
  data as observed absence.
- Encode untrusted bytes/text safely in errors, logs, terminals, CSV, and
  machine output; do not copy payloads into diagnostics.
- Review integer behavior on 32-bit and 64-bit targets where conversions differ.
- Confirm no external network access, telemetry, or capture upload is added.
- Review any dependency and all unsafe code under the project exception policy.

## Required Evidence

- Unit tests at zero, minimum, maximum, truncation, overflow, and configured
  limit boundaries.
- Recovery tests proving safe progress and correct next-record behavior.
- `proptest` properties for arbitrary bytes, progress, bounds, and invariants.
- `cargo-fuzz` targets for raw and structured inputs, with crash/hang regression
  promotion.
- Explicit resource-limit and diagnostic-amplification tests.

Report findings using the engineering review severities in `AGENTS.md`. The
review is incomplete if limits or recovery rules are implicit.

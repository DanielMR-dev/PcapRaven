---
name: fuzz-robustness
description: Use for PcapRaven bounded cargo-fuzz harnesses, curated corpora, smoke and acceptance campaigns, invariant assertions, and crash or hang triage.
---

# Fuzz Robustness

## Procedure

1. Read `AGENTS.md`, `docs/SECURITY_MODEL.md`, `docs/TESTING.md`,
   `docs/ROBUSTNESS.md`, and the active roadmap scope.
2. Identify the public product API, attacker-controlled bytes, pre-product
   harness transformations, and every retained/output cardinality.
3. Decode fuzz bytes with checked conversions, checked arithmetic, guarded
   slicing, and hard collection caps. Harness setup must not panic on malformed
   bytes before the product API executes.
4. Assert more than no-crash: determinism, progress, output limits, canonical
   ordering, referential integrity, exact temporal/counter invariants, and
   privacy non-retention as applicable.
5. Keep targets offline and filesystem-free. Use only synthetic curated seeds;
   ignore mutated corpus, artifacts, coverage, and profile output.
6. Build all targets before campaigns. Run the documented short CI profile for
   smoke verification, but never report it as a long-campaign pass.
7. For a crash, hang, sanitizer result, or invariant failure: preserve the
   reproducer outside tracked paths, minimize it, identify the owning layer,
   implement the smallest fix, add a reviewed regression seed/test, and rerun
   the affected target plus workspace gates.
8. Record exact target, maximum input length, duration, timeout, RSS limit,
   toolchain, cargo-fuzz version, revision, environment, result, and promoted
   regression. Leave unrun campaign rows explicitly pending.

Reject harnesses that use unchecked fuzz-controlled narrowing/indexing,
attacker-sized allocation, network/filesystem side effects, nondeterministic
state, or assertions that merely duplicate setup rather than product behavior.

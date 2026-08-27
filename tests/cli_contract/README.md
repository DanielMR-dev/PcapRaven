# CLI Contract Snapshots

This tree contains the Phase 21 byte-exact snapshots for the generated
pcapraven command-line surface. It is deliberately separate from
tests/golden/, which is the report-payload regression matrix.

The help/ files contain successful stdout for the root command and each of
the seven product commands. The usage/ and errors/ files contain exact
stderr for representative exit-2 invocations. The version contract is tested
dynamically against CARGO_PKG_VERSION; its current 0.0.0 value is not stored
here.

Snapshots contain only deterministic platform-independent text and are
compared byte-for-byte by
crates/pcapraven-cli/tests/contract.rs. Regenerate candidates outside this
tree, review them, and copy only approved changes. Do not place report
goldens or schema payloads here.

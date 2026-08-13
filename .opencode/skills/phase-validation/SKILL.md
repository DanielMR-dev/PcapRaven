---
name: phase-validation
description: Use before completing any PcapRaven phase or change to verify roadmap scope, required artifacts, canonical-document consistency, paths, validation evidence, and absence of premature functionality.
---

# Phase Validation

## Procedure

1. Read `AGENTS.md`, `MANIFEST.md`, the current entry in `docs/ROADMAP.md`, and
   all canonical documents affected by the change.
2. Build a checklist from the user's requirements and phase deliverables,
   exclusions, tests, documentation, and review obligations.
3. Enumerate repository files and compare them with `MANIFEST.md`. Identify
   missing, extra, generated, or premature artifacts.
4. Inspect every changed or created file in full and inspect the complete diff.
5. Verify referenced repository paths exist unless text explicitly marks them
   as planned. Resolve relative Markdown links with exact case.
6. Search for contradictory terminology, crate/dependency direction, phase
   numbering, security invariants, finding semantics, and present-tense claims
   about future work.
7. Run only verification allowed and meaningful for the current phase. Record
   exact commands and failures; do not claim unrun gates.
8. Confirm an independent read-only Reviewer pass occurred after Developer
   verification. Route CRITICAL/HIGH findings through remediation and re-review.
9. Report changed paths, verification, unavailable commands, and every remaining
   MEDIUM/LOW observation with rationale.

## Phase 0 Gate

Phase 0 must contain all documentation and OpenCode governance artifacts listed
in `MANIFEST.md`, and no `Cargo.toml`, `Cargo.lock`, Rust source, `crates/`,
fixture tree, CI workflow, parser, packet decoder, flow logic, protocol analysis,
detection, reporting, or functional CLI. README and all examples must label
future capabilities as planned or targeted.

Reject completion when any required path is missing, any internal link is
broken, the roadmap does not contain exactly Phase 0 through Phase 19 in the
required order, OpenCode frontmatter or reviewer permissions are invalid, or a
document contradicts its canonical owner.

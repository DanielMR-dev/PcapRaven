---
name: security-supply-chain
description: Audit and harden PcapRaven dependency, license, provenance, build-script, GitHub Actions, and fuzz-toolchain boundaries without expanding product scope.
metadata:
  short-description: Audit PcapRaven supply-chain boundaries
---

# PcapRaven security and supply-chain audit

Use this skill for dependency upgrades, RustSec or license review, Cargo
provenance policy, compile-time dependency review, immutable CI action pins,
Dependabot configuration, or the Phase 20 security and supply-chain gate.
Read `AGENTS.md` and the current `docs/ROADMAP.md` entry first. The canonical
security, testing, architecture, and domain documents remain authoritative;
this skill describes the audit procedure and must not create a later-phase
feature.

## Preserve the repository boundary

- Keep the seven-package main workspace and the excluded fuzz package
  topology unchanged unless the accepted phase explicitly authorizes a
  dependency-policy remediation.
- Do not run `cargo update`, `cargo audit fix`, or an unconstrained dependency
  upgrade while auditing. A dependency change needs a concrete finding,
  compatibility/MSRV review, license and source review, lockfile review, and
  focused regression evidence.
- Treat `Cargo.lock` and `fuzz/Cargo.lock` as separate security boundaries.
  Preserve both committed locks and use `--locked` for validation.
- Separate runtime dependencies from dev-only, fuzz-only, build-script, and
  proc-macro dependencies. A build or fuzz dependency can execute during
  compilation but must not be described as part of the product runtime.
- Keep the application offline by default. Network access is for explicitly
  authorized audit-tool database refreshes, dependency retrieval during
  setup, or repository-service inspection—not for product operation or tests.

## Audit procedure

1. Establish the accepted baseline: branch, commit, phase prerequisite,
   workspace/MSRV toolchains, both lockfile hashes, direct manifests, and
   current CI action pins. Record these before editing.
2. Resolve both graphs with `cargo metadata` and `cargo tree`, including
   workspace dev/build edges and all fuzz targets. Validate metadata JSON and
   compare the graph to the architecture checker. Do not rely on a single
   direct-dependency list.
3. Use the reviewed tool versions required by the phase. For Phase 20 they
   are `cargo-audit 0.22.2` and `cargo-deny 0.20.2`, installed with
   `--locked`. Inspect official release information before substituting a
   newer version; never silently change the audit toolchain.
4. Run RustSec against each committed lockfile with warnings denied. Run
   cargo-deny against the main workspace and the fuzz manifest with all
   features, locked resolution, and advisory, ban, license, and source checks.
   Refresh advisory data only when the task authorizes network use, and record
   the database load/result rather than treating an unavailable database as a
   clean audit.
5. Derive the license allowlist from the actual resolved graphs and crate
   license files. Keep it the smallest set that covers reviewed expressions;
   do not add broad exceptions or unexplained `ignore` entries. Include dev
   and build dependencies, and make private-package treatment explicit.
6. Review provenance and execution risk. Confirm registry or approved Git
   sources, checksums in both lockfiles, duplicate-version decisions,
   wildcard rejection, workspace-dependency consistency, and all build-script
   and proc-macro packages. Inspect unsafe code in direct runtime crates and
   relevant transitive/build dependencies, distinguishing source comments and
   tests from executable library code. Do not claim that a safe public API
   erases the dependency’s unsafe implementation; record the boundary and
   why the current use is acceptable.
7. Review CI as executable supply-chain code: every third-party action uses a
   full immutable commit SHA with a human-readable tag comment, checkout has
   `persist-credentials: false`, global/job permissions are least privilege,
   and no untrusted pull-request code receives secrets or write permission.
   Pin fuzzing to a dated nightly that actually passed all bounded targets.
8. Add or update only the minimal policy, evidence ledger, CI job, Dependabot
   schedule, canonical security/testing gates, and reusable skill required by
   the accepted phase. Keep detailed evidence in `docs/SUPPLY_CHAIN.md` and
   keep canonical documents as concise owners or summaries.

## Required evidence and failure handling

Report exact commands, versions, lock hashes, graph counts, advisory results,
license sources, action SHAs, toolchain versions, and reviewer findings. A
failed audit is evidence to triage, not a reason to weaken the policy. Do not
ignore an advisory, unmaintained package, license, source, duplicate, or
toolchain failure without a documented owner, rationale, expiry, and explicit
canonical-policy approval. Prefer remediation or a scoped stop-and-ask when
the issue changes requirements.

Run the normal Rust, architecture, schema/golden, documentation, and relevant
fuzz gates after policy edits. Use the Phase Validation skill before declaring
the phase complete. The Reviewer remains source-read-only and does not use
network tools; record inaccessible repository settings and CI-only evidence
instead of inferring them locally.

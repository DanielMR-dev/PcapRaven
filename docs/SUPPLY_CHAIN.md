# Supply-Chain and Dependency Security Audit

## Scope

This document is the Phase 20 evidence ledger for dependency, advisory,
license, provenance, build-input, CI, maintenance, and runtime security
review. Policy remains owned by the [Security Model](SECURITY_MODEL.md); this
ledger records the inspected graph and the commands that produced the
results. The audit does not add product behavior, a release pipeline, or a
v1.0.0 claim.

The normal workspace contains exactly seven runtime packages. The excluded
`fuzz/` package is audited separately and is not a production workspace
member. All captures and protocol values remain untrusted, and the
application remains offline by default.

## Phase 20 Baseline

The accepted Phase 19 `main` ancestor used for this work was:

```text
507cd7d2d643a8fbbe35a1db93eaa396fed9f484
```

The Phase 20 branch is `phase-20-security-supply-chain`. The application
declared MSRV remains Rust `1.85`; the pinned stable development toolchain is
`1.97.1` from `rust-toolchain.toml`. Fuzzing uses the separately pinned
`nightly-2026-08-13` from `fuzz/rust-toolchain.toml`, which was the exact
nightly used for the post-pin eight-target smoke run:

```text
rustc 1.99.0-nightly (c98d0cb27 2026-08-12)
commit-hash: c98d0cb27cc63afdd62602a52eb4feb8a1c682dd
host: x86_64-unknown-linux-gnu
```

The committed lockfile fingerprints at the start and end of the change are:

| File | SHA-256 |
| --- | --- |
| `Cargo.lock` | `ca4e23d1a3de6493a35425fbbaf69f8ba5588d90dbd351fb75c695ed3828cb19` |
| `fuzz/Cargo.lock` | `63bd5a28e79a32debc9b68659f5f2a9edd37652607d4adbcd745035c35f9ce13` |

No dependency version was upgraded or added. The only manifest policy
remediation was to express the existing `proptest = 1.11.0` test dependency
once as a workspace dependency, satisfying duplicate-declaration policy.
The excluded fuzz package also now declares its existing local MIT license so
the private-package license policy can inspect it. Neither change altered a
lockfile.

The exact development security tools were installed with locked installer
graphs:

```text
cargo-audit 0.22.2
cargo-deny 0.20.2
cargo-fuzz 0.13.2
```

`cargo-deny` is run with the pinned development toolchain, not MSRV 1.85.
The application MSRV was not raised to satisfy a security-tool requirement.

## Dependency Surfaces

Runtime direct external dependencies are six crates: `pcap-parser`,
`etherparse`, `serde`, `serde_json`, `csv`, and `clap`. The main graph contains
41 registry packages and seven local path packages. The one unique main-graph
dev dependency is `proptest`; it is used by four crates through the shared
workspace declaration and is not linked into production binaries. The fuzz
graph contains three direct external packages (`libfuzzer-sys`, `serde_json`,
and `csv`) plus six local PcapRaven path dependencies. Its complete resolved
graph contains 28 registry packages and seven local path packages.

The compile-time surface is part of this review. Main-graph metadata identifies
the proc-macro packages `serde_derive 1.0.219` and `zerocopy-derive 0.8.56`, and
custom-build targets in `getrandom 0.3.4`, `libc 0.2.189`, `num-traits 0.2.19`,
`proc-macro2 1.0.107`, `quote 1.0.47`, `serde 1.0.219`, `serde_json 1.0.140`,
`wit-bindgen 0.46.0`, and `zerocopy 0.8.56`. The fuzz graph additionally has
the `libfuzzer-sys 0.4.13` build target and uses `getrandom 0.4.3` and
`libc 0.2.189`. These are build-time inputs, not hidden runtime services.

## Direct Dependency Inventory

The table records the exact declarations used by this revision. “Active”
means that the upstream release page or source was current at the review date;
it does not mean that a freshness-only update is required.

| Crate | Version | Scope | Features | Source | License | Maintenance | Advisory state | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pcap-parser` | `=0.17.0` | runtime | default, `data`, `serialize` disabled | crates.io | MIT OR Apache-2.0 | active; latest reviewed `0.17.0` (2025-07-25) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `etherparse` | `=0.21.0` | runtime | default disabled | crates.io | MIT OR Apache-2.0 | active; latest reviewed `0.21.0` (2026-07-21) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `serde` | `=1.0.219` | runtime | default disabled; `alloc`, `derive` | crates.io | MIT OR Apache-2.0 | active; newer `1.0.229` reviewed (2026-07-18) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `serde_json` | `=1.0.140` | runtime and fuzz | default disabled; `alloc` | crates.io | MIT OR Apache-2.0 | active; newer `1.0.151` reviewed (2026-07-20) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `csv` | `=1.3.1` | runtime and fuzz | default disabled | crates.io | MIT OR Unlicense | maintained; newer `1.4.0` reviewed (2025-10-17) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `clap` | `=4.6.4` | runtime | default disabled; `std`, `help`, `usage`, `error-context` | crates.io | MIT OR Apache-2.0 | active; newer `4.6.6` reviewed (2026-08-06) | clean in both applicable RustSec/cargo-deny checks | KEEP |
| `proptest` | `=1.11.0` | dev only | default disabled; `std` | crates.io | MIT OR Apache-2.0 | passive maintenance stated upstream; latest reviewed `1.11.0` | clean in main cargo-deny check | KEEP |
| `libfuzzer-sys` | `=0.4.13` | fuzz only | default features | crates.io | MIT OR Apache-2.0 OR NCSA | active; latest reviewed `0.4.13` (2026-06-04) | clean in fuzz RustSec/cargo-deny checks | KEEP |

Upstream release pages and package metadata were reviewed for the direct
dependencies, including the newer releases noted above. A newer release alone
was not treated as a security defect: the exact pins remain because RustSec,
license, source, MSRV, feature, and regression checks are clean, and Phase 20
does not perform freshness-only graph updates.

Review references (accessed 2026-08-26) include the
[`pcap-parser` package record](https://docs.rs/crate/pcap-parser/latest),
[`etherparse` releases](https://github.com/JulianSchmid/etherparse/releases),
[`clap` releases](https://github.com/clap-rs/clap/releases),
[`serde` releases](https://github.com/serde-rs/serde/releases),
[`serde_json` package record](https://docs.rs/crate/serde_json/latest),
[`csv` upstream repository](https://github.com/BurntSushi/rust-csv),
[`proptest` status](https://docs.rs/crate/proptest/latest/source/README.md),
and [`libfuzzer-sys` package record](https://docs.rs/crate/libfuzzer-sys/latest).

## Transitive Dependency Inventory

The complete graphs were generated and inspected with:

```text
cargo tree --workspace --all-features --locked
cargo tree --manifest-path fuzz/Cargo.toml --locked
cargo metadata --format-version 1 --locked
cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 --locked
```

All registry packages in both lockfiles have Cargo checksums, and no lockfile
contains duplicate package names. The main graph includes the parser chain
through `nom`, `circular`, `memchr`, and `rusticata-macros`; the normalization
chain through `arrayvec`; the reporting chain through `csv-core`, `itoa`, and
`ryu`; the serialization derive chain through `proc-macro2`, `quote`, `syn`,
and `unicode-ident`; and the property-testing chain through `rand`,
`rand_chacha`, `rand_core`, `ppv-lite86`, `getrandom`, `zerocopy`, `regex-syntax`,
and `unarray`. The fuzz-only graph additionally contains `arbitrary`,
`libfuzzer-sys`, `cc`, `jobserver`, `find-msvc-tools`, and `shlex`.

The separate lockfiles legitimately resolve target-dependent variants such as
`getrandom 0.3.4` in the main graph and `getrandom 0.4.3` in the fuzz graph.
There are no duplicate-version or wildcard exceptions in `deny.toml`.

## Advisory Audit

Both committed lockfiles passed the exact required RustSec commands on the
review date. The audit database reported 1,226 loaded advisories; no advisory,
yanked package, warning, or ignore was reported.

```text
cargo audit --file Cargo.lock --deny warnings       PASS
  scanned 48 crate dependencies; loaded 1226 advisories

cargo audit --file fuzz/Cargo.lock --deny warnings  PASS
  scanned 35 crate dependencies; loaded 1226 advisories
```

The machine policy also runs `cargo deny` advisories checks for both graphs.
`[advisories].ignore` is explicitly empty, and unmaintained and unsound
advisories are treated as failures rather than silently waived.

## License Audit

The JSON inventories were generated with `cargo deny list --format json
--layout crate` for the main workspace and the fuzz manifest, then reviewed
against the actual lock metadata. The reviewed SPDX expressions contain the
following identifiers (some are optional alternatives in an `OR` expression):

```text
Apache-2.0
Apache-2.0 WITH LLVM-exception
BSD-2-Clause
BSL-1.0
LGPL-2.1-or-later
MIT
NCSA
Unicode-3.0
Unlicense
```

The smallest allowlist that satisfies every current expression is
`Apache-2.0`, `MIT`, `NCSA`, and `Unicode-3.0`: the first two satisfy the
permissive alternatives, `NCSA` is required by the fuzz-only
`(MIT OR Apache-2.0) AND NCSA` expression, and `Unicode-3.0` is required by the
Unicode `AND` expression. `BSL-1.0`, `LGPL-2.1-or-later`,
`Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, and `Unlicense` are observed
as alternatives but are not separately allowed because another permitted
choice satisfies each expression. There are no clarifications and no
package-specific license exceptions. The main and fuzz checks both pass. The
main-only check reports the expected informational unmatched `NCSA` allowance
because that identifier occurs only in the separate fuzz graph; it does not
broaden the accepted set or mask a license failure.
Private workspace packages are checked (`licenses.private.ignore = false`),
including the explicit MIT metadata on `pcapraven-fuzz`.

## Source Provenance

The metadata and lockfile review found:

- all external packages sourced from the approved crates.io index
  `https://github.com/rust-lang/crates.io-index`;
- no Git dependencies and no unknown registries;
- local path sources only for the seven internal runtime packages in the main
  graph and those packages used by the excluded fuzz manifest; and
- checksums for every registry package in both committed lockfiles.

`deny.toml` denies unknown registries and unknown Git sources, allows only the
approved registry, and allows no Git source. The architecture checker
continues to enforce the seven-package runtime graph and separately validates
the excluded fuzz package.

## Compile-Time Trust

Proc macros and build scripts execute during compilation and are therefore
reviewed as supply-chain inputs. `serde_derive` and `zerocopy-derive` provide
the expected derive implementations. The other build targets generate
platform configuration or compile support code. `libfuzzer-sys` is fuzz-only;
its `cc` build dependency compiles the bundled libFuzzer support and never
enters the application runtime graph.

Source inspection of these actual locked packages found no unexpected
application-time network request, secret-bearing feature, or hidden process
execution. Native compiler invocation is confined to expected build tooling.
The application does not claim to be free of native or third-party unsafe
implementation merely because PcapRaven source is safe Rust.

## Third-Party Unsafe Review

The workspace keeps `unsafe_code = "forbid"`; no project unsafe item was found.
Some dependencies legitimately contain unsafe implementation:

- `pcap-parser` uses a small internal unsafe array helper behind its public
  parser API; PcapRaven calls the public streaming reader only after its own
  bounded container preflight and does not expose parser types.
- `etherparse` uses internal slice/pointer optimizations; PcapRaven calls its
  checked public `*HeaderSlice::from_slice` constructors after framing and
  length validation.
- serialization and fuzz/build crates contain ordinary implementation unsafe or
  FFI/native build boundaries, including `libfuzzer-sys` and `cc` in the
  excluded fuzz graph.

These observations are third-party implementation details, not PcapRaven
unsafe code. RustSec and cargo-deny reported no relevant unsoundness or security
advisory. No vendoring or fork is justified by ordinary upstream unsafe usage.

## Dependency Maintenance Review

The direct decisions are all `KEEP`. The reviewed upstream state, exact
features, source, licenses, MSRV implications, transitive footprint, and
RustSec result do not expose a release-blocking issue. The pinned versions are
intentionally not replaced by newer versions solely for freshness. Future
Dependabot proposals remain subject to the same review, including changelog,
feature delta, source delta, license delta, MSRV, transitive graph, RustSec,
cargo-deny, architecture, and relevant fuzz/performance checks.

## GitHub Actions Supply Chain

Every external action in `.github/workflows/ci.yml` remains pinned to an
immutable full commit SHA:

| Action | Pin and documented tag | Use |
| --- | --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) | all jobs |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` (`v4.6.2`) | fuzz failure artifacts |

The workflow keeps `permissions: contents: read`, uses ordinary `pull_request`
and `push` to `main` triggers, adds no privileged trigger, and adds no secret
or write permission. Every read-only checkout explicitly sets
`persist-credentials: false`.

The dedicated `security-supply-chain` job installs exact locked
`cargo-audit 0.22.2` and `cargo-deny 0.20.2`, audits both lockfiles, and runs
the four cargo-deny policy classes for both the main and fuzz graphs. It has a
30-minute timeout and does not use `continue-on-error`.

## Fuzz Toolchain Provenance

The mutable CI `nightly` input was replaced with the canonical
`fuzz/rust-toolchain.toml` pin `nightly-2026-08-13`. The eight post-pin local
smoke campaigns all passed with the existing target-specific maximum lengths
and:

```text
-max_total_time=30 -timeout=5 -rss_limit_mb=1024
```

Targets were `fuzz_pcap_reader`, `fuzz_packet_normalizer`,
`fuzz_flow_reconstructor`, `fuzz_dns_parser`, `fuzz_http_parser`,
`fuzz_tls_parser`, `fuzz_detection_engine`, and `fuzz_reporting`. The local
Linux host required `ASAN_OPTIONS=detect_leaks=0` because LeakSanitizer cannot
run under its ptrace environment; this was a local harness-environment
workaround, not a CI policy relaxation. CI retains its normal sanitizer
configuration and the same bounded commands.

## Dependabot Policy

`.github/dependabot.yml` opens reviewable weekly update PRs for:

- the root Cargo workspace;
- the excluded `/fuzz` Cargo package; and
- GitHub Actions.

The configuration has finite open-PR limits and no automatic merge, bypass,
credential, or private-registry configuration. An update proposal is not an
approval and must pass the normal and security CI gates.

## Security Exceptions and Waivers

None. There are no advisory ignores, license exceptions, source exceptions,
duplicate-version skips, or Git dependencies.

## Runtime Security Re-Walk

The Phase 19 code-health inventory was re-walked at the security boundaries.
The reader, normalizer, DNS/HTTP/TLS parsers, flow and observation state,
detector output, diagnostics, reporting encoders, and CLI output lifecycle
retain finite bounds, checked arithmetic, parser-progress checks, and
transactional failure behavior. The only panic-like source matches are test
helpers documented by the existing code-health audit; no externally reachable
production panic was introduced.

HTTP sensitive header values and TLS randoms, session IDs, key material,
identities, early data, certificates, and ciphertext remain non-retained.
Terminal escaping, standards-based JSON/NDJSON/CSV encoding, CSV formula
prefixing, stdout/stderr separation, and `OpenOptions::create_new(true)` with
flush/error cleanup remain intact. Production source has no runtime socket,
network client, unexpected process execution, or secret-bearing environment
feature. No project FFI or unsafe code was added.

## Verification Evidence

The complete baseline quality suite passed before and after the Phase 20
changes. The final run includes formatting, Clippy with warnings denied,
verification-support tests, fixture and golden checks, workspace tests,
schema and CLI golden tests, rustdoc, metadata, architecture, locked MSRV
check/build/test, and the Phase 18 methodology and smoke checks. The exact
security commands passed as recorded above. `git diff --check` passed, and the
canonical lockfiles and `tests/golden/` have zero diff.

The Phase 20 change does not modify production Rust behavior or a runtime
dependency. The conditional full Phase 18 three-run performance comparison and
600-second production-surface fuzz campaigns were therefore not required;
the all-eight fuzz infrastructure smoke was rerun because the fuzz toolchain
input changed.

## Reviewer Findings

The independent source-read-only Phase 20 review of the staged implementation
completed on 2026-08-26. It found no issues:

```text
CRITICAL = 0
HIGH = 0
MEDIUM = 0
LOW = 0
remediation cycles = 0
```

The review verified the 31-file scope, no production-source or lockfile diff,
the four-class policy checks for both graphs, immutable action SHAs,
`persist-credentials: false` on every checkout, the least-privilege workflow,
the exact dated fuzz pin, and the absence of later-phase functionality. No
remediation was required. PR workflow run `33009011617` for head `50178b7`
passed all 14 jobs, including the security/supply-chain job and all eight
fuzz-smoke jobs.

## Residual Risks

The available GitHub authentication could not read branch-protection details,
required-status-check policy, force-push/deletion protection, or Dependabot
security-feature visibility. The public rulesets endpoint returned no rulesets,
but that does not prove that all repository protections are absent. No setting
was changed or inferred. The final PR workflow run `33009011617` for head
`50178b7` passed all 14 jobs, including the complete cross-platform, fuzz-smoke,
quality, MSRV, and security/supply-chain matrix.

The audit is a point-in-time review of committed lockfiles and the advisory
database available on the review date. Third-party unsafe/native build code
remains an upstream supply-chain boundary. Release signing, SBOM generation,
artifact attestation, binary provenance, and release publication remain future
Phase 24/27 work and are not Phase 20 claims.

## Phase Status

At branch start this phase was `CURRENT / IN PROGRESS`. Final local gates, the
independent source-read-only review, and PR workflow run `33009011617` are
complete, so the current canonical status is:

```text
Phase 19: COMPLETE
Phase 20: COMPLETE / ACCEPTED
Phase 21: NEXT / NOT IMPLEMENTED
Phases 22 through 28: FUTURE / NOT IMPLEMENTED
```

No CLI freeze, reporting-schema finalization, packaging, release automation,
release candidate, v1.0.0, or other later-phase capability is implemented.

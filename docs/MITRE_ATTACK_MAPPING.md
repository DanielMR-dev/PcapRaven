# MITRE ATT&CK Mapping Model and Provenance

## 1. Overview and Scope

This document specifies PcapRaven's MITRE ATT&CK mapping architecture, data models, provenance tracking, and canonical technique assignments for analytical findings produced by the Detection Engine (`pcapraven-detection`).

PcapRaven aligns its threat-hunting and network forensics mappings with the **MITRE ATT&CK Enterprise Matrix (Version 19.2)**.

### Non-Attribution and Non-Confirmation Principle

In accordance with PcapRaven's core governance and detection model (`docs/DETECTION_MODEL.md`):
- MITRE ATT&CK mappings represent **factual analytical relevance**, never confirmed malware presence, threat-actor attribution, or verified adversary activity.
- Heuristic detectors and correlators flag structural, statistical, and behavioral anomalies. Legitimate network operations (CDNs, telemetry, cloud services, DNSSEC, security tools) routinely exhibit overlapping traffic patterns.
- Findings without justifiable technique alignment **do not** attach spurious mappings merely to appear comprehensive.

---

## 2. Data Model and Provenance

MITRE ATT&CK structures are defined in `pcapraven-domain::mitre_attack` as strongly validated, immutable types:

### 2.1 `MitreAttackCatalogVersion` and `MitreAttackObjectVersion`

- `MitreAttackCatalogVersion`: Canonical knowledge base version, e.g. `CANONICAL_MITRE_CATALOG_VERSION = MitreAttackCatalogVersion::new(19, 2)`.
- `MitreAttackObjectVersion`: Specific technique version within the matrix, e.g. `MitreAttackObjectVersion::new(1, 4)`.

### 2.2 `MitreAttackDomain` and `MitreAttackRelationship`

- `MitreAttackDomain::Enterprise`: Strictly bounded to the Enterprise Matrix.
- `MitreAttackRelationship::Analytical`: Explicit declaration that mappings represent heuristic analytical alignment, not confirmed attribution.

### 2.3 `MitreAttackId`

A validated technique or sub-technique identifier:
- **Format:** `T{4 digits}` (e.g., `T1071`) or `T{4 digits}.{3 digits}` (e.g., `T1071.004`).
- **Validation:** Enforces strict prefix and numeric formatting without external regex or STIX dependencies. Leading and trailing whitespace is rejected (`trim()` is prohibited).

### 2.4 `MitreTactic`

Enterprise tactics defined with canonical identifiers:
- `InitialAccess` (`TA0001`)
- `Execution` (`TA0002`)
- `Persistence` (`TA0003`)
- `PrivilegeEscalation` (`TA0004`)
- `DefenseEvasion` (`TA0005`)
- `CredentialAccess` (`TA0006`)
- `Discovery` (`TA0007`)
- `LateralMovement` (`TA0008`)
- `Collection` (`TA0009`)
- `Exfiltration` (`TA0010`)
- `CommandAndControl` (`TA0011`)
- `Impact` (`TA0040`)
- `ResourceDevelopment` (`TA0042`)
- `Reconnaissance` (`TA0043`)

### 2.5 `MitreMappingDeclaration` and `MitreMapping`

- `MitreMappingDeclaration`: Declared statically on detector metadata (`DetectorMetadata`) and correlator metadata (`CorrelatorMetadata`). Captures domain, catalog version, technique ID, technique name, technique version, tactic, relationship, and mapping rationale.
- `MitreMapping`: Engine-stamped mapping on final accepted `FindingRecord`s, combining a `MitreMappingDeclaration` with immutable provenance:
  - `DetectorDeclared { detector_id, detector_version }`: Stamped for findings emitted by primary heuristic detectors.
  - `CorrelatorDeclared { correlator_id, correlator_version }`: Stamped for findings emitted by post-evaluation finding correlators.

`FindingDraft` and `CorrelationDraft` do **not** carry `MitreMapping`s; provenance and stamping are owned solely by the detection engine.

---

## 3. Canonical Built-in Detector Mappings

| Component Identifier | Component Kind | Version | MITRE Technique | Technique Name | Tactic | Rationale Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `behavior.periodic_beaconing` | Primary Detector | `v1.0.0` | *(None)* | — | — | Generic periodicity alone is insufficient for confident protocol technique mapping. |
| `dns.long_query_name` | Primary Detector | `v1.0.1` | *(None)* | — | — | Individual long query names frequently occur in legitimate CDN and security lookups. |
| `dns.possible_tunneling` | Primary Detector | `v1.1.1` | `T1071.004` | Application Layer Protocol: DNS | Command and Control (`TA0011`) | Repeated high-diversity, long-name DNS queries within a flow match DNS data encoding/tunneling patterns. |
| `behavior.repeated_low_volume_flows` | Primary Detector | `v1.0.0` | *(None)* | — | — | Low-volume repeated connections occur widely across benign operating system and background telemetry. |
| `behavior.possible_c2_multi_signal` | Correlator | `v1.1.1` | `T1071.004` | Application Layer Protocol: DNS | Command and Control (`TA0011`) | Cross-detector correlation of periodic timing with DNS tunneling patterns strongly aligns with DNS-based C2 communication channels. |

---

## 4. Ordering, Validation, and Invariants

1. **Deterministic Ordering:** Declarations and stamped mappings attached to a finding are validated for strictly ascending technique ID order and absence of duplicates.
2. **Bounds Enforcement:** A maximum of 16 MITRE mappings may be attached to a single finding record (`HARD_MAX_MITRE_MAPPINGS_PER_FINDING = 16`). Technique names are capped at 128 bytes and rationales at 1,024 bytes with control character prohibition.
3. **Engine-Owned Provenance:** The detection engine validates declarations and stamps `MitreMapping` with exact provenance during finding acceptance.
4. **Filtering:** The `pcapraven findings` and `pcapraven analyze` CLIs support filtering by MITRE technique or tactic ID via `--mitre <ID>` (e.g., `--mitre T1071.004`).

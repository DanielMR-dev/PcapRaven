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

### 2.1 `MitreAttackId`

A validated technique or sub-technique identifier:
- **Format:** `T{4 digits}` (e.g., `T1071`) or `T{4 digits}.{3 digits}` (e.g., `T1071.004`).
- **Validation:** Enforces strict prefix and numeric formatting without external regex or STIX dependencies.

### 2.2 `MitreTactic`

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

### 2.3 `MitreMappingProvenance`

Stamps the exact originating component that declared the mapping:
- `DetectorDeclared`: Declared by a primary heuristic detector (`detector_id`, `detector_version`).
- `CorrelatorDeclared`: Declared by a post-evaluation finding correlator (`correlator_id`, `correlator_version`).
- `CuratedFinding`: Assigned during offline investigation or curation.

### 2.4 `MitreMapping`

Complete mapping record encapsulating:
- `technique_id`: [`MitreAttackId`]
- `technique_name`: Static name string (e.g., `"Application Layer Protocol: DNS"`)
- `tactic`: [`MitreTactic`]
- `rationale`: [`MitreMappingRationale`] explaining the analytical connection
- `provenance`: [`MitreMappingProvenance`]

---

## 3. Canonical Built-in Detector Mappings

| Component Identifier | Component Kind | Version | MITRE Technique | Technique Name | Tactic | Rationale Summary |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `behavior.periodic_beaconing` | Primary Detector | `v1.0.1` | *(None)* | — | — | Generic periodicity alone is insufficient for confident protocol technique mapping. |
| `dns.long_query_name` | Primary Detector | `v1.0.1` | *(None)* | — | — | Individual long query names frequently occur in legitimate CDN and security lookups. |
| `dns.possible_tunneling` | Primary Detector | `v1.1.0` | `T1071.004` | Application Layer Protocol: DNS | Command and Control (`TA0011`) | Repeated high-diversity, long-name DNS queries within a flow match DNS data encoding/tunneling patterns. |
| `behavior.repeated_low_volume_flows` | Primary Detector | `v1.0.1` | *(None)* | — | — | Low-volume repeated connections occur widely across benign operating system and background telemetry. |
| `behavior.possible_c2_multi_signal` | Correlator | `v1.1.0` | `T1071.004` | Application Layer Protocol: DNS | Command and Control (`TA0011`) | Cross-detector correlation of periodic timing with DNS tunneling patterns strongly aligns with DNS-based C2 communication channels. |

---

## 4. Ordering, Validation, and Invariants

1. **Deterministic Ordering:** Mappings attached to a finding are validated for strictly ascending technique ID order and absence of duplicates.
2. **Bounds Enforcement:** A maximum of 8 MITRE mappings may be attached to a single finding record.
3. **Immutable Engine Output:** MITRE mappings are attached at draft creation and preserved immutably throughout engine execution, correlation, and filtering.
4. **Filtering:** The `pcapraven findings` CLI supports filtering by MITRE technique ID via `--mitre <TECHNIQUE_ID>` (e.g., `--mitre T1071.004`).

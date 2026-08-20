---
name: mitre-attack-mapping
description: Use for PcapRaven MITRE ATT&CK Enterprise Matrix v19.2 mapping provenance, validation, and explainability.
---

# MITRE ATT&CK Mapping Skill

This skill documents requirements and procedures for declaring, validating, stamping, and reviewing MITRE ATT&CK mappings in PcapRaven.

## Core Invariants

1. **Enterprise Matrix Version Pinned:** Canonical catalog version is MITRE ATT&CK Enterprise Matrix `v19.2`. Object versions are explicitly typed (`MitreAttackObjectVersion`, e.g., `1.4`).
2. **Domain & Relationship Semantics:** Domain is strictly `MitreAttackDomain::Enterprise`. Relationship is strictly `MitreAttackRelationship::Analytical` (heuristics indicate analytical alignment with technique behavior, not confirmed intrusion/adversary attribution).
3. **Declaration Provenance Ownership:**
   - Detectors and correlators declare mappings statically on their metadata (`DetectorMetadata`, `CorrelatorMetadata`) via `MitreMappingDeclaration`.
   - `FindingDraft` and `CorrelationDraft` do **not** carry `MitreMapping`s.
   - The `DetectionEngine` stamps final `MitreMapping`s onto accepted `FindingRecord`s with explicit `MitreMappingProvenance::DetectorDeclared` or `MitreMappingProvenance::CorrelatorDeclared`.
4. **Strict Identifier Syntax:** `MitreAttackId` must strictly match `T####` (e.g. `T1071`) or `T####.###` (e.g. `T1071.004`). No leading or trailing whitespace is accepted (`trim()` is prohibited).
5. **Bounded Technique Names and Rationales:** Technique names and rationales are strictly bounded and cannot contain ASCII control characters.
6. **No Floating-Point Arithmetic:** Zero `f32`/`f64` usage in mapping representations.

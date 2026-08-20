//! MITRE ATT&CK domain models and mapping provenance for analytical findings.
//!
//! Represents conservative, auditable mappings to MITRE Enterprise ATT&CK (v19.2)
//! techniques and tactics with engine-owned provenance and explicit non-attribution rationales.

use crate::finding::{DetectorId, DetectorVersion};
use core::fmt;
use std::str::FromStr;

/// Supported MITRE Enterprise ATT&CK knowledge base version string.
pub const MITRE_ATTACK_VERSION: &str = "19.2";

/// Canonical MITRE Enterprise ATT&CK catalog version.
pub const CANONICAL_MITRE_CATALOG_VERSION: MitreAttackCatalogVersion =
    MitreAttackCatalogVersion::new(19, 2);

/// Maximum allowed byte length for a MITRE ATT&CK identifier (16 bytes, e.g. "T1071.004").
pub const MAX_MITRE_ATTACK_ID_LENGTH: usize = 16;

/// Maximum allowed byte length for a MITRE technique name (128 bytes).
pub const MAX_MITRE_TECHNIQUE_NAME_LENGTH: usize = 128;

/// Maximum allowed byte length for a MITRE mapping rationale (1,024 bytes).
pub const MAX_MITRE_RATIONALE_LENGTH: usize = 1_024;

/// Hard maximum MITRE mappings per finding or detector metadata (16).
pub const HARD_MAX_MITRE_MAPPINGS_PER_FINDING: usize = 16;

/// Errors that can occur during MITRE ATT&CK domain model validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MitreAttackValidationError {
    /// Technique identifier must not be empty.
    EmptyTechniqueId,
    /// Technique identifier exceeds maximum allowed length.
    TechniqueIdTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Technique identifier format is invalid (must be `T####` or `T####.###`).
    InvalidTechniqueIdFormat(String),
    /// Technique name must not be empty.
    EmptyTechniqueName,
    /// Technique name exceeds maximum allowed length.
    TechniqueNameTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Technique name contains a prohibited control character.
    TechniqueNameControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Mapping rationale must not be empty.
    EmptyRationale,
    /// Mapping rationale exceeds maximum allowed length.
    RationaleTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Mapping rationale contains a prohibited control character.
    RationaleControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Catalog version string is invalid.
    InvalidCatalogVersion(String),
    /// Object version string is invalid.
    InvalidObjectVersion(String),
    /// Duplicate MITRE mapping declared or assigned.
    DuplicateMapping(MitreAttackId),
    /// MITRE mappings must be strictly sorted by technique ID.
    OutOfOrderMapping {
        /// Previous technique ID.
        previous: String,
        /// Attempted technique ID.
        attempted: String,
    },
    /// MITRE mapping count exceeds hard maximum limit.
    MappingsExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
}

impl fmt::Display for MitreAttackValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTechniqueId => {
                f.write_str("MITRE ATT&CK technique identifier cannot be empty")
            }
            Self::TechniqueIdTooLong { length, max } => write!(
                f,
                "MITRE ATT&CK technique ID length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::InvalidTechniqueIdFormat(s) => write!(
                f,
                "invalid MITRE ATT&CK technique ID format '{s}': expected 'T####' or 'T####.###'"
            ),
            Self::EmptyTechniqueName => f.write_str("MITRE ATT&CK technique name cannot be empty"),
            Self::TechniqueNameTooLong { length, max } => write!(
                f,
                "MITRE ATT&CK technique name length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::TechniqueNameControlCharacter { byte } => write!(
                f,
                "MITRE ATT&CK technique name contains prohibited control character 0x{byte:02x}"
            ),
            Self::EmptyRationale => f.write_str("MITRE ATT&CK mapping rationale cannot be empty"),
            Self::RationaleTooLong { length, max } => write!(
                f,
                "MITRE ATT&CK mapping rationale length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::RationaleControlCharacter { byte } => write!(
                f,
                "MITRE ATT&CK mapping rationale contains prohibited control character 0x{byte:02x}"
            ),
            Self::InvalidCatalogVersion(s) => {
                write!(
                    f,
                    "invalid MITRE ATT&CK catalog version '{s}': expected 'major.minor'"
                )
            }
            Self::InvalidObjectVersion(s) => {
                write!(
                    f,
                    "invalid MITRE ATT&CK object version '{s}': expected 'major.minor'"
                )
            }
            Self::DuplicateMapping(id) => {
                write!(f, "duplicate MITRE ATT&CK mapping for technique {id}")
            }
            Self::OutOfOrderMapping {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order MITRE ATT&CK mapping: attempted {attempted} after {previous}"
            ),
            Self::MappingsExceeded { count, max } => write!(
                f,
                "MITRE ATT&CK mapping count ({count}) exceeds maximum allowed ({max})"
            ),
        }
    }
}

impl std::error::Error for MitreAttackValidationError {}

/// Structured MITRE ATT&CK knowledge base / catalog version (e.g. 19.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreAttackCatalogVersion {
    /// Major catalog version.
    pub major: u16,
    /// Minor catalog version.
    pub minor: u16,
}

impl MitreAttackCatalogVersion {
    /// Creates a new catalog version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Parses a catalog version string without trimming whitespace.
    pub fn try_new(s: impl AsRef<str>) -> Result<Self, MitreAttackValidationError> {
        let raw = s.as_ref();
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() != 2 {
            return Err(MitreAttackValidationError::InvalidCatalogVersion(
                raw.to_string(),
            ));
        }
        let major = parts[0]
            .parse::<u16>()
            .map_err(|_| MitreAttackValidationError::InvalidCatalogVersion(raw.to_string()))?;
        let minor = parts[1]
            .parse::<u16>()
            .map_err(|_| MitreAttackValidationError::InvalidCatalogVersion(raw.to_string()))?;
        Ok(Self { major, minor })
    }
}

impl fmt::Display for MitreAttackCatalogVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for MitreAttackCatalogVersion {
    type Err = MitreAttackValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// Structured MITRE ATT&CK technique object version (e.g. 1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreAttackObjectVersion {
    /// Major object version.
    pub major: u16,
    /// Minor object version.
    pub minor: u16,
}

impl MitreAttackObjectVersion {
    /// Creates a new object version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Parses an object version string without trimming whitespace.
    pub fn try_new(s: impl AsRef<str>) -> Result<Self, MitreAttackValidationError> {
        let raw = s.as_ref();
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() != 2 {
            return Err(MitreAttackValidationError::InvalidObjectVersion(
                raw.to_string(),
            ));
        }
        let major = parts[0]
            .parse::<u16>()
            .map_err(|_| MitreAttackValidationError::InvalidObjectVersion(raw.to_string()))?;
        let minor = parts[1]
            .parse::<u16>()
            .map_err(|_| MitreAttackValidationError::InvalidObjectVersion(raw.to_string()))?;
        Ok(Self { major, minor })
    }
}

impl fmt::Display for MitreAttackObjectVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl FromStr for MitreAttackObjectVersion {
    type Err = MitreAttackValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// MITRE ATT&CK domain classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum MitreAttackDomain {
    /// Enterprise ATT&CK domain.
    #[default]
    Enterprise,
}

impl MitreAttackDomain {
    /// Returns the static string representation of the domain.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Enterprise => "Enterprise",
        }
    }
}

impl fmt::Display for MitreAttackDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Analytical relationship between finding heuristic and MITRE ATT&CK technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum MitreAttackRelationship {
    /// Analytical relevance / heuristic alignment without asserting confirmed malware presence.
    #[default]
    Analytical,
}

impl MitreAttackRelationship {
    /// Returns the static string representation of the relationship.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Analytical => "Analytical",
        }
    }
}

impl fmt::Display for MitreAttackRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated MITRE ATT&CK technique or sub-technique identifier (e.g. `T1071` or `T1071.004`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreAttackId {
    id: String,
}

impl MitreAttackId {
    /// Creates and validates a new MITRE ATT&CK identifier.
    ///
    /// Must match `T` followed by 4 ascii digits, optionally followed by `.` and 3 ascii digits.
    /// Leading/trailing whitespace is strictly prohibited and will cause validation to fail.
    pub fn try_new(id: impl AsRef<str>) -> Result<Self, MitreAttackValidationError> {
        let raw = id.as_ref();
        if raw.is_empty() {
            return Err(MitreAttackValidationError::EmptyTechniqueId);
        }
        if raw.len() > MAX_MITRE_ATTACK_ID_LENGTH {
            return Err(MitreAttackValidationError::TechniqueIdTooLong {
                length: raw.len(),
                max: MAX_MITRE_ATTACK_ID_LENGTH,
            });
        }

        let bytes = raw.as_bytes();
        if bytes[0] != b'T' {
            return Err(MitreAttackValidationError::InvalidTechniqueIdFormat(
                raw.to_string(),
            ));
        }

        // Format: T#### or T####.###
        if bytes.len() == 5 {
            // T####
            if bytes[1..5].iter().all(u8::is_ascii_digit) {
                return Ok(Self {
                    id: raw.to_string(),
                });
            }
        } else if bytes.len() == 9 {
            // T####.###
            if bytes[1..5].iter().all(u8::is_ascii_digit)
                && bytes[5] == b'.'
                && bytes[6..9].iter().all(u8::is_ascii_digit)
            {
                return Ok(Self {
                    id: raw.to_string(),
                });
            }
        }

        Err(MitreAttackValidationError::InvalidTechniqueIdFormat(
            raw.to_string(),
        ))
    }

    /// Returns the MITRE ATT&CK ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Returns `true` if this identifier represents a sub-technique (contains a `.`).
    #[must_use]
    pub fn is_sub_technique(&self) -> bool {
        self.id.contains('.')
    }
}

impl fmt::Display for MitreAttackId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

impl FromStr for MitreAttackId {
    type Err = MitreAttackValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

/// MITRE Enterprise ATT&CK Tactic classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MitreTactic {
    /// Initial Access (TA0001).
    InitialAccess,
    /// Execution (TA0002).
    Execution,
    /// Persistence (TA0003).
    Persistence,
    /// Privilege Escalation (TA0004).
    PrivilegeEscalation,
    /// Defense Evasion (TA0005).
    DefenseEvasion,
    /// Credential Access (TA0006).
    CredentialAccess,
    /// Discovery (TA0007).
    Discovery,
    /// Lateral Movement (TA0008).
    LateralMovement,
    /// Collection (TA0009).
    Collection,
    /// Command and Control (TA0011).
    CommandAndControl,
    /// Exfiltration (TA0010).
    Exfiltration,
    /// Impact (TA0040).
    Impact,
}

impl MitreTactic {
    /// Returns the static string representation of the tactic.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }

    /// Returns the stable MITRE ATT&CK tactic ID (e.g. `TA0011`).
    #[must_use]
    pub const fn tactic_id(&self) -> &'static str {
        match self {
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }
}

impl fmt::Display for MitreTactic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated explanation of why a detector finding relates to a MITRE ATT&CK technique.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreMappingRationale {
    text: String,
}

impl MitreMappingRationale {
    /// Creates and validates a new mapping rationale.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, MitreAttackValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(MitreAttackValidationError::EmptyRationale);
        }
        if raw.len() > MAX_MITRE_RATIONALE_LENGTH {
            return Err(MitreAttackValidationError::RationaleTooLong {
                length: raw.len(),
                max: MAX_MITRE_RATIONALE_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(MitreAttackValidationError::RationaleControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }
        Ok(Self {
            text: raw.to_string(),
        })
    }

    /// Returns the rationale as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for MitreMappingRationale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Engine-owned provenance recording the origin of a MITRE ATT&CK mapping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MitreMappingProvenance {
    /// Mapping declared statically by a primary detector.
    DetectorDeclared {
        /// Originating detector identifier.
        detector_id: DetectorId,
        /// Originating detector version.
        detector_version: DetectorVersion,
    },
    /// Mapping declared statically by a cross-detector correlator.
    CorrelatorDeclared {
        /// Originating correlator identifier.
        correlator_id: DetectorId,
        /// Originating correlator version.
        correlator_version: DetectorVersion,
    },
}

impl fmt::Display for MitreMappingProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DetectorDeclared {
                detector_id,
                detector_version,
            } => write!(f, "detector:{detector_id}@{detector_version}"),
            Self::CorrelatorDeclared {
                correlator_id,
                correlator_version,
            } => write!(f, "correlator:{correlator_id}@{correlator_version}"),
        }
    }
}

/// Component-level analytical MITRE ATT&CK mapping declaration without component provenance.
///
/// Declared statically on [`crate::finding::DetectorId`]-associated metadata.
/// Component provenance is stamped exclusively by the detection engine during finding construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreMappingDeclaration {
    domain: MitreAttackDomain,
    catalog_version: MitreAttackCatalogVersion,
    technique_id: MitreAttackId,
    technique_name: String,
    technique_version: MitreAttackObjectVersion,
    tactic: MitreTactic,
    relationship: MitreAttackRelationship,
    rationale: MitreMappingRationale,
}

impl MitreMappingDeclaration {
    /// Creates and validates a new MITRE mapping declaration.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        domain: MitreAttackDomain,
        catalog_version: MitreAttackCatalogVersion,
        technique_id: MitreAttackId,
        technique_name: impl Into<String>,
        technique_version: MitreAttackObjectVersion,
        tactic: MitreTactic,
        relationship: MitreAttackRelationship,
        rationale: MitreMappingRationale,
    ) -> Result<Self, MitreAttackValidationError> {
        let name = technique_name.into();
        if name.is_empty() {
            return Err(MitreAttackValidationError::EmptyTechniqueName);
        }
        if name.len() > MAX_MITRE_TECHNIQUE_NAME_LENGTH {
            return Err(MitreAttackValidationError::TechniqueNameTooLong {
                length: name.len(),
                max: MAX_MITRE_TECHNIQUE_NAME_LENGTH,
            });
        }
        for c in name.chars() {
            if c.is_control() {
                return Err(MitreAttackValidationError::TechniqueNameControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }

        Ok(Self {
            domain,
            catalog_version,
            technique_id,
            technique_name: name,
            technique_version,
            tactic,
            relationship,
            rationale,
        })
    }

    /// Returns the ATT&CK domain.
    #[must_use]
    pub const fn domain(&self) -> MitreAttackDomain {
        self.domain
    }

    /// Returns the catalog knowledge base version.
    #[must_use]
    pub const fn catalog_version(&self) -> MitreAttackCatalogVersion {
        self.catalog_version
    }

    /// Returns the technique identifier (e.g. `T1071.004`).
    #[must_use]
    pub const fn technique_id(&self) -> &MitreAttackId {
        &self.technique_id
    }

    /// Returns the human-readable technique name.
    #[must_use]
    pub fn technique_name(&self) -> &str {
        &self.technique_name
    }

    /// Returns the technique object version.
    #[must_use]
    pub const fn technique_version(&self) -> MitreAttackObjectVersion {
        self.technique_version
    }

    /// Returns the associated tactic.
    #[must_use]
    pub const fn tactic(&self) -> MitreTactic {
        self.tactic
    }

    /// Returns the mapping relationship.
    #[must_use]
    pub const fn relationship(&self) -> MitreAttackRelationship {
        self.relationship
    }

    /// Returns the mapping rationale.
    #[must_use]
    pub const fn rationale(&self) -> &MitreMappingRationale {
        &self.rationale
    }
}

/// Canonical, engine-stamped MITRE ATT&CK mapping attached to a finding record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreMapping {
    domain: MitreAttackDomain,
    catalog_version: MitreAttackCatalogVersion,
    technique_id: MitreAttackId,
    technique_name: String,
    technique_version: MitreAttackObjectVersion,
    tactic: MitreTactic,
    relationship: MitreAttackRelationship,
    rationale: MitreMappingRationale,
    provenance: MitreMappingProvenance,
}

impl MitreMapping {
    /// Creates a canonical MITRE mapping by attaching engine-owned provenance to a validated declaration.
    #[must_use]
    pub fn from_declaration(
        declaration: &MitreMappingDeclaration,
        provenance: MitreMappingProvenance,
    ) -> Self {
        Self {
            domain: declaration.domain(),
            catalog_version: declaration.catalog_version(),
            technique_id: declaration.technique_id().clone(),
            technique_name: declaration.technique_name().to_string(),
            technique_version: declaration.technique_version(),
            tactic: declaration.tactic(),
            relationship: declaration.relationship(),
            rationale: declaration.rationale().clone(),
            provenance,
        }
    }

    /// Creates and validates a new canonical MITRE mapping with explicit provenance.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        domain: MitreAttackDomain,
        catalog_version: MitreAttackCatalogVersion,
        technique_id: MitreAttackId,
        technique_name: impl Into<String>,
        technique_version: MitreAttackObjectVersion,
        tactic: MitreTactic,
        relationship: MitreAttackRelationship,
        rationale: MitreMappingRationale,
        provenance: MitreMappingProvenance,
    ) -> Result<Self, MitreAttackValidationError> {
        let decl = MitreMappingDeclaration::try_new(
            domain,
            catalog_version,
            technique_id,
            technique_name,
            technique_version,
            tactic,
            relationship,
            rationale,
        )?;
        Ok(Self::from_declaration(&decl, provenance))
    }

    /// Returns the ATT&CK domain.
    #[must_use]
    pub const fn domain(&self) -> MitreAttackDomain {
        self.domain
    }

    /// Returns the catalog knowledge base version.
    #[must_use]
    pub const fn catalog_version(&self) -> MitreAttackCatalogVersion {
        self.catalog_version
    }

    /// Returns the technique identifier (e.g. `T1071.004`).
    #[must_use]
    pub const fn technique_id(&self) -> &MitreAttackId {
        &self.technique_id
    }

    /// Returns the human-readable technique name.
    #[must_use]
    pub fn technique_name(&self) -> &str {
        &self.technique_name
    }

    /// Returns the technique object version.
    #[must_use]
    pub const fn technique_version(&self) -> MitreAttackObjectVersion {
        self.technique_version
    }

    /// Returns the associated tactic.
    #[must_use]
    pub const fn tactic(&self) -> MitreTactic {
        self.tactic
    }

    /// Returns the mapping relationship.
    #[must_use]
    pub const fn relationship(&self) -> MitreAttackRelationship {
        self.relationship
    }

    /// Returns the mapping rationale.
    #[must_use]
    pub const fn rationale(&self) -> &MitreMappingRationale {
        &self.rationale
    }

    /// Returns the engine-owned provenance of the mapping.
    #[must_use]
    pub const fn provenance(&self) -> &MitreMappingProvenance {
        &self.provenance
    }
}

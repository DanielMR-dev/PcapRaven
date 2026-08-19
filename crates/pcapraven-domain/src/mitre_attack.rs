//! MITRE ATT&CK domain models and mapping provenance for analytical findings.
//!
//! Represents conservative, auditable mappings to MITRE Enterprise ATT&CK (v19.2)
//! techniques and tactics with engine-owned provenance and explicit non-attribution rationales.

use crate::finding::{DetectorId, DetectorVersion, FindingValidationError};
use core::fmt;
use std::str::FromStr;

/// Supported MITRE Enterprise ATT&CK knowledge base version.
pub const MITRE_ATTACK_VERSION: &str = "v19.2";

/// Maximum allowed byte length for a MITRE ATT&CK identifier (16 bytes, e.g. "T1071.004").
pub const MAX_MITRE_ATTACK_ID_LENGTH: usize = 16;

/// Maximum allowed byte length for a MITRE technique name (128 bytes).
pub const MAX_MITRE_TECHNIQUE_NAME_LENGTH: usize = 128;

/// Maximum allowed byte length for a MITRE mapping rationale (1,024 bytes).
pub const MAX_MITRE_RATIONALE_LENGTH: usize = 1_024;

/// Hard maximum MITRE mappings per finding (16).
pub const HARD_MAX_MITRE_MAPPINGS_PER_FINDING: usize = 16;

/// Validated MITRE ATT&CK technique or sub-technique identifier (e.g. `T1071` or `T1071.004`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreAttackId {
    id: String,
}

impl MitreAttackId {
    /// Creates and validates a new MITRE ATT&CK identifier.
    ///
    /// Must match `T` followed by 4 digits, optionally followed by `.` and 3 digits.
    pub fn try_new(id: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = id.as_ref();
        if raw.is_empty() || raw.len() > MAX_MITRE_ATTACK_ID_LENGTH {
            return Err(FindingValidationError::InvalidDetectorIdCharacter { character: ' ' });
        }

        let bytes = raw.as_bytes();
        if bytes[0] != b'T' {
            return Err(FindingValidationError::InvalidDetectorIdCharacter {
                character: bytes[0] as char,
            });
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

        Err(FindingValidationError::InvalidDetectorIdCharacter {
            character: bytes.first().copied().unwrap_or(b' ') as char,
        })
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
    type Err = FindingValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s.trim())
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
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyFindingRationale);
        }
        if raw.len() > MAX_MITRE_RATIONALE_LENGTH {
            return Err(FindingValidationError::FindingRationaleTooLong {
                length: raw.len(),
                max: MAX_MITRE_RATIONALE_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(FindingValidationError::FindingRationaleControlCharacter {
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

/// Canonical MITRE ATT&CK mapping attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MitreMapping {
    technique_id: MitreAttackId,
    technique_name: String,
    tactic: MitreTactic,
    rationale: MitreMappingRationale,
    provenance: MitreMappingProvenance,
}

impl MitreMapping {
    /// Creates and validates a new canonical MITRE mapping.
    pub fn try_new(
        technique_id: MitreAttackId,
        technique_name: impl Into<String>,
        tactic: MitreTactic,
        rationale: MitreMappingRationale,
        provenance: MitreMappingProvenance,
    ) -> Result<Self, FindingValidationError> {
        let name = technique_name.into();
        if name.is_empty() {
            return Err(FindingValidationError::EmptyFindingTitle);
        }
        if name.len() > MAX_MITRE_TECHNIQUE_NAME_LENGTH {
            return Err(FindingValidationError::FindingTitleTooLong {
                length: name.len(),
                max: MAX_MITRE_TECHNIQUE_NAME_LENGTH,
            });
        }
        for c in name.chars() {
            if c.is_control() {
                return Err(FindingValidationError::FindingTitleControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }

        Ok(Self {
            technique_id,
            technique_name: name,
            tactic,
            rationale,
            provenance,
        })
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

    /// Returns the associated tactic.
    #[must_use]
    pub const fn tactic(&self) -> MitreTactic {
        self.tactic
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

//! Finding domain concepts, stable detector identity, severity, confidence, and structured subjects.
//!
//! Findings represent interpreted analytical results supported by factual evidence records,
//! referencing normalized flows, packets, and observations.

use crate::evidence::{EvidenceDraft, EvidenceReference};
use crate::flow::FlowReference;
use crate::mitre_attack::{HARD_MAX_MITRE_MAPPINGS_PER_FINDING, MitreAttackId, MitreMapping};
use crate::observation::ObservationReference;
use crate::packet::PacketReference;
use core::fmt;

/// Maximum allowed byte length for a detector identifier (96 bytes).
pub const MAX_DETECTOR_ID_LENGTH: usize = 96;

/// Maximum allowed byte length for a finding title (128 bytes).
pub const MAX_FINDING_TITLE_LENGTH: usize = 128;

/// Maximum allowed byte length for a finding summary (512 bytes).
pub const MAX_FINDING_SUMMARY_LENGTH: usize = 512;

/// Maximum allowed byte length for a finding rationale (2,048 bytes).
pub const MAX_FINDING_RATIONALE_LENGTH: usize = 2_048;

/// Errors that can occur during finding domain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingValidationError {
    /// Detector identifier must not be empty.
    EmptyDetectorId,
    /// Detector identifier exceeds the maximum allowed length.
    DetectorIdTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Detector identifier contains an invalid character or does not match namespaced grammar.
    InvalidDetectorIdCharacter {
        /// Invalid character.
        character: char,
    },
    /// Detector identifier must contain at least one namespace separator dot ('.') separating non-empty segments.
    InvalidDetectorIdNamespace,
    /// Finding title must not be empty.
    EmptyFindingTitle,
    /// Finding title exceeds maximum length.
    FindingTitleTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Finding title contains a prohibited control character.
    FindingTitleControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Finding summary must not be empty.
    EmptyFindingSummary,
    /// Finding summary exceeds maximum length.
    FindingSummaryTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Finding summary contains a prohibited control character.
    FindingSummaryControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Finding rationale must not be empty.
    EmptyFindingRationale,
    /// Finding rationale exceeds maximum length.
    FindingRationaleTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Finding rationale contains a prohibited control character.
    FindingRationaleControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Finding subject must contain at least one packet, flow, or observation reference.
    EmptyFindingSubject,
    /// Number of packet references in finding subject exceeds limit.
    SubjectPacketReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of flow references in finding subject exceeds limit.
    SubjectFlowReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of observation references in finding subject exceeds limit.
    SubjectObservationReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Duplicate packet reference in finding subject.
    DuplicateSubjectPacketReference(PacketReference),
    /// Packet references in finding subject must be strictly increasing.
    OutOfOrderSubjectPacketReference {
        /// Previous packet ordinal.
        previous: u64,
        /// Attempted packet ordinal.
        attempted: u64,
    },
    /// Duplicate flow reference in finding subject.
    DuplicateSubjectFlowReference(FlowReference),
    /// Flow references in finding subject must be strictly increasing.
    OutOfOrderSubjectFlowReference {
        /// Previous flow ordinal.
        previous: u64,
        /// Attempted flow ordinal.
        attempted: u64,
    },
    /// Duplicate observation reference in finding subject.
    DuplicateSubjectObservationReference(ObservationReference),
    /// Observation references in finding subject must be strictly increasing.
    OutOfOrderSubjectObservationReference {
        /// Previous observation reference.
        previous: ObservationReference,
        /// Attempted observation reference.
        attempted: ObservationReference,
    },
    /// Finding must contain at least one supporting evidence item.
    FindingWithoutEvidence,
    /// Number of evidence drafts in finding draft exceeds limit.
    FindingEvidenceExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of evidence references in finding record exceeds limit.
    EvidenceReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Finding contains a duplicate evidence reference.
    DuplicateEvidenceReference(EvidenceReference),
    /// Evidence references in finding must be strictly increasing.
    OutOfOrderEvidenceReference {
        /// Previous evidence ordinal.
        previous: u64,
        /// Attempted evidence ordinal.
        attempted: u64,
    },
    /// Number of source finding references is below the required minimum.
    InsufficientSourceFindingReferences {
        /// Current count.
        count: usize,
        /// Minimum required count.
        minimum: usize,
    },
    /// Number of source finding references in finding record exceeds limit.
    SourceFindingReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Duplicate source finding reference in finding record.
    DuplicateSourceFindingReference(FindingReference),
    /// Source finding references in finding record must be strictly increasing.
    OutOfOrderSourceFindingReference {
        /// Previous finding ordinal.
        previous: u64,
        /// Attempted finding ordinal.
        attempted: u64,
    },
    /// Number of MITRE ATT&CK mappings exceeds limit.
    MitreMappingsExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Duplicate MITRE ATT&CK mapping on finding.
    DuplicateMitreMapping(MitreAttackId),
    /// MITRE ATT&CK mappings must be strictly increasing by technique ID.
    OutOfOrderMitreMapping {
        /// Previous technique ID.
        previous: String,
        /// Attempted technique ID.
        attempted: String,
    },
    /// Invalid severity string.
    InvalidSeverity(String),
    /// Invalid confidence string.
    InvalidConfidence(String),
}

impl fmt::Display for FindingValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDetectorId => f.write_str("detector identifier cannot be empty"),
            Self::DetectorIdTooLong { length, max } => write!(
                f,
                "detector identifier length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::InvalidDetectorIdCharacter { character } => write!(
                f,
                "detector identifier contains invalid character '{character}'"
            ),
            Self::InvalidDetectorIdNamespace => f.write_str(
                "detector identifier must contain namespaced dot-separated lowercase ASCII segments"
            ),
            Self::EmptyFindingTitle => f.write_str("finding title cannot be empty"),
            Self::FindingTitleTooLong { length, max } => write!(
                f,
                "finding title length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::FindingTitleControlCharacter { byte } => write!(
                f,
                "finding title contains prohibited control character 0x{byte:02x}"
            ),
            Self::EmptyFindingSummary => f.write_str("finding summary cannot be empty"),
            Self::FindingSummaryTooLong { length, max } => write!(
                f,
                "finding summary length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::FindingSummaryControlCharacter { byte } => write!(
                f,
                "finding summary contains prohibited control character 0x{byte:02x}"
            ),
            Self::EmptyFindingRationale => f.write_str("finding rationale cannot be empty"),
            Self::FindingRationaleTooLong { length, max } => write!(
                f,
                "finding rationale length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::FindingRationaleControlCharacter { byte } => write!(
                f,
                "finding rationale contains prohibited control character 0x{byte:02x}"
            ),
            Self::EmptyFindingSubject => {
                f.write_str("finding subject must reference at least one entity")
            }
            Self::SubjectPacketReferencesExceeded { count, max } => write!(
                f,
                "finding subject packet reference count ({count}) exceeds maximum ({max})"
            ),
            Self::SubjectFlowReferencesExceeded { count, max } => write!(
                f,
                "finding subject flow reference count ({count}) exceeds maximum ({max})"
            ),
            Self::SubjectObservationReferencesExceeded { count, max } => write!(
                f,
                "finding subject observation reference count ({count}) exceeds maximum ({max})"
            ),
            Self::DuplicateSubjectPacketReference(p) => write!(
                f,
                "duplicate packet reference pkt:{} in finding subject",
                p.capture_record_ordinal()
            ),
            Self::OutOfOrderSubjectPacketReference {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order packet reference in finding subject: attempted pkt:{attempted} after pkt:{previous}"
            ),
            Self::DuplicateSubjectFlowReference(flow) => write!(
                f,
                "duplicate flow reference flow:{} in finding subject",
                flow.ordinal()
            ),
            Self::OutOfOrderSubjectFlowReference {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order flow reference in finding subject: attempted flow:{attempted} after flow:{previous}"
            ),
            Self::DuplicateSubjectObservationReference(obs) => write!(
                f,
                "duplicate observation reference {obs} in finding subject"
            ),
            Self::OutOfOrderSubjectObservationReference {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order observation reference in finding subject: attempted {attempted} after {previous}"
            ),
            Self::FindingWithoutEvidence => {
                f.write_str("finding must contain at least one supporting evidence record")
            }
            Self::FindingEvidenceExceeded { count, max } => write!(
                f,
                "finding evidence draft count ({count}) exceeds maximum ({max})"
            ),
            Self::EvidenceReferencesExceeded { count, max } => write!(
                f,
                "finding evidence reference count ({count}) exceeds maximum ({max})"
            ),
            Self::DuplicateEvidenceReference(e) => {
                write!(f, "duplicate evidence reference {e} in finding")
            }
            Self::OutOfOrderEvidenceReference {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order evidence reference in finding: attempted evi:{attempted} after evi:{previous}"
            ),
            Self::InsufficientSourceFindingReferences { count, minimum } => write!(
                f,
                "insufficient source finding references ({count} < required {minimum})"
            ),
            Self::SourceFindingReferencesExceeded { count, max } => write!(
                f,
                "finding source finding reference count ({count}) exceeds maximum ({max})"
            ),
            Self::DuplicateSourceFindingReference(fr) => {
                write!(f, "duplicate source finding reference {fr} in finding")
            }
            Self::OutOfOrderSourceFindingReference {
                previous,
                attempted,
            } => write!(
                f,
                "out-of-order source finding reference in finding: attempted find:{attempted} after find:{previous}"
            ),
            Self::MitreMappingsExceeded { count, max } => write!(
                f,
                "finding MITRE ATT&CK mapping count ({count}) exceeds maximum ({max})"
            ),
            Self::DuplicateMitreMapping(t) => {
                write!(f, "duplicate MITRE ATT&CK mapping for technique {t} on finding")
            }
            Self::OutOfOrderMitreMapping { previous, attempted } => write!(
                f,
                "out-of-order MITRE ATT&CK mapping on finding: attempted {attempted} after {previous}"
            ),
            Self::InvalidSeverity(s) => write!(f, "invalid severity '{s}': expected info, low, medium, high, or critical"),
            Self::InvalidConfidence(s) => write!(f, "invalid confidence '{s}': expected low, medium, or high"),
        }
    }
}

impl std::error::Error for FindingValidationError {}

/// Stable, namespaced identifier for a detector.
///
/// Encapsulates lowercase ASCII dot-separated segments (e.g. `test.synthetic.detector`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorId {
    id: String,
}

impl DetectorId {
    /// Creates and validates a new detector identifier.
    pub fn try_new(id: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = id.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyDetectorId);
        }
        if raw.len() > MAX_DETECTOR_ID_LENGTH {
            return Err(FindingValidationError::DetectorIdTooLong {
                length: raw.len(),
                max: MAX_DETECTOR_ID_LENGTH,
            });
        }

        let segments: Vec<&str> = raw.split('.').collect();
        if segments.len() < 2 {
            return Err(FindingValidationError::InvalidDetectorIdNamespace);
        }

        for segment in segments {
            if segment.is_empty() {
                return Err(FindingValidationError::InvalidDetectorIdNamespace);
            }
            let bytes = segment.as_bytes();
            let first = bytes[0];
            if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
                return Err(FindingValidationError::InvalidDetectorIdCharacter {
                    character: first as char,
                });
            }
            for &b in &bytes[1..] {
                if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'-' && b != b'_' {
                    return Err(FindingValidationError::InvalidDetectorIdCharacter {
                        character: b as char,
                    });
                }
            }
        }

        Ok(Self {
            id: raw.to_string(),
        })
    }

    /// Returns the detector identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for DetectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}

/// Independent version of a detector's analytical logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorVersion {
    /// Major version number (incompatible analytical changes).
    pub major: u16,
    /// Minor version number (backward-compatible additions/heuristics).
    pub minor: u16,
    /// Patch version number (bug fixes, parameter tuning).
    pub patch: u16,
}

impl DetectorVersion {
    /// Creates a new detector version.
    #[must_use]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for DetectorVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Foundational severity classification for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational context without direct security risk.
    Info,
    /// Low security impact or minor anomaly.
    Low,
    /// Medium security impact or notable suspicious activity.
    Medium,
    /// High security impact or strong threat indicator.
    High,
    /// Critical security impact or confirmed severe compromise.
    Critical,
}

impl Severity {
    /// Returns the static string representation of the severity level.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for Severity {
    type Err = FindingValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim().to_ascii_lowercase();
        match clean.as_str() {
            "info" | "informational" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(FindingValidationError::InvalidSeverity(s.to_string())),
        }
    }
}

/// Foundational analytical confidence level for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Low analytical confidence (possible alternative explanations exist).
    Low,
    /// Medium analytical confidence (solid indicators with minor ambiguity).
    Medium,
    /// High analytical confidence (direct, unambiguous evidence).
    High,
}

impl Confidence {
    /// Returns the static string representation of the confidence level.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::str::FromStr for Confidence {
    type Err = FindingValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim().to_ascii_lowercase();
        match clean.as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(FindingValidationError::InvalidConfidence(s.to_string())),
        }
    }
}

/// Monotonically assigned unique identifier for a finding within a detection run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FindingReference {
    id: u64,
}

impl FindingReference {
    /// Creates a new finding reference.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Returns the numeric identifier of this finding.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

impl fmt::Display for FindingReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "find:{}", self.id)
    }
}

/// Concise, terminal-safe finding title.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingTitle {
    text: String,
}

impl FindingTitle {
    /// Creates and validates a new finding title.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyFindingTitle);
        }
        if raw.len() > MAX_FINDING_TITLE_LENGTH {
            return Err(FindingValidationError::FindingTitleTooLong {
                length: raw.len(),
                max: MAX_FINDING_TITLE_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(FindingValidationError::FindingTitleControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }
        Ok(Self {
            text: raw.to_string(),
        })
    }

    /// Returns the title as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for FindingTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Concise, terminal-safe finding summary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingSummary {
    text: String,
}

impl FindingSummary {
    /// Creates and validates a new finding summary.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyFindingSummary);
        }
        if raw.len() > MAX_FINDING_SUMMARY_LENGTH {
            return Err(FindingValidationError::FindingSummaryTooLong {
                length: raw.len(),
                max: MAX_FINDING_SUMMARY_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(FindingValidationError::FindingSummaryControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }
        Ok(Self {
            text: raw.to_string(),
        })
    }

    /// Returns the summary as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for FindingSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Detailed, terminal-safe finding rationale explaining why the detector matched.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingRationale {
    text: String,
}

impl FindingRationale {
    /// Creates and validates a new finding rationale.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, FindingValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(FindingValidationError::EmptyFindingRationale);
        }
        if raw.len() > MAX_FINDING_RATIONALE_LENGTH {
            return Err(FindingValidationError::FindingRationaleTooLong {
                length: raw.len(),
                max: MAX_FINDING_RATIONALE_LENGTH,
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

impl fmt::Display for FindingRationale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Bounded, deterministic subject identifying the traffic entities involved in a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingSubject {
    packet_references: Vec<PacketReference>,
    flow_references: Vec<FlowReference>,
    observation_references: Vec<ObservationReference>,
}

impl FindingSubject {
    /// Hard maximum packet references per finding subject (1,024).
    pub const HARD_MAX_PACKET_REFERENCES: usize = 1_024;
    /// Hard maximum flow references per finding subject (256).
    pub const HARD_MAX_FLOW_REFERENCES: usize = 256;
    /// Hard maximum observation references per finding subject (4,096).
    pub const HARD_MAX_OBSERVATION_REFERENCES: usize = 4_096;

    /// Creates and validates a new finding subject.
    ///
    /// References must be strictly increasing and non-empty in total.
    pub fn try_new(
        packet_references: Vec<PacketReference>,
        flow_references: Vec<FlowReference>,
        observation_references: Vec<ObservationReference>,
    ) -> Result<Self, FindingValidationError> {
        if packet_references.is_empty()
            && flow_references.is_empty()
            && observation_references.is_empty()
        {
            return Err(FindingValidationError::EmptyFindingSubject);
        }

        if packet_references.len() > Self::HARD_MAX_PACKET_REFERENCES {
            return Err(FindingValidationError::SubjectPacketReferencesExceeded {
                count: packet_references.len(),
                max: Self::HARD_MAX_PACKET_REFERENCES,
            });
        }
        for window in packet_references.windows(2) {
            let prev = window[0].capture_record_ordinal();
            let curr = window[1].capture_record_ordinal();
            if curr == prev {
                return Err(FindingValidationError::DuplicateSubjectPacketReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderSubjectPacketReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        if flow_references.len() > Self::HARD_MAX_FLOW_REFERENCES {
            return Err(FindingValidationError::SubjectFlowReferencesExceeded {
                count: flow_references.len(),
                max: Self::HARD_MAX_FLOW_REFERENCES,
            });
        }
        for window in flow_references.windows(2) {
            let prev = window[0].ordinal();
            let curr = window[1].ordinal();
            if curr == prev {
                return Err(FindingValidationError::DuplicateSubjectFlowReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderSubjectFlowReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        if observation_references.len() > Self::HARD_MAX_OBSERVATION_REFERENCES {
            return Err(
                FindingValidationError::SubjectObservationReferencesExceeded {
                    count: observation_references.len(),
                    max: Self::HARD_MAX_OBSERVATION_REFERENCES,
                },
            );
        }
        for window in observation_references.windows(2) {
            let prev = window[0];
            let curr = window[1];
            if curr == prev {
                return Err(FindingValidationError::DuplicateSubjectObservationReference(curr));
            }
            if curr < prev {
                return Err(
                    FindingValidationError::OutOfOrderSubjectObservationReference {
                        previous: prev,
                        attempted: curr,
                    },
                );
            }
        }

        Ok(Self {
            packet_references,
            flow_references,
            observation_references,
        })
    }

    /// Returns the ordered slice of packet references.
    #[must_use]
    pub fn packet_references(&self) -> &[PacketReference] {
        &self.packet_references
    }

    /// Returns the ordered slice of flow references.
    #[must_use]
    pub fn flow_references(&self) -> &[FlowReference] {
        &self.flow_references
    }

    /// Returns the ordered slice of observation references.
    #[must_use]
    pub fn observation_references(&self) -> &[ObservationReference] {
        &self.observation_references
    }
}

/// Draft finding emitted by a detector before canonical identity assignment and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDraft {
    subject: FindingSubject,
    title: FindingTitle,
    summary: FindingSummary,
    rationale: FindingRationale,
    severity: Severity,
    confidence: Confidence,
    evidence: Vec<EvidenceDraft>,
}

impl FindingDraft {
    /// Default maximum evidence drafts per finding (64).
    pub const DEFAULT_MAX_EVIDENCE_DRAFTS: usize = 64;
    /// Hard maximum evidence drafts per finding (256).
    pub const HARD_MAX_EVIDENCE_DRAFTS: usize = 256;

    /// Creates a validated finding draft.
    pub fn try_new(
        subject: FindingSubject,
        title: FindingTitle,
        summary: FindingSummary,
        rationale: FindingRationale,
        severity: Severity,
        confidence: Confidence,
        evidence: Vec<EvidenceDraft>,
    ) -> Result<Self, FindingValidationError> {
        if evidence.is_empty() {
            return Err(FindingValidationError::FindingWithoutEvidence);
        }
        if evidence.len() > Self::HARD_MAX_EVIDENCE_DRAFTS {
            return Err(FindingValidationError::FindingEvidenceExceeded {
                count: evidence.len(),
                max: Self::HARD_MAX_EVIDENCE_DRAFTS,
            });
        }
        Ok(Self {
            subject,
            title,
            summary,
            rationale,
            severity,
            confidence,
            evidence,
        })
    }

    /// Returns the finding subject.
    #[must_use]
    pub const fn subject(&self) -> &FindingSubject {
        &self.subject
    }

    /// Returns the finding title.
    #[must_use]
    pub const fn title(&self) -> &FindingTitle {
        &self.title
    }

    /// Returns the finding summary.
    #[must_use]
    pub const fn summary(&self) -> &FindingSummary {
        &self.summary
    }

    /// Returns the finding rationale.
    #[must_use]
    pub const fn rationale(&self) -> &FindingRationale {
        &self.rationale
    }

    /// Returns the severity level.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the confidence level.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the supporting evidence drafts.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceDraft] {
        &self.evidence
    }

    /// Consumes the draft, returning its evidence drafts.
    #[must_use]
    pub fn into_evidence(self) -> Vec<EvidenceDraft> {
        self.evidence
    }
}

/// Canonical, immutable finding record with engine-assigned identities and validated evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRecord {
    reference: FindingReference,
    detector_id: DetectorId,
    detector_version: DetectorVersion,
    subject: FindingSubject,
    title: FindingTitle,
    summary: FindingSummary,
    rationale: FindingRationale,
    severity: Severity,
    confidence: Confidence,
    evidence_references: Vec<EvidenceReference>,
    source_finding_references: Vec<FindingReference>,
    mitre_mappings: Vec<MitreMapping>,
}

impl FindingRecord {
    /// Default maximum source finding references per finding (64).
    pub const DEFAULT_MAX_SOURCE_FINDING_REFERENCES: usize = 64;
    /// Hard maximum source finding references per finding (256).
    pub const HARD_MAX_SOURCE_FINDING_REFERENCES: usize = 256;

    /// Creates a new canonical finding record.
    ///
    /// Validates that evidence references are non-empty and strictly increasing,
    /// and that source finding references (if present) are bounded and strictly increasing.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        reference: FindingReference,
        detector_id: DetectorId,
        detector_version: DetectorVersion,
        subject: FindingSubject,
        title: FindingTitle,
        summary: FindingSummary,
        rationale: FindingRationale,
        severity: Severity,
        confidence: Confidence,
        evidence_references: Vec<EvidenceReference>,
        source_finding_references: Vec<FindingReference>,
        mitre_mappings: Vec<MitreMapping>,
    ) -> Result<Self, FindingValidationError> {
        if evidence_references.is_empty() {
            return Err(FindingValidationError::FindingWithoutEvidence);
        }

        for window in evidence_references.windows(2) {
            let prev = window[0].id();
            let curr = window[1].id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateEvidenceReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderEvidenceReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        if source_finding_references.len() > Self::HARD_MAX_SOURCE_FINDING_REFERENCES {
            return Err(FindingValidationError::SourceFindingReferencesExceeded {
                count: source_finding_references.len(),
                max: Self::HARD_MAX_SOURCE_FINDING_REFERENCES,
            });
        }

        for window in source_finding_references.windows(2) {
            let prev = window[0].id();
            let curr = window[1].id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateSourceFindingReference(
                    window[1],
                ));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderSourceFindingReference {
                    previous: prev,
                    attempted: curr,
                });
            }
        }

        if mitre_mappings.len() > HARD_MAX_MITRE_MAPPINGS_PER_FINDING {
            return Err(FindingValidationError::MitreMappingsExceeded {
                count: mitre_mappings.len(),
                max: HARD_MAX_MITRE_MAPPINGS_PER_FINDING,
            });
        }

        for window in mitre_mappings.windows(2) {
            let prev = window[0].technique_id();
            let curr = window[1].technique_id();
            if curr == prev {
                return Err(FindingValidationError::DuplicateMitreMapping(curr.clone()));
            }
            if curr < prev {
                return Err(FindingValidationError::OutOfOrderMitreMapping {
                    previous: prev.to_string(),
                    attempted: curr.to_string(),
                });
            }
        }

        Ok(Self {
            reference,
            detector_id,
            detector_version,
            subject,
            title,
            summary,
            rationale,
            severity,
            confidence,
            evidence_references,
            source_finding_references,
            mitre_mappings,
        })
    }

    /// Returns the engine-assigned finding reference.
    #[must_use]
    pub const fn reference(&self) -> FindingReference {
        self.reference
    }

    /// Returns the detector identifier.
    #[must_use]
    pub const fn detector_id(&self) -> &DetectorId {
        &self.detector_id
    }

    /// Returns the detector version.
    #[must_use]
    pub const fn detector_version(&self) -> DetectorVersion {
        self.detector_version
    }

    /// Returns the finding subject.
    #[must_use]
    pub const fn subject(&self) -> &FindingSubject {
        &self.subject
    }

    /// Returns the finding title.
    #[must_use]
    pub const fn title(&self) -> &FindingTitle {
        &self.title
    }

    /// Returns the finding summary.
    #[must_use]
    pub const fn summary(&self) -> &FindingSummary {
        &self.summary
    }

    /// Returns the finding rationale.
    #[must_use]
    pub const fn rationale(&self) -> &FindingRationale {
        &self.rationale
    }

    /// Returns the finding severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the finding confidence.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the ordered slice of supporting evidence references.
    #[must_use]
    pub fn evidence_references(&self) -> &[EvidenceReference] {
        &self.evidence_references
    }

    /// Returns the ordered slice of source finding references for correlated findings.
    #[must_use]
    pub fn source_finding_references(&self) -> &[FindingReference] {
        &self.source_finding_references
    }

    /// Returns the ordered slice of MITRE ATT&CK mappings.
    #[must_use]
    pub fn mitre_mappings(&self) -> &[MitreMapping] {
        &self.mitre_mappings
    }
}

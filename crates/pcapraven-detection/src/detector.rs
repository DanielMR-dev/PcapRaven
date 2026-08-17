//! Detector trait, metadata contracts, and incomplete data policies.

use crate::config::DetectorParameters;
use crate::engine::DetectionInput;
use crate::error::{DetectorConfigError, DetectorExecutionError};
use core::fmt;
use pcapraven_domain::{DetectorId, DetectorVersion, FindingDraft, FindingSummary, FindingTitle};

/// Policy declared by a detector regarding execution over incomplete/partial traffic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IncompleteDataPolicy {
    /// Skip evaluation entirely when input traffic analysis is partial.
    Skip,
    /// Allow evaluation on partial input, provided any emitted findings include supporting limitations.
    AllowWithLimitations,
}

impl IncompleteDataPolicy {
    /// Returns the static label for this policy.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Skip => "Skip",
            Self::AllowWithLimitations => "AllowWithLimitations",
        }
    }
}

impl fmt::Display for IncompleteDataPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immutable metadata identifying a detector and its behavioral contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorMetadata {
    id: DetectorId,
    version: DetectorVersion,
    title: FindingTitle,
    purpose: FindingSummary,
    incomplete_data_policy: IncompleteDataPolicy,
}

impl DetectorMetadata {
    /// Creates new detector metadata.
    #[must_use]
    pub const fn new(
        id: DetectorId,
        version: DetectorVersion,
        title: FindingTitle,
        purpose: FindingSummary,
        incomplete_data_policy: IncompleteDataPolicy,
    ) -> Self {
        Self {
            id,
            version,
            title,
            purpose,
            incomplete_data_policy,
        }
    }

    /// Returns the unique detector identifier.
    #[must_use]
    pub const fn id(&self) -> &DetectorId {
        &self.id
    }

    /// Returns the detector version.
    #[must_use]
    pub const fn version(&self) -> DetectorVersion {
        self.version
    }

    /// Returns the detector display title.
    #[must_use]
    pub const fn title(&self) -> &FindingTitle {
        &self.title
    }

    /// Returns the detector purpose summary.
    #[must_use]
    pub const fn purpose(&self) -> &FindingSummary {
        &self.purpose
    }

    /// Returns the detector incomplete data policy.
    #[must_use]
    pub const fn incomplete_data_policy(&self) -> IncompleteDataPolicy {
        self.incomplete_data_policy
    }
}

/// Pure, offline analytical detector evaluation contract.
///
/// Implementations must be pure functions of borrowed domain inputs and configuration parameters,
/// producing zero network, filesystem, or process side effects.
pub trait Detector: Send + Sync {
    /// Returns immutable metadata describing the detector.
    fn metadata(&self) -> &DetectorMetadata;

    /// Validates configuration parameters prior to execution.
    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError>;

    /// Evaluates normalized domain input facts against validated parameters, producing finding drafts.
    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
    ) -> Result<Vec<FindingDraft>, DetectorExecutionError>;
}

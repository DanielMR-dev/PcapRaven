//! Error model for flow reconstruction operations.

use crate::config::FlowConfigError;
use core::fmt;

/// Error returned by flow reconstruction operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// Invalid configuration parameters provided to the reconstructor.
    InvalidConfiguration(FlowConfigError),
    /// Packet ordinals were duplicate or not strictly increasing in capture stream order.
    NonMonotonicPacketOrder {
        /// Previously observed packet ordinal.
        previous_ordinal: u64,
        /// Current violating packet ordinal.
        current_ordinal: u64,
    },
    /// A normalized packet contained contradictory domain facts.
    InvalidNormalizedPacket {
        /// Explanation of the domain inconsistency.
        detail: &'static str,
    },
    /// A configured finite resource limit was reached.
    ResourceLimit {
        /// Name of the exhausted limit.
        limit: &'static str,
        /// Current resource count.
        value: usize,
        /// Configured limit threshold.
        max: usize,
    },
    /// An internal invariant was violated.
    InternalInvariant {
        /// Details of the invariant violation.
        detail: &'static str,
    },
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(err) => write!(f, "invalid flow configuration: {}", err),
            Self::NonMonotonicPacketOrder {
                previous_ordinal,
                current_ordinal,
            } => write!(
                f,
                "non-monotonic packet ordinal: observed {} after previous {}",
                current_ordinal, previous_ordinal
            ),
            Self::InvalidNormalizedPacket { detail } => {
                write!(f, "invalid normalized packet facts: {}", detail)
            }
            Self::ResourceLimit { limit, value, max } => {
                write!(
                    f,
                    "flow resource limit {} exhausted ({} >= {})",
                    limit, value, max
                )
            }
            Self::InternalInvariant { detail } => {
                write!(
                    f,
                    "internal flow reconstruction invariant violated: {}",
                    detail
                )
            }
        }
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfiguration(err) => Some(err),
            _ => None,
        }
    }
}

impl From<FlowConfigError> for FlowError {
    fn from(err: FlowConfigError) -> Self {
        Self::InvalidConfiguration(err)
    }
}

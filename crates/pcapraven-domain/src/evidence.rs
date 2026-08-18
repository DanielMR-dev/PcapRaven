//! Structured evidence records, measurements, exact rational ratios, and schema anchors.
//!
//! Evidence records provide immutable, factual supporting context for heuristic security
//! findings, referencing normalized packets, flows, and observations without copying
//! arbitrary unparsed payloads.

use crate::flow::FlowReference;
use crate::flow_metrics::FlowDuration;
use crate::observation::ObservationReference;
use crate::packet::PacketReference;
use core::fmt;

/// Greatest common divisor for exact rational reduction.
const fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Canonical schema version anchor for protocol observations.
pub const PROTOCOL_OBSERVATION_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0);

/// Canonical schema version anchor for structured evidence records.
pub const EVIDENCE_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 1);

/// Version of the structured evidence record schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion {
    /// Major schema version (incompatible changes).
    pub major: u16,
    /// Minor schema version (backward-compatible additions).
    pub minor: u16,
}

impl SchemaVersion {
    /// Current canonical schema version for structured evidence (v1.0).
    pub const CURRENT: Self = EVIDENCE_SCHEMA_VERSION;

    /// Creates a new schema version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the major version number.
    #[must_use]
    pub const fn major(&self) -> u16 {
        self.major
    }

    /// Returns the minor version number.
    #[must_use]
    pub const fn minor(&self) -> u16 {
        self.minor
    }

    /// Returns `true` if this schema version is backward-compatible with `required`.
    #[must_use]
    pub const fn is_compatible_with(&self, required: &Self) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}", self.major, self.minor)
    }
}

/// Monotonically assigned unique identifier for an evidence record within an analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EvidenceReference {
    id: u64,
}

impl EvidenceReference {
    /// Creates a new evidence reference.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Returns the numeric identifier of this evidence record.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

impl fmt::Display for EvidenceReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evi:{}", self.id)
    }
}

/// Category describing the provenance and analytical nature of an evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceKind {
    /// Measurement derived directly from packet-level headers or lengths.
    PacketMeasurement,
    /// Measurement derived from bidirectional flow traffic counters.
    FlowMeasurement,
    /// Evidence originating from decoded DNS, HTTP, or TLS protocol observations.
    ProtocolObservation,
    /// Exact temporal metric or inter-arrival calculation.
    TemporalMetric,
    /// Exact rational comparison or ratio measurement.
    RatioComparison,
    /// Factual protocol framing or structural observation.
    ProtocolFact,
}

impl EvidenceKind {
    /// Returns the static string representation of the evidence kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PacketMeasurement => "PacketMeasurement",
            Self::FlowMeasurement => "FlowMeasurement",
            Self::ProtocolObservation => "ProtocolObservation",
            Self::TemporalMetric => "TemporalMetric",
            Self::RatioComparison => "RatioComparison",
            Self::ProtocolFact => "ProtocolFact",
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors that can occur when validating evidence structures and measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValidationError {
    /// Description must not be empty.
    EmptyDescription,
    /// Description exceeds the maximum byte limit.
    DescriptionTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Description contains a prohibited control character.
    DescriptionControlCharacter {
        /// Prohibited byte value.
        byte: u8,
    },
    /// Metric key must not be empty.
    EmptyMetricKey,
    /// Metric key exceeds the maximum byte limit.
    MetricKeyTooLong {
        /// Actual byte length.
        length: usize,
        /// Maximum allowed byte length.
        max: usize,
    },
    /// Metric key contains an invalid character or does not match grammar `[a-z0-9][a-z0-9._-]*`.
    InvalidMetricKeyCharacter {
        /// Invalid character.
        character: char,
    },
    /// Observed value and threshold value have incompatible types.
    IncompatibleMeasurementTypes,
    /// Threshold value provided without a comparison operator.
    ThresholdWithoutComparison,
    /// Comparison operator provided without a threshold value.
    ComparisonWithoutThreshold,
    /// Measurement unit is incompatible with the value representation.
    IncompatibleUnitAndValue,
    /// Percentage value exceeds 100%.
    PercentageOutOfRange {
        /// Percentage value.
        value: u128,
    },
    /// Evidence record must contain at least one packet, flow, observation reference, or measurement.
    EmptyEvidenceRecord,
    /// Number of packet references exceeds the configured limit.
    PacketReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of flow references exceeds the configured limit.
    FlowReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of observation references exceeds the configured limit.
    ObservationReferencesExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of measurements exceeds the configured limit.
    MeasurementsExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Number of limitations exceeds the configured limit.
    LimitationsExceeded {
        /// Current count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },
    /// Duplicate packet reference.
    DuplicatePacketReference(PacketReference),
    /// Packet references must be strictly increasing.
    OutOfOrderPacketReference {
        /// Previous highest packet ordinal.
        previous: u64,
        /// Attempted packet ordinal.
        attempted: u64,
    },
    /// Duplicate flow reference.
    DuplicateFlowReference(FlowReference),
    /// Flow references must be strictly increasing.
    OutOfOrderFlowReference {
        /// Previous highest flow ordinal.
        previous: u64,
        /// Attempted flow ordinal.
        attempted: u64,
    },
    /// Duplicate observation reference.
    DuplicateObservationReference(ObservationReference),
    /// Observation references must be strictly increasing.
    OutOfOrderObservationReference {
        /// Previous highest observation reference.
        previous: ObservationReference,
        /// Attempted observation reference.
        attempted: ObservationReference,
    },
    /// Duplicate metric key within one evidence record.
    DuplicateMetricKey(EvidenceMetricKey),
    /// Duplicate limitation within one evidence record.
    DuplicateLimitation(EvidenceLimitation),
}

impl fmt::Display for EvidenceValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDescription => f.write_str("evidence description cannot be empty"),
            Self::DescriptionTooLong { length, max } => write!(
                f,
                "evidence description length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::DescriptionControlCharacter { byte } => write!(
                f,
                "evidence description contains prohibited control character byte 0x{byte:02x}"
            ),
            Self::EmptyMetricKey => f.write_str("evidence metric key cannot be empty"),
            Self::MetricKeyTooLong { length, max } => write!(
                f,
                "evidence metric key length ({length} bytes) exceeds maximum ({max} bytes)"
            ),
            Self::InvalidMetricKeyCharacter { character } => write!(
                f,
                "evidence metric key contains invalid character '{character}'"
            ),
            Self::IncompatibleMeasurementTypes => f.write_str(
                "observed measurement value and threshold value have incompatible types"
            ),
            Self::ThresholdWithoutComparison => f.write_str(
                "evidence threshold value provided without a comparison operator"
            ),
            Self::ComparisonWithoutThreshold => f.write_str(
                "evidence comparison operator provided without a threshold value"
            ),
            Self::IncompatibleUnitAndValue => {
                f.write_str("evidence measurement unit is incompatible with value type")
            }
            Self::PercentageOutOfRange { value } => {
                write!(f, "percentage value ({value}) exceeds 100")
            }
            Self::EmptyEvidenceRecord => f.write_str(
                "evidence record must contain at least one supporting packet, flow, observation, or measurement"
            ),
            Self::PacketReferencesExceeded { count, max } => write!(
                f,
                "packet references count ({count}) exceeds maximum ({max})"
            ),
            Self::FlowReferencesExceeded { count, max } => write!(
                f,
                "flow references count ({count}) exceeds maximum ({max})"
            ),
            Self::ObservationReferencesExceeded { count, max } => write!(
                f,
                "observation references count ({count}) exceeds maximum ({max})"
            ),
            Self::MeasurementsExceeded { count, max } => write!(
                f,
                "measurements count ({count}) exceeds maximum ({max})"
            ),
            Self::LimitationsExceeded { count, max } => write!(
                f,
                "limitations count ({count}) exceeds maximum ({max})"
            ),
            Self::DuplicatePacketReference(pkt) => {
                write!(f, "duplicate packet reference: {pkt:?}")
            }
            Self::OutOfOrderPacketReference { previous, attempted } => write!(
                f,
                "out-of-order packet reference: attempted {attempted} after {previous}"
            ),
            Self::DuplicateFlowReference(flow) => {
                write!(f, "duplicate flow reference: {flow}")
            }
            Self::OutOfOrderFlowReference { previous, attempted } => write!(
                f,
                "out-of-order flow reference: attempted {attempted} after {previous}"
            ),
            Self::DuplicateObservationReference(obs) => {
                write!(f, "duplicate observation reference: {obs}")
            }
            Self::OutOfOrderObservationReference { previous, attempted } => write!(
                f,
                "out-of-order observation reference: attempted {attempted} after {previous}"
            ),
            Self::DuplicateMetricKey(key) => {
                write!(f, "duplicate evidence metric key: {key}")
            }
            Self::DuplicateLimitation(lim) => {
                write!(f, "duplicate evidence limitation: {lim}")
            }
        }
    }
}

impl std::error::Error for EvidenceValidationError {}

/// Concise, terminal-safe factual description of an evidence item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceDescription {
    text: String,
}

impl EvidenceDescription {
    /// Maximum allowed UTF-8 encoded byte length for an evidence description (512 bytes).
    pub const MAX_LENGTH: usize = 512;

    /// Creates a new evidence description, validating terminal safety, non-emptiness, and length bounds.
    pub fn try_new(text: impl AsRef<str>) -> Result<Self, EvidenceValidationError> {
        let raw = text.as_ref();
        if raw.is_empty() {
            return Err(EvidenceValidationError::EmptyDescription);
        }
        if raw.len() > Self::MAX_LENGTH {
            return Err(EvidenceValidationError::DescriptionTooLong {
                length: raw.len(),
                max: Self::MAX_LENGTH,
            });
        }
        for c in raw.chars() {
            if c.is_control() {
                return Err(EvidenceValidationError::DescriptionControlCharacter {
                    byte: c as u32 as u8,
                });
            }
        }
        Ok(Self {
            text: raw.to_string(),
        })
    }

    /// Returns the text as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for EvidenceDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Namespaced or canonical key identifying a measured metric in an evidence item.
///
/// Must match ASCII grammar `[a-z0-9][a-z0-9._-]*` with a maximum length of 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceMetricKey {
    key: String,
}

impl EvidenceMetricKey {
    /// Maximum allowed byte length for an evidence metric key (64 bytes).
    pub const MAX_LENGTH: usize = 64;

    /// Creates a new validated evidence metric key.
    pub fn try_new(key: impl AsRef<str>) -> Result<Self, EvidenceValidationError> {
        let raw = key.as_ref();
        if raw.is_empty() {
            return Err(EvidenceValidationError::EmptyMetricKey);
        }
        if raw.len() > Self::MAX_LENGTH {
            return Err(EvidenceValidationError::MetricKeyTooLong {
                length: raw.len(),
                max: Self::MAX_LENGTH,
            });
        }

        let bytes = raw.as_bytes();
        let first = bytes[0];
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(EvidenceValidationError::InvalidMetricKeyCharacter {
                character: first as char,
            });
        }

        for &b in &bytes[1..] {
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() && b != b'.' && b != b'_' && b != b'-'
            {
                return Err(EvidenceValidationError::InvalidMetricKeyCharacter {
                    character: b as char,
                });
            }
        }

        Ok(Self {
            key: raw.to_string(),
        })
    }

    /// Returns the metric key as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }
}

impl fmt::Display for EvidenceMetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key)
    }
}

/// Exact rational ratio represented as `numerator / denominator` in lowest terms.
///
/// Ensures exact, overflow-free, and float-free comparisons across all rational metrics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvidenceRatio {
    numerator: u128,
    denominator: u128,
}

impl EvidenceRatio {
    /// Zero ratio (0 / 1).
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };

    /// Unit ratio (1 / 1).
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// Creates a new canonical non-negative rational ratio.
    ///
    /// Automatically reduces the fraction to lowest terms via GCD.
    /// Returns `None` if `denominator == 0`.
    #[must_use]
    pub const fn from_fraction(numerator: u128, denominator: u128) -> Option<Self> {
        if denominator == 0 {
            return None;
        }
        if numerator == 0 {
            return Some(Self::ZERO);
        }
        let g = gcd(numerator, denominator);
        Some(Self {
            numerator: numerator / g,
            denominator: denominator / g,
        })
    }

    /// Creates an exact ratio from a whole integer (`val / 1`).
    #[must_use]
    pub const fn from_integer(val: u128) -> Self {
        Self {
            numerator: val,
            denominator: 1,
        }
    }

    /// Returns the canonical numerator.
    #[must_use]
    pub const fn numerator(&self) -> u128 {
        self.numerator
    }

    /// Returns the canonical denominator.
    #[must_use]
    pub const fn denominator(&self) -> u128 {
        self.denominator
    }

    /// Formats the ratio as an exact fraction string (e.g. `"3/4"` or `"5/1"`).
    #[must_use]
    pub fn to_exact_string(&self) -> String {
        format!("{}/{}", self.numerator, self.denominator)
    }
}

impl PartialOrd for EvidenceRatio {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvidenceRatio {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.denominator == other.denominator {
            return self.numerator.cmp(&other.numerator);
        }
        if self.numerator == other.numerator {
            if self.numerator == 0 {
                return core::cmp::Ordering::Equal;
            }
            return other.denominator.cmp(&self.denominator);
        }

        // Exact Euclidean continued-fraction rational comparison (zero float, overflow-free).
        let mut n1 = self.numerator;
        let mut d1 = self.denominator;
        let mut n2 = other.numerator;
        let mut d2 = other.denominator;

        loop {
            let q1 = n1 / d1;
            let r1 = n1 % d1;
            let q2 = n2 / d2;
            let r2 = n2 % d2;

            if q1 != q2 {
                return q1.cmp(&q2);
            }

            match (r1 == 0, r2 == 0) {
                (true, true) => return core::cmp::Ordering::Equal,
                (true, false) => return core::cmp::Ordering::Less,
                (false, true) => return core::cmp::Ordering::Greater,
                (false, false) => {
                    let next_n1 = d2;
                    let next_d1 = r2;
                    let next_n2 = d1;
                    let next_d2 = r1;
                    n1 = next_n1;
                    d1 = next_d1;
                    n2 = next_n2;
                    d2 = next_d2;
                }
            }
        }
    }
}

impl fmt::Debug for EvidenceRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EvidenceRatio({}/{})", self.numerator, self.denominator)
    }
}

impl fmt::Display for EvidenceRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.numerator, self.denominator)
    }
}

/// Explicit measurement unit for structured evidence values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceUnit {
    /// Count of bytes.
    Bytes,
    /// Count of packets.
    Packets,
    /// Nanoseconds duration.
    Nanoseconds,
    /// Microseconds duration.
    Microseconds,
    /// Milliseconds duration.
    Milliseconds,
    /// Seconds duration.
    Seconds,
    /// Dimensionless rational ratio.
    Ratio,
    /// Generic integer item count.
    Count,
    /// Whole integer percentage (0..=100).
    PercentageInteger,
}

impl EvidenceUnit {
    /// Returns the static label for the unit.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Packets => "packets",
            Self::Nanoseconds => "ns",
            Self::Microseconds => "us",
            Self::Milliseconds => "ms",
            Self::Seconds => "s",
            Self::Ratio => "ratio",
            Self::Count => "count",
            Self::PercentageInteger => "%",
        }
    }
}

impl fmt::Display for EvidenceUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strictly typed evidence measurement value without floating-point numbers or unbounded text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EvidenceValue {
    /// Signed 128-bit integer.
    Integer(i128),
    /// Unsigned 128-bit integer.
    Unsigned(u128),
    /// Exact rational fraction.
    Ratio(EvidenceRatio),
    /// Boolean flag.
    Boolean(bool),
    /// Exact rational temporal duration.
    Duration(FlowDuration),
}

impl EvidenceValue {
    /// Returns `true` if this value is an integer, unsigned number, rational ratio, or duration.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::Integer(_) | Self::Unsigned(_) | Self::Ratio(_) | Self::Duration(_)
        )
    }
}

impl fmt::Display for EvidenceValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => write!(f, "{v}"),
            Self::Unsigned(v) => write!(f, "{v}"),
            Self::Ratio(r) => write!(f, "{r}"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Duration(d) => write!(f, "{d}"),
        }
    }
}

/// Comparison operator applied between an observed measurement and a detector threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceComparison {
    /// Observed value equals threshold.
    Equal,
    /// Observed value does not equal threshold.
    NotEqual,
    /// Observed value is strictly less than threshold.
    LessThan,
    /// Observed value is less than or equal to threshold.
    LessThanOrEqual,
    /// Observed value is strictly greater than threshold.
    GreaterThan,
    /// Observed value is greater than or equal to threshold.
    GreaterThanOrEqual,
}

impl EvidenceComparison {
    /// Returns the static mathematical symbol or label for this comparison.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::LessThan => "<",
            Self::LessThanOrEqual => "<=",
            Self::GreaterThan => ">",
            Self::GreaterThanOrEqual => ">=",
        }
    }
}

impl fmt::Display for EvidenceComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Individual factual measurement comparing an observed value against an optional threshold.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EvidenceMeasurement {
    key: EvidenceMetricKey,
    observed_value: EvidenceValue,
    threshold_value: Option<EvidenceValue>,
    comparison: Option<EvidenceComparison>,
    unit: EvidenceUnit,
}

impl EvidenceMeasurement {
    /// Validates unit and value type compatibility.
    fn validate_unit_and_value(
        value: &EvidenceValue,
        unit: EvidenceUnit,
    ) -> Result<(), EvidenceValidationError> {
        match unit {
            EvidenceUnit::Ratio => {
                if !matches!(value, EvidenceValue::Ratio(_)) {
                    return Err(EvidenceValidationError::IncompatibleUnitAndValue);
                }
            }
            EvidenceUnit::PercentageInteger => match value {
                EvidenceValue::Unsigned(v) => {
                    if *v > 100 {
                        return Err(EvidenceValidationError::PercentageOutOfRange { value: *v });
                    }
                }
                EvidenceValue::Integer(v) => {
                    if *v < 0 || *v > 100 {
                        return Err(EvidenceValidationError::PercentageOutOfRange {
                            value: (*v).max(0) as u128,
                        });
                    }
                }
                EvidenceValue::Ratio(_)
                | EvidenceValue::Boolean(_)
                | EvidenceValue::Duration(_) => {
                    return Err(EvidenceValidationError::IncompatibleUnitAndValue);
                }
            },
            EvidenceUnit::Seconds => match value {
                EvidenceValue::Integer(_)
                | EvidenceValue::Unsigned(_)
                | EvidenceValue::Duration(_) => {}
                EvidenceValue::Boolean(_) | EvidenceValue::Ratio(_) => {
                    return Err(EvidenceValidationError::IncompatibleUnitAndValue);
                }
            },
            EvidenceUnit::Bytes
            | EvidenceUnit::Packets
            | EvidenceUnit::Nanoseconds
            | EvidenceUnit::Microseconds
            | EvidenceUnit::Milliseconds
            | EvidenceUnit::Count => match value {
                EvidenceValue::Integer(_) | EvidenceValue::Unsigned(_) => {}
                EvidenceValue::Boolean(_) => {
                    if unit != EvidenceUnit::Count {
                        return Err(EvidenceValidationError::IncompatibleUnitAndValue);
                    }
                }
                EvidenceValue::Ratio(_) | EvidenceValue::Duration(_) => {
                    return Err(EvidenceValidationError::IncompatibleUnitAndValue);
                }
            },
        }
        Ok(())
    }

    /// Creates a factual measurement without an explicit threshold.
    pub fn try_new(
        key: EvidenceMetricKey,
        observed_value: EvidenceValue,
        unit: EvidenceUnit,
    ) -> Result<Self, EvidenceValidationError> {
        Self::validate_unit_and_value(&observed_value, unit)?;
        Ok(Self {
            key,
            observed_value,
            threshold_value: None,
            comparison: None,
            unit,
        })
    }

    /// Creates a measurement comparing an observed value against a threshold.
    pub fn try_with_threshold(
        key: EvidenceMetricKey,
        observed_value: EvidenceValue,
        threshold_value: EvidenceValue,
        comparison: EvidenceComparison,
        unit: EvidenceUnit,
    ) -> Result<Self, EvidenceValidationError> {
        Self::validate_unit_and_value(&observed_value, unit)?;
        Self::validate_unit_and_value(&threshold_value, unit)?;

        // Ensure observed and threshold value variants match
        match (&observed_value, &threshold_value) {
            (EvidenceValue::Integer(_), EvidenceValue::Integer(_))
            | (EvidenceValue::Unsigned(_), EvidenceValue::Unsigned(_))
            | (EvidenceValue::Ratio(_), EvidenceValue::Ratio(_))
            | (EvidenceValue::Boolean(_), EvidenceValue::Boolean(_))
            | (EvidenceValue::Duration(_), EvidenceValue::Duration(_)) => {}
            _ => return Err(EvidenceValidationError::IncompatibleMeasurementTypes),
        }

        Ok(Self {
            key,
            observed_value,
            threshold_value: Some(threshold_value),
            comparison: Some(comparison),
            unit,
        })
    }

    /// Returns the metric key.
    #[must_use]
    pub const fn key(&self) -> &EvidenceMetricKey {
        &self.key
    }

    /// Returns the observed factual value.
    #[must_use]
    pub const fn observed_value(&self) -> &EvidenceValue {
        &self.observed_value
    }

    /// Returns the optional threshold value.
    #[must_use]
    pub const fn threshold_value(&self) -> Option<&EvidenceValue> {
        self.threshold_value.as_ref()
    }

    /// Returns the optional comparison operator.
    #[must_use]
    pub const fn comparison(&self) -> Option<EvidenceComparison> {
        self.comparison
    }

    /// Returns the measurement unit.
    #[must_use]
    pub const fn unit(&self) -> EvidenceUnit {
        self.unit
    }
}

/// Analysis limitations or data incompleteness affecting the interpretation of an evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceLimitation {
    /// Capture container or record bytes were truncated.
    CaptureTruncated,
    /// Application payload was truncated in capture.
    TruncatedPayload,
    /// Packet lacked a normalized network layer.
    MissingNetworkLayer,
    /// Protocol handshake was incomplete or interrupted.
    IncompleteHandshake,
    /// Configured packet count analysis budget was reached.
    PacketCountBudgetReached,
    /// Configured protocol observation analysis budget was reached.
    ObservationBudgetReached,
    /// Configured flow capacity budget was reached.
    FlowBudgetReached,
    /// Configured header section byte budget was exceeded.
    HeaderBudgetExceeded,
}

impl EvidenceLimitation {
    /// Returns the static label for this limitation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CaptureTruncated => "CaptureTruncated",
            Self::TruncatedPayload => "TruncatedPayload",
            Self::MissingNetworkLayer => "MissingNetworkLayer",
            Self::IncompleteHandshake => "IncompleteHandshake",
            Self::PacketCountBudgetReached => "PacketCountBudgetReached",
            Self::ObservationBudgetReached => "ObservationBudgetReached",
            Self::FlowBudgetReached => "FlowBudgetReached",
            Self::HeaderBudgetExceeded => "HeaderBudgetExceeded",
        }
    }
}

impl fmt::Display for EvidenceLimitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Builder for constructing validated [`EvidenceRecord`] instances.
#[derive(Debug, Clone)]
pub struct EvidenceRecordBuilder {
    reference: EvidenceReference,
    kind: EvidenceKind,
    description: EvidenceDescription,
    packet_references: Vec<PacketReference>,
    flow_references: Vec<FlowReference>,
    observation_references: Vec<ObservationReference>,
    measurements: Vec<EvidenceMeasurement>,
    limitations: Vec<EvidenceLimitation>,
    schema_version: SchemaVersion,
}

impl EvidenceRecordBuilder {
    /// Default maximum packet references per evidence record (64).
    pub const DEFAULT_MAX_PACKET_REFERENCES: usize = 64;
    /// Hard maximum packet references per evidence record (1,024).
    pub const HARD_MAX_PACKET_REFERENCES: usize = 1_024;

    /// Default maximum flow references per evidence record (32).
    pub const DEFAULT_MAX_FLOW_REFERENCES: usize = 32;
    /// Hard maximum flow references per evidence record (256).
    pub const HARD_MAX_FLOW_REFERENCES: usize = 256;

    /// Default maximum observation references per evidence record (128).
    pub const DEFAULT_MAX_OBSERVATION_REFERENCES: usize = 128;
    /// Hard maximum observation references per evidence record (4,096).
    pub const HARD_MAX_OBSERVATION_REFERENCES: usize = 4_096;

    /// Default maximum measurements per evidence record (32).
    pub const DEFAULT_MAX_MEASUREMENTS: usize = 32;
    /// Hard maximum measurements per evidence record (256).
    pub const HARD_MAX_MEASUREMENTS: usize = 256;

    /// Default maximum limitations per evidence record (8).
    pub const DEFAULT_MAX_LIMITATIONS: usize = 8;
    /// Hard maximum limitations per evidence record (64).
    pub const HARD_MAX_LIMITATIONS: usize = 64;

    /// Creates a new evidence record builder with required reference, kind, and description.
    #[must_use]
    pub fn new(
        reference: EvidenceReference,
        kind: EvidenceKind,
        description: EvidenceDescription,
    ) -> Self {
        Self {
            reference,
            kind,
            description,
            packet_references: Vec::new(),
            flow_references: Vec::new(),
            observation_references: Vec::new(),
            measurements: Vec::new(),
            limitations: Vec::new(),
            schema_version: EVIDENCE_SCHEMA_VERSION,
        }
    }

    /// Sets an explicit schema version anchor.
    #[must_use]
    pub fn with_schema_version(mut self, schema_version: SchemaVersion) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Appends a packet reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_packet_reference(
        &mut self,
        packet: PacketReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.packet_references.len() >= Self::HARD_MAX_PACKET_REFERENCES {
            return Err(EvidenceValidationError::PacketReferencesExceeded {
                count: self.packet_references.len() + 1,
                max: Self::HARD_MAX_PACKET_REFERENCES,
            });
        }
        if let Some(last) = self.packet_references.last() {
            let last_ord = last.capture_record_ordinal();
            let new_ord = packet.capture_record_ordinal();
            if new_ord == last_ord {
                return Err(EvidenceValidationError::DuplicatePacketReference(packet));
            }
            if new_ord < last_ord {
                return Err(EvidenceValidationError::OutOfOrderPacketReference {
                    previous: last_ord,
                    attempted: new_ord,
                });
            }
        }
        self.packet_references.push(packet);
        Ok(self)
    }

    /// Appends a flow reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_flow_reference(
        &mut self,
        flow: FlowReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.flow_references.len() >= Self::HARD_MAX_FLOW_REFERENCES {
            return Err(EvidenceValidationError::FlowReferencesExceeded {
                count: self.flow_references.len() + 1,
                max: Self::HARD_MAX_FLOW_REFERENCES,
            });
        }
        if let Some(last) = self.flow_references.last() {
            let last_ord = last.ordinal();
            let new_ord = flow.ordinal();
            if new_ord == last_ord {
                return Err(EvidenceValidationError::DuplicateFlowReference(flow));
            }
            if new_ord < last_ord {
                return Err(EvidenceValidationError::OutOfOrderFlowReference {
                    previous: last_ord,
                    attempted: new_ord,
                });
            }
        }
        self.flow_references.push(flow);
        Ok(self)
    }

    /// Appends an observation reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_observation_reference(
        &mut self,
        obs: ObservationReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.observation_references.len() >= Self::HARD_MAX_OBSERVATION_REFERENCES {
            return Err(EvidenceValidationError::ObservationReferencesExceeded {
                count: self.observation_references.len() + 1,
                max: Self::HARD_MAX_OBSERVATION_REFERENCES,
            });
        }
        if let Some(last) = self.observation_references.last() {
            if obs == *last {
                return Err(EvidenceValidationError::DuplicateObservationReference(obs));
            }
            if obs < *last {
                return Err(EvidenceValidationError::OutOfOrderObservationReference {
                    previous: *last,
                    attempted: obs,
                });
            }
        }
        self.observation_references.push(obs);
        Ok(self)
    }

    /// Appends a measurement, enforcing hard cardinality limits and unique metric keys.
    pub fn add_measurement(
        &mut self,
        measurement: EvidenceMeasurement,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.measurements.len() >= Self::HARD_MAX_MEASUREMENTS {
            return Err(EvidenceValidationError::MeasurementsExceeded {
                count: self.measurements.len() + 1,
                max: Self::HARD_MAX_MEASUREMENTS,
            });
        }
        if self
            .measurements
            .iter()
            .any(|m| m.key() == measurement.key())
        {
            return Err(EvidenceValidationError::DuplicateMetricKey(
                measurement.key().clone(),
            ));
        }
        self.measurements.push(measurement);
        Ok(self)
    }

    /// Appends a limitation, enforcing hard cardinality limits, uniqueness, and sorted order.
    pub fn add_limitation(
        &mut self,
        limitation: EvidenceLimitation,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.limitations.len() >= Self::HARD_MAX_LIMITATIONS {
            return Err(EvidenceValidationError::LimitationsExceeded {
                count: self.limitations.len() + 1,
                max: Self::HARD_MAX_LIMITATIONS,
            });
        }
        if self.limitations.contains(&limitation) {
            return Err(EvidenceValidationError::DuplicateLimitation(limitation));
        }
        self.limitations.push(limitation);
        self.limitations.sort();
        Ok(self)
    }

    /// Builds the validated [`EvidenceRecord`].
    ///
    /// Fails if all reference and measurement collections are empty.
    pub fn build(self) -> Result<EvidenceRecord, EvidenceValidationError> {
        if self.packet_references.is_empty()
            && self.flow_references.is_empty()
            && self.observation_references.is_empty()
            && self.measurements.is_empty()
        {
            return Err(EvidenceValidationError::EmptyEvidenceRecord);
        }

        Ok(EvidenceRecord {
            reference: self.reference,
            kind: self.kind,
            description: self.description,
            packet_references: self.packet_references,
            flow_references: self.flow_references,
            observation_references: self.observation_references,
            measurements: self.measurements,
            limitations: self.limitations,
            schema_version: self.schema_version,
        })
    }
}

/// Builder for constructing validated [`EvidenceDraft`] instances without final reference assignment.
#[derive(Debug, Clone)]
pub struct EvidenceDraftBuilder {
    kind: EvidenceKind,
    description: EvidenceDescription,
    packet_references: Vec<PacketReference>,
    flow_references: Vec<FlowReference>,
    observation_references: Vec<ObservationReference>,
    measurements: Vec<EvidenceMeasurement>,
    limitations: Vec<EvidenceLimitation>,
    schema_version: SchemaVersion,
}

impl EvidenceDraftBuilder {
    /// Creates a new evidence draft builder with required kind and description.
    #[must_use]
    pub fn new(kind: EvidenceKind, description: EvidenceDescription) -> Self {
        Self {
            kind,
            description,
            packet_references: Vec::new(),
            flow_references: Vec::new(),
            observation_references: Vec::new(),
            measurements: Vec::new(),
            limitations: Vec::new(),
            schema_version: EVIDENCE_SCHEMA_VERSION,
        }
    }

    /// Sets an explicit schema version anchor.
    #[must_use]
    pub fn with_schema_version(mut self, schema_version: SchemaVersion) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Appends a packet reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_packet_reference(
        &mut self,
        packet: PacketReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.packet_references.len() >= EvidenceRecordBuilder::HARD_MAX_PACKET_REFERENCES {
            return Err(EvidenceValidationError::PacketReferencesExceeded {
                count: self.packet_references.len() + 1,
                max: EvidenceRecordBuilder::HARD_MAX_PACKET_REFERENCES,
            });
        }
        if let Some(last) = self.packet_references.last() {
            let last_ord = last.capture_record_ordinal();
            let new_ord = packet.capture_record_ordinal();
            if new_ord == last_ord {
                return Err(EvidenceValidationError::DuplicatePacketReference(packet));
            }
            if new_ord < last_ord {
                return Err(EvidenceValidationError::OutOfOrderPacketReference {
                    previous: last_ord,
                    attempted: new_ord,
                });
            }
        }
        self.packet_references.push(packet);
        Ok(self)
    }

    /// Appends a flow reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_flow_reference(
        &mut self,
        flow: FlowReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.flow_references.len() >= EvidenceRecordBuilder::HARD_MAX_FLOW_REFERENCES {
            return Err(EvidenceValidationError::FlowReferencesExceeded {
                count: self.flow_references.len() + 1,
                max: EvidenceRecordBuilder::HARD_MAX_FLOW_REFERENCES,
            });
        }
        if let Some(last) = self.flow_references.last() {
            let last_ord = last.ordinal();
            let new_ord = flow.ordinal();
            if new_ord == last_ord {
                return Err(EvidenceValidationError::DuplicateFlowReference(flow));
            }
            if new_ord < last_ord {
                return Err(EvidenceValidationError::OutOfOrderFlowReference {
                    previous: last_ord,
                    attempted: new_ord,
                });
            }
        }
        self.flow_references.push(flow);
        Ok(self)
    }

    /// Appends an observation reference, enforcing hard cardinality limits, strict ordering, and uniqueness.
    pub fn add_observation_reference(
        &mut self,
        obs: ObservationReference,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.observation_references.len()
            >= EvidenceRecordBuilder::HARD_MAX_OBSERVATION_REFERENCES
        {
            return Err(EvidenceValidationError::ObservationReferencesExceeded {
                count: self.observation_references.len() + 1,
                max: EvidenceRecordBuilder::HARD_MAX_OBSERVATION_REFERENCES,
            });
        }
        if let Some(last) = self.observation_references.last() {
            if obs == *last {
                return Err(EvidenceValidationError::DuplicateObservationReference(obs));
            }
            if obs < *last {
                return Err(EvidenceValidationError::OutOfOrderObservationReference {
                    previous: *last,
                    attempted: obs,
                });
            }
        }
        self.observation_references.push(obs);
        Ok(self)
    }

    /// Appends a measurement, enforcing hard cardinality limits and unique metric keys.
    pub fn add_measurement(
        &mut self,
        measurement: EvidenceMeasurement,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.measurements.len() >= EvidenceRecordBuilder::HARD_MAX_MEASUREMENTS {
            return Err(EvidenceValidationError::MeasurementsExceeded {
                count: self.measurements.len() + 1,
                max: EvidenceRecordBuilder::HARD_MAX_MEASUREMENTS,
            });
        }
        if self
            .measurements
            .iter()
            .any(|m| m.key() == measurement.key())
        {
            return Err(EvidenceValidationError::DuplicateMetricKey(
                measurement.key().clone(),
            ));
        }
        self.measurements.push(measurement);
        Ok(self)
    }

    /// Appends a limitation, enforcing hard cardinality limits, uniqueness, and sorted order.
    pub fn add_limitation(
        &mut self,
        limitation: EvidenceLimitation,
    ) -> Result<&mut Self, EvidenceValidationError> {
        if self.limitations.len() >= EvidenceRecordBuilder::HARD_MAX_LIMITATIONS {
            return Err(EvidenceValidationError::LimitationsExceeded {
                count: self.limitations.len() + 1,
                max: EvidenceRecordBuilder::HARD_MAX_LIMITATIONS,
            });
        }
        if self.limitations.contains(&limitation) {
            return Err(EvidenceValidationError::DuplicateLimitation(limitation));
        }
        self.limitations.push(limitation);
        self.limitations.sort();
        Ok(self)
    }

    /// Builds the validated [`EvidenceDraft`].
    ///
    /// Fails if all reference and measurement collections are empty.
    pub fn build(self) -> Result<EvidenceDraft, EvidenceValidationError> {
        if self.packet_references.is_empty()
            && self.flow_references.is_empty()
            && self.observation_references.is_empty()
            && self.measurements.is_empty()
        {
            return Err(EvidenceValidationError::EmptyEvidenceRecord);
        }

        Ok(EvidenceDraft {
            kind: self.kind,
            description: self.description,
            packet_references: self.packet_references,
            flow_references: self.flow_references,
            observation_references: self.observation_references,
            measurements: self.measurements,
            limitations: self.limitations,
            schema_version: self.schema_version,
        })
    }
}

/// Structured, immutable evidence draft emitted by a detector before engine reference assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDraft {
    kind: EvidenceKind,
    description: EvidenceDescription,
    packet_references: Vec<PacketReference>,
    flow_references: Vec<FlowReference>,
    observation_references: Vec<ObservationReference>,
    measurements: Vec<EvidenceMeasurement>,
    limitations: Vec<EvidenceLimitation>,
    schema_version: SchemaVersion,
}

impl EvidenceDraft {
    /// Creates an evidence draft builder.
    #[must_use]
    pub fn builder(kind: EvidenceKind, description: EvidenceDescription) -> EvidenceDraftBuilder {
        EvidenceDraftBuilder::new(kind, description)
    }

    /// Returns the analytical kind of this evidence.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// Returns the factual description.
    #[must_use]
    pub const fn description(&self) -> &EvidenceDescription {
        &self.description
    }

    /// Returns the ordered slice of supporting packet references.
    #[must_use]
    pub fn packet_references(&self) -> &[PacketReference] {
        &self.packet_references
    }

    /// Returns the ordered slice of supporting flow references.
    #[must_use]
    pub fn flow_references(&self) -> &[FlowReference] {
        &self.flow_references
    }

    /// Returns the ordered slice of supporting observation references.
    #[must_use]
    pub fn observation_references(&self) -> &[ObservationReference] {
        &self.observation_references
    }

    /// Returns the slice of concrete measurements.
    #[must_use]
    pub fn measurements(&self) -> &[EvidenceMeasurement] {
        &self.measurements
    }

    /// Returns the sorted slice of analytical limitations.
    #[must_use]
    pub fn limitations(&self) -> &[EvidenceLimitation] {
        &self.limitations
    }

    /// Returns the schema version anchor.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }
}

/// Structured, immutable evidence record supporting a detector finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    reference: EvidenceReference,
    kind: EvidenceKind,
    description: EvidenceDescription,
    packet_references: Vec<PacketReference>,
    flow_references: Vec<FlowReference>,
    observation_references: Vec<ObservationReference>,
    measurements: Vec<EvidenceMeasurement>,
    limitations: Vec<EvidenceLimitation>,
    schema_version: SchemaVersion,
}

impl EvidenceRecord {
    /// Creates an evidence record builder.
    #[must_use]
    pub fn builder(
        reference: EvidenceReference,
        kind: EvidenceKind,
        description: EvidenceDescription,
    ) -> EvidenceRecordBuilder {
        EvidenceRecordBuilder::new(reference, kind, description)
    }

    /// Creates an evidence record from an engine-assigned reference and a validated evidence draft.
    #[must_use]
    pub fn from_draft(reference: EvidenceReference, draft: EvidenceDraft) -> Self {
        Self {
            reference,
            kind: draft.kind,
            description: draft.description,
            packet_references: draft.packet_references,
            flow_references: draft.flow_references,
            observation_references: draft.observation_references,
            measurements: draft.measurements,
            limitations: draft.limitations,
            schema_version: draft.schema_version,
        }
    }

    /// Returns the unique evidence reference.
    #[must_use]
    pub const fn reference(&self) -> EvidenceReference {
        self.reference
    }

    /// Returns the analytical kind of this evidence.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// Returns the factual description.
    #[must_use]
    pub const fn description(&self) -> &EvidenceDescription {
        &self.description
    }

    /// Returns the ordered slice of supporting packet references.
    #[must_use]
    pub fn packet_references(&self) -> &[PacketReference] {
        &self.packet_references
    }

    /// Returns the ordered slice of supporting flow references.
    #[must_use]
    pub fn flow_references(&self) -> &[FlowReference] {
        &self.flow_references
    }

    /// Returns the ordered slice of supporting observation references.
    #[must_use]
    pub fn observation_references(&self) -> &[ObservationReference] {
        &self.observation_references
    }

    /// Returns the slice of concrete measurements.
    #[must_use]
    pub fn measurements(&self) -> &[EvidenceMeasurement] {
        &self.measurements
    }

    /// Returns the sorted slice of analytical limitations.
    #[must_use]
    pub fn limitations(&self) -> &[EvidenceLimitation] {
        &self.limitations
    }

    /// Returns the schema version anchor.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }
}

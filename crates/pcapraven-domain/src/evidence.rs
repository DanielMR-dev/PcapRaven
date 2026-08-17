//! Structured evidence records, measurements, exact rational ratios, and schema anchors.
//!
//! Evidence records provide immutable, factual supporting context for heuristic security
//! findings, referencing normalized packets, flows, and observations without copying
//! arbitrary unparsed payloads.

use crate::flow::FlowReference;
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

/// Version of the structured evidence record schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion {
    /// Major schema version (incompatible changes).
    pub major: u16,
    /// Minor schema version (backward-compatible additions).
    pub minor: u16,
}

impl SchemaVersion {
    /// Current canonical schema version for Phase 10 (v1.0).
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

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
    /// Structural or protocol framing anomaly.
    StructuralAnomaly,
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
            Self::StructuralAnomaly => "StructuralAnomaly",
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Concise, terminal-safe factual description of an evidence item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceDescription {
    text: String,
}

impl EvidenceDescription {
    /// Maximum allowed character length for an evidence description.
    pub const MAX_LENGTH: usize = 1024;

    /// Creates a new evidence description, truncating and sanitizing control characters for terminal safety.
    pub fn new(text: impl Into<String>) -> Self {
        let raw = text.into();
        let mut sanitized = String::with_capacity(raw.len().min(Self::MAX_LENGTH));
        for c in raw.chars().take(Self::MAX_LENGTH) {
            if c.is_control() && c != '\t' {
                sanitized.push(' ');
            } else {
                sanitized.push(c);
            }
        }
        Self { text: sanitized }
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceMetricKey {
    key: String,
}

impl EvidenceMetricKey {
    /// Maximum allowed character length for an evidence metric key.
    pub const MAX_LENGTH: usize = 128;

    /// Creates a new evidence metric key.
    pub fn new(key: impl Into<String>) -> Self {
        let raw = key.into();
        let mut sanitized = String::with_capacity(raw.len().min(Self::MAX_LENGTH));
        for c in raw.chars().take(Self::MAX_LENGTH) {
            if c.is_control() {
                sanitized.push('_');
            } else {
                sanitized.push(c);
            }
        }
        Self { key: sanitized }
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    /// Custom explicit unit label.
    Custom(String),
}

impl EvidenceUnit {
    /// Returns the static label for standard units, or custom string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
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
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for EvidenceUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strictly typed evidence measurement value without floating-point numbers.
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
    /// Bounded descriptive text string.
    Text(String),
}

impl EvidenceValue {
    /// Returns `true` if this value is an integer or unsigned number.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(self, Self::Integer(_) | Self::Unsigned(_) | Self::Ratio(_))
    }
}

impl fmt::Display for EvidenceValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(v) => write!(f, "{v}"),
            Self::Unsigned(v) => write!(f, "{v}"),
            Self::Ratio(r) => write!(f, "{r}"),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::Text(s) => f.write_str(s),
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
    /// Observed value falls within acceptable range.
    InRange,
    /// Observed value falls outside acceptable range.
    OutsideRange,
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
            Self::InRange => "in_range",
            Self::OutsideRange => "outside_range",
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
    /// Metric identifier key.
    pub key: EvidenceMetricKey,
    /// Observed factual value.
    pub observed_value: EvidenceValue,
    /// Optional detector threshold or baseline value.
    pub threshold_value: Option<EvidenceValue>,
    /// Optional comparison operator.
    pub comparison: Option<EvidenceComparison>,
    /// Measurement unit.
    pub unit: EvidenceUnit,
}

impl EvidenceMeasurement {
    /// Creates a factual measurement without an explicit threshold.
    #[must_use]
    pub fn new(key: EvidenceMetricKey, observed_value: EvidenceValue, unit: EvidenceUnit) -> Self {
        Self {
            key,
            observed_value,
            threshold_value: None,
            comparison: None,
            unit,
        }
    }

    /// Creates a measurement comparing an observed value against a threshold.
    #[must_use]
    pub fn with_threshold(
        key: EvidenceMetricKey,
        observed_value: EvidenceValue,
        threshold_value: EvidenceValue,
        comparison: EvidenceComparison,
        unit: EvidenceUnit,
    ) -> Self {
        Self {
            key,
            observed_value,
            threshold_value: Some(threshold_value),
            comparison: Some(comparison),
            unit,
        }
    }
}

/// Analysis limitations or data incompleteness affecting the interpretation of an evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceLimitation {
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

/// Structured, immutable evidence record supporting a detector finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Unique evidence record identifier.
    pub reference: EvidenceReference,
    /// Analytical category of this evidence.
    pub kind: EvidenceKind,
    /// Concise factual description.
    pub description: EvidenceDescription,
    /// Ordered references to supporting packets.
    pub packet_references: Vec<PacketReference>,
    /// Ordered references to supporting flow instances.
    pub flow_references: Vec<FlowReference>,
    /// Ordered references to supporting protocol observations.
    pub observation_references: Vec<ObservationReference>,
    /// Concrete numeric and rational measurements.
    pub measurements: Vec<EvidenceMeasurement>,
    /// Incompleteness limitations affecting this evidence.
    pub limitations: Vec<EvidenceLimitation>,
    /// Schema version anchor.
    pub schema_version: SchemaVersion,
}

impl EvidenceRecord {
    /// Creates a new evidence record with default schema version and empty collections.
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
            schema_version: SchemaVersion::CURRENT,
        }
    }

    /// Appends a packet reference to this evidence record.
    pub fn add_packet_reference(&mut self, packet: PacketReference) {
        self.packet_references.push(packet);
    }

    /// Appends a flow reference to this evidence record.
    pub fn add_flow_reference(&mut self, flow: FlowReference) {
        self.flow_references.push(flow);
    }

    /// Appends an observation reference to this evidence record.
    pub fn add_observation_reference(&mut self, obs: ObservationReference) {
        self.observation_references.push(obs);
    }

    /// Appends a measurement to this evidence record.
    pub fn add_measurement(&mut self, measurement: EvidenceMeasurement) {
        self.measurements.push(measurement);
    }

    /// Appends an analytical limitation to this evidence record.
    pub fn add_limitation(&mut self, limitation: EvidenceLimitation) {
        self.limitations.push(limitation);
    }
}

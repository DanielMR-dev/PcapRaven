//! Capture-independent factual flow statistics and exact temporal metric types.

use crate::packet::PacketTimestamp;
use core::fmt;

/// Unsigned 128-bit integer division and greatest common divisor for rational duration reduction.
const fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Exact non-negative rational duration in seconds represented as `numerator / denominator`.
///
/// Fractions are automatically reduced to lowest terms via GCD upon creation.
/// Zero duration is canonically represented as `0 / 1`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowDuration {
    numerator: u128,
    denominator: u128,
}

impl FlowDuration {
    /// Zero seconds (0 / 1).
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };

    /// Creates a new canonical non-negative rational duration.
    ///
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

    /// Creates an exact duration from whole seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self {
            numerator: secs as u128,
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

    /// Checked addition of two exact durations.
    #[must_use]
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        let g = gcd(self.denominator, other.denominator);
        let b_div_g = self.denominator / g;
        let d_div_g = other.denominator / g;
        let lcm_den = b_div_g.checked_mul(other.denominator)?;
        let term1 = self.numerator.checked_mul(d_div_g)?;
        let term2 = other.numerator.checked_mul(b_div_g)?;
        let sum_num = term1.checked_add(term2)?;
        Self::from_fraction(sum_num, lcm_den)
    }

    /// Checked subtraction of two exact durations (`self - other`).
    ///
    /// Returns `None` on underflow or if `self < other`.
    #[must_use]
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self < other {
            return None;
        }
        let g = gcd(self.denominator, other.denominator);
        let b_div_g = self.denominator / g;
        let d_div_g = other.denominator / g;
        let lcm_den = b_div_g.checked_mul(other.denominator)?;
        let term1 = self.numerator.checked_mul(d_div_g)?;
        let term2 = other.numerator.checked_mul(b_div_g)?;
        let diff_num = term1.checked_sub(term2)?;
        Self::from_fraction(diff_num, lcm_den)
    }
}

impl PartialOrd for FlowDuration {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FlowDuration {
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

        // Exact, multiplication-free rational comparison using Euclidean continued fractions.
        // For positive fractions n1/d1 and n2/d2:
        //   n1/d1 = q1 + r1/d1
        //   n2/d2 = q2 + r2/d2
        // If q1 != q2, q1.cmp(&q2) determines the ordering.
        // If q1 == q2:
        //   - if r1 == 0 and r2 == 0 => Equal
        //   - if r1 == 0 and r2 > 0 => Less
        //   - if r1 > 0 and r2 == 0 => Greater
        //   - if r1 > 0 and r2 > 0: r1/d1 < r2/d2 <=> d2/r2 < d1/r1.
        // Swapping roles to compare (d2, r2) with (d1, r1) preserves the original comparison direction.
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

impl fmt::Debug for FlowDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.denominator == 1 {
            write!(f, "{}s", self.numerator)
        } else {
            write!(f, "{}/{}s", self.numerator, self.denominator)
        }
    }
}

impl fmt::Display for FlowDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Reason why a temporal metric is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowTemporalUnavailableReason {
    /// Insufficient valid samples were observed to compute the metric.
    InsufficientSamples,
    /// Timestamp was unavailable on one or more required packet references.
    TimestampUnavailable,
    /// Timestamp metadata was structurally invalid or inconsistent.
    InvalidTimestamp,
    /// Timestamps moved backward (non-monotonic) across packet sequence.
    NonMonotonicTimestamp,
    /// Calculation exceeded representable integer bounds.
    ArithmeticOverflow,
}

impl FlowTemporalUnavailableReason {
    /// Returns a static descriptive label for this unavailable reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientSamples => "InsufficientSamples",
            Self::TimestampUnavailable => "TimestampUnavailable",
            Self::InvalidTimestamp => "InvalidTimestamp",
            Self::NonMonotonicTimestamp => "NonMonotonicTimestamp",
            Self::ArithmeticOverflow => "ArithmeticOverflow",
        }
    }
}

impl fmt::Display for FlowTemporalUnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A temporal metric value that is either available or unavailable with an explicit reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowTemporalValue<T> {
    /// The metric was computed successfully.
    Available(T),
    /// The metric could not be computed.
    Unavailable(FlowTemporalUnavailableReason),
}

impl<T> FlowTemporalValue<T> {
    /// Returns `true` if the temporal value is available.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    /// Returns a reference to the available value, if present.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Available(val) => Some(val),
            Self::Unavailable(_) => None,
        }
    }

    /// Returns the unavailable reason, if unavailable.
    #[must_use]
    pub const fn unavailable_reason(&self) -> Option<FlowTemporalUnavailableReason> {
        match self {
            Self::Available(_) => None,
            Self::Unavailable(reason) => Some(*reason),
        }
    }
}

/// Summary of timestamp availability and validity across packets in a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FlowTimestampCoverage {
    /// Count of packets with valid, usable timestamps.
    pub available_timestamps: u64,
    /// Count of packets with [`PacketTimestamp::Unavailable`].
    pub unavailable_timestamps: u64,
    /// Count of packets with structurally invalid timestamps.
    pub invalid_timestamps: u64,
    /// Count of non-monotonic temporal transitions.
    pub non_monotonic_transitions: u64,
}

impl FlowTimestampCoverage {
    /// Creates a new timestamp coverage record.
    #[must_use]
    pub const fn new(
        available_timestamps: u64,
        unavailable_timestamps: u64,
        invalid_timestamps: u64,
        non_monotonic_transitions: u64,
    ) -> Self {
        Self {
            available_timestamps,
            unavailable_timestamps,
            invalid_timestamps,
            non_monotonic_transitions,
        }
    }
}

/// Factual packet, byte, and truncation counters for a directional traffic bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FlowTrafficCounters {
    /// Total number of packets associated with this bucket.
    pub packet_count: u64,
    /// Aggregate bytes captured (sum of [`crate::packet::PacketReference::captured_len`]).
    pub captured_bytes: u64,
    /// Aggregate original wire bytes (sum of [`crate::packet::PacketReference::original_len`]).
    pub wire_bytes: u64,
    /// Number of packets where [`crate::packet::PacketReference::truncated`] was true.
    pub truncated_packet_count: u64,
}

impl FlowTrafficCounters {
    /// Creates a new traffic counter bucket with explicit values.
    #[must_use]
    pub const fn new(
        packet_count: u64,
        captured_bytes: u64,
        wire_bytes: u64,
        truncated_packet_count: u64,
    ) -> Self {
        Self {
            packet_count,
            captured_bytes,
            wire_bytes,
            truncated_packet_count,
        }
    }

    /// Returns an empty counter bucket with zero values.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            packet_count: 0,
            captured_bytes: 0,
            wire_bytes: 0,
            truncated_packet_count: 0,
        }
    }
}

/// Factual bidirectional traffic statistics broken down by direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FlowTrafficStatistics {
    /// Total aggregate traffic across all directions.
    pub total: FlowTrafficCounters,
    /// Traffic transmitted from endpoint A to endpoint B.
    pub a_to_b: FlowTrafficCounters,
    /// Traffic transmitted from endpoint B to endpoint A.
    pub b_to_a: FlowTrafficCounters,
    /// Traffic transmitted where source equals destination endpoint.
    pub same_endpoint: FlowTrafficCounters,
}

impl FlowTrafficStatistics {
    /// Creates a new traffic statistics record.
    #[must_use]
    pub const fn new(
        total: FlowTrafficCounters,
        a_to_b: FlowTrafficCounters,
        b_to_a: FlowTrafficCounters,
        same_endpoint: FlowTrafficCounters,
    ) -> Self {
        Self {
            total,
            a_to_b,
            b_to_a,
            same_endpoint,
        }
    }

    /// Returns an empty traffic statistics record.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            total: FlowTrafficCounters::empty(),
            a_to_b: FlowTrafficCounters::empty(),
            b_to_a: FlowTrafficCounters::empty(),
            same_endpoint: FlowTrafficCounters::empty(),
        }
    }
}

/// Inter-arrival time statistics for an uninterrupted temporal series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowInterArrivalMetrics {
    /// Number of valid inter-arrival interval samples observed.
    pub interval_sample_count: u64,
    /// Number of temporal discontinuities (missing, invalid, or non-monotonic timestamps).
    pub discontinuity_count: u64,
    /// Minimum observed inter-arrival interval.
    pub minimum_interval: FlowTemporalValue<FlowDuration>,
    /// Maximum observed inter-arrival interval.
    pub maximum_interval: FlowTemporalValue<FlowDuration>,
    /// Exact mean inter-arrival interval (`sum / count`).
    pub mean_interval: FlowTemporalValue<FlowDuration>,
    /// Number of successive interval delta samples observed (`|d_{i+1} - d_i|`).
    pub successive_delta_sample_count: u64,
    /// Mean absolute successive interval delta.
    pub mean_absolute_successive_interval_delta: FlowTemporalValue<FlowDuration>,
}

impl FlowInterArrivalMetrics {
    /// Creates a new inter-arrival metrics record.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        interval_sample_count: u64,
        discontinuity_count: u64,
        minimum_interval: FlowTemporalValue<FlowDuration>,
        maximum_interval: FlowTemporalValue<FlowDuration>,
        mean_interval: FlowTemporalValue<FlowDuration>,
        successive_delta_sample_count: u64,
        mean_absolute_successive_interval_delta: FlowTemporalValue<FlowDuration>,
    ) -> Self {
        Self {
            interval_sample_count,
            discontinuity_count,
            minimum_interval,
            maximum_interval,
            mean_interval,
            successive_delta_sample_count,
            mean_absolute_successive_interval_delta,
        }
    }
}

/// Exact temporal metrics summarizing a completed flow instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowTemporalMetrics {
    /// Raw timestamp of the first associated packet.
    pub first_packet_timestamp: PacketTimestamp,
    /// Raw timestamp of the last associated packet.
    pub last_packet_timestamp: PacketTimestamp,
    /// Exact flow duration (`last - first`).
    pub duration: FlowTemporalValue<FlowDuration>,
    /// Timestamp availability and validity coverage counters.
    pub coverage: FlowTimestampCoverage,
    /// Inter-arrival statistics across all packets in the flow.
    pub overall_inter_arrival: FlowInterArrivalMetrics,
    /// Inter-arrival statistics for packets from endpoint A to B.
    pub a_to_b_inter_arrival: FlowInterArrivalMetrics,
    /// Inter-arrival statistics for packets from endpoint B to A.
    pub b_to_a_inter_arrival: FlowInterArrivalMetrics,
    /// Inter-arrival statistics for same-endpoint packets.
    pub same_endpoint_inter_arrival: FlowInterArrivalMetrics,
}

impl FlowTemporalMetrics {
    /// Creates a new temporal metrics record.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        first_packet_timestamp: PacketTimestamp,
        last_packet_timestamp: PacketTimestamp,
        duration: FlowTemporalValue<FlowDuration>,
        coverage: FlowTimestampCoverage,
        overall_inter_arrival: FlowInterArrivalMetrics,
        a_to_b_inter_arrival: FlowInterArrivalMetrics,
        b_to_a_inter_arrival: FlowInterArrivalMetrics,
        same_endpoint_inter_arrival: FlowInterArrivalMetrics,
    ) -> Self {
        Self {
            first_packet_timestamp,
            last_packet_timestamp,
            duration,
            coverage,
            overall_inter_arrival,
            a_to_b_inter_arrival,
            b_to_a_inter_arrival,
            same_endpoint_inter_arrival,
        }
    }
}

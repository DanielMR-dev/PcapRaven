//! Exact timestamp arithmetic and online fixed-size metric accumulators.

use crate::error::FlowError;
use pcapraven_domain::{
    FlowDirection, FlowDuration, FlowInterArrivalMetrics, FlowTemporalMetrics,
    FlowTemporalUnavailableReason, FlowTemporalValue, FlowTimestampCoverage, FlowTrafficCounters,
    FlowTrafficStatistics, PacketReference, PacketTimestamp, PacketTimestampResolution,
};

/// Computes the greatest common divisor of two `u128` integers.
#[must_use]
pub const fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Validates that a [`PacketTimestamp`] is structurally sound and internally consistent.
///
/// # Errors
/// Returns [`FlowTemporalUnavailableReason::TimestampUnavailable`] if unavailable,
/// or [`FlowTemporalUnavailableReason::InvalidTimestamp`] if fields contradict
/// resolution rules or exceed valid numerical ranges.
pub fn validate_timestamp_structure(
    ts: &PacketTimestamp,
) -> Result<(), FlowTemporalUnavailableReason> {
    match *ts {
        PacketTimestamp::Unavailable => Err(FlowTemporalUnavailableReason::TimestampUnavailable),
        PacketTimestamp::Available {
            seconds,
            fractional_units,
            resolution,
            offset_seconds,
        } => {
            let units = resolution.units_per_second();
            if units == 0 {
                return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
            }
            if fractional_units >= units {
                return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
            }
            match resolution {
                PacketTimestampResolution::Decimal {
                    exponent,
                    units_per_second,
                } => {
                    if exponent > 19 {
                        return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
                    }
                    let expected = 10u64.checked_pow(u32::from(exponent));
                    if expected != Some(units_per_second) {
                        return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
                    }
                }
                PacketTimestampResolution::Binary {
                    exponent,
                    units_per_second,
                } => {
                    if exponent >= 64 {
                        return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
                    }
                    let expected = 1u64.checked_shl(u32::from(exponent));
                    if expected != Some(units_per_second) {
                        return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
                    }
                }
            }
            if seconds.checked_add(i128::from(offset_seconds)).is_none() {
                return Err(FlowTemporalUnavailableReason::InvalidTimestamp);
            }
            Ok(())
        }
    }
}

/// Computes the exact non-negative duration between two timestamps without floating-point math.
///
/// # Errors
/// Returns [`FlowTemporalUnavailableReason`] if either timestamp is unavailable/invalid,
/// if timestamps are non-monotonic (`t2 < t1`), or on arithmetic overflow.
pub fn exact_duration_between(
    t1: &PacketTimestamp,
    t2: &PacketTimestamp,
) -> Result<FlowDuration, FlowTemporalUnavailableReason> {
    validate_timestamp_structure(t1)?;
    validate_timestamp_structure(t2)?;

    let (s1, f1, r1, o1) = match *t1 {
        PacketTimestamp::Available {
            seconds,
            fractional_units,
            resolution,
            offset_seconds,
        } => (seconds, fractional_units, resolution, offset_seconds),
        PacketTimestamp::Unavailable => {
            return Err(FlowTemporalUnavailableReason::TimestampUnavailable);
        }
    };

    let (s2, f2, r2, o2) = match *t2 {
        PacketTimestamp::Available {
            seconds,
            fractional_units,
            resolution,
            offset_seconds,
        } => (seconds, fractional_units, resolution, offset_seconds),
        PacketTimestamp::Unavailable => {
            return Err(FlowTemporalUnavailableReason::TimestampUnavailable);
        }
    };

    let eff_s1 = s1
        .checked_add(i128::from(o1))
        .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
    let eff_s2 = s2
        .checked_add(i128::from(o2))
        .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;

    let u1 = u128::from(r1.units_per_second());
    let u2 = u128::from(r2.units_per_second());
    let f1_128 = u128::from(f1);
    let f2_128 = u128::from(f2);

    if eff_s2 < eff_s1 {
        return Err(FlowTemporalUnavailableReason::NonMonotonicTimestamp);
    }

    let g = gcd(u1, u2);
    let u1_div_g = u1 / g;
    let u2_div_g = u2 / g;
    let lcm_den = u1_div_g
        .checked_mul(u2)
        .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;

    let f1_scaled = f1_128
        .checked_mul(u2_div_g)
        .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
    let f2_scaled = f2_128
        .checked_mul(u1_div_g)
        .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;

    if eff_s2 == eff_s1 {
        if f2_scaled < f1_scaled {
            return Err(FlowTemporalUnavailableReason::NonMonotonicTimestamp);
        }
        let frac_diff = f2_scaled - f1_scaled;
        FlowDuration::from_fraction(frac_diff, lcm_den)
            .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)
    } else {
        let sec_diff: u128 = (eff_s2 - eff_s1)
            .try_into()
            .map_err(|_| FlowTemporalUnavailableReason::ArithmeticOverflow)?;
        if f2_scaled >= f1_scaled {
            let frac_diff = f2_scaled - f1_scaled;
            let whole_units = sec_diff
                .checked_mul(lcm_den)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            let total_num = whole_units
                .checked_add(frac_diff)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            FlowDuration::from_fraction(total_num, lcm_den)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)
        } else {
            let sec_diff_borrowed = sec_diff
                .checked_sub(1)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            let frac_diff = lcm_den
                .checked_add(f2_scaled)
                .and_then(|v| v.checked_sub(f1_scaled))
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            let whole_units = sec_diff_borrowed
                .checked_mul(lcm_den)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            let total_num = whole_units
                .checked_add(frac_diff)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)?;
            FlowDuration::from_fraction(total_num, lcm_den)
                .ok_or(FlowTemporalUnavailableReason::ArithmeticOverflow)
        }
    }
}

/// Fixed-size factual traffic counter accumulator.
#[derive(Debug, Clone)]
pub(crate) struct TrafficAccumulator {
    total: FlowTrafficCounters,
    a_to_b: FlowTrafficCounters,
    b_to_a: FlowTrafficCounters,
    same_endpoint: FlowTrafficCounters,
}

impl TrafficAccumulator {
    pub(crate) fn new(
        direction: FlowDirection,
        packet: &PacketReference,
    ) -> Result<Self, FlowError> {
        let mut acc = Self {
            total: FlowTrafficCounters::empty(),
            a_to_b: FlowTrafficCounters::empty(),
            b_to_a: FlowTrafficCounters::empty(),
            same_endpoint: FlowTrafficCounters::empty(),
        };
        acc.observe(direction, packet)?;
        Ok(acc)
    }

    pub(crate) fn observe(
        &mut self,
        direction: FlowDirection,
        packet: &PacketReference,
    ) -> Result<(), FlowError> {
        let trunc_increment = if packet.truncated { 1 } else { 0 };

        let total_pkts =
            self.total
                .packet_count
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "traffic packet_count overflow",
                })?;
        let total_cap = self
            .total
            .captured_bytes
            .checked_add(u64::from(packet.captured_len))
            .ok_or(FlowError::InternalInvariant {
                detail: "traffic captured_bytes overflow",
            })?;
        let total_wire = self
            .total
            .wire_bytes
            .checked_add(u64::from(packet.original_len))
            .ok_or(FlowError::InternalInvariant {
                detail: "traffic wire_bytes overflow",
            })?;
        let total_trunc = self
            .total
            .truncated_packet_count
            .checked_add(trunc_increment)
            .ok_or(FlowError::InternalInvariant {
                detail: "traffic truncated_packet_count overflow",
            })?;

        let dir_bucket = match direction {
            FlowDirection::AToB => &mut self.a_to_b,
            FlowDirection::BToA => &mut self.b_to_a,
            FlowDirection::SameEndpoint => &mut self.same_endpoint,
        };

        let dir_pkts =
            dir_bucket
                .packet_count
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "directional packet_count overflow",
                })?;
        let dir_cap = dir_bucket
            .captured_bytes
            .checked_add(u64::from(packet.captured_len))
            .ok_or(FlowError::InternalInvariant {
                detail: "directional captured_bytes overflow",
            })?;
        let dir_wire = dir_bucket
            .wire_bytes
            .checked_add(u64::from(packet.original_len))
            .ok_or(FlowError::InternalInvariant {
                detail: "directional wire_bytes overflow",
            })?;
        let dir_trunc = dir_bucket
            .truncated_packet_count
            .checked_add(trunc_increment)
            .ok_or(FlowError::InternalInvariant {
                detail: "directional truncated_packet_count overflow",
            })?;

        self.total.packet_count = total_pkts;
        self.total.captured_bytes = total_cap;
        self.total.wire_bytes = total_wire;
        self.total.truncated_packet_count = total_trunc;

        dir_bucket.packet_count = dir_pkts;
        dir_bucket.captured_bytes = dir_cap;
        dir_bucket.wire_bytes = dir_wire;
        dir_bucket.truncated_packet_count = dir_trunc;

        Ok(())
    }

    #[must_use]
    pub(crate) fn finalize(self) -> FlowTrafficStatistics {
        FlowTrafficStatistics::new(self.total, self.a_to_b, self.b_to_a, self.same_endpoint)
    }
}

/// Fixed-size accumulator for a single directional or overall temporal inter-arrival series.
#[derive(Debug, Clone)]
pub(crate) struct SeriesAccumulator {
    interval_sample_count: u64,
    discontinuity_count: u64,
    min_interval: Option<FlowDuration>,
    max_interval: Option<FlowDuration>,
    sum_intervals: Option<FlowDuration>,
    previous_valid_timestamp: Option<PacketTimestamp>,
    previous_interval: Option<FlowDuration>,
    successive_delta_sample_count: u64,
    sum_successive_deltas: Option<FlowDuration>,
}

impl SeriesAccumulator {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            interval_sample_count: 0,
            discontinuity_count: 0,
            min_interval: None,
            max_interval: None,
            sum_intervals: Some(FlowDuration::ZERO),
            previous_valid_timestamp: None,
            previous_interval: None,
            successive_delta_sample_count: 0,
            sum_successive_deltas: Some(FlowDuration::ZERO),
        }
    }

    pub(crate) fn observe(&mut self, timestamp: &PacketTimestamp) {
        if validate_timestamp_structure(timestamp).is_err() {
            if self.previous_valid_timestamp.is_some() {
                self.discontinuity_count = self.discontinuity_count.saturating_add(1);
            }
            self.previous_valid_timestamp = None;
            self.previous_interval = None;
            return;
        }

        let prev = match self.previous_valid_timestamp {
            Some(prev_ts) => prev_ts,
            None => {
                self.previous_valid_timestamp = Some(*timestamp);
                self.previous_interval = None;
                return;
            }
        };

        match exact_duration_between(&prev, timestamp) {
            Ok(interval) => {
                self.interval_sample_count = self.interval_sample_count.saturating_add(1);
                self.min_interval = Some(match self.min_interval {
                    Some(cur_min) => cur_min.min(interval),
                    None => interval,
                });
                self.max_interval = Some(match self.max_interval {
                    Some(cur_max) => cur_max.max(interval),
                    None => interval,
                });

                if let Some(cur_sum) = self.sum_intervals {
                    match cur_sum.checked_add(&interval) {
                        Some(new_sum) => self.sum_intervals = Some(new_sum),
                        None => {
                            self.sum_intervals = None;
                        }
                    }
                }

                if let Some(prev_interval) = self.previous_interval {
                    let diff = if interval >= prev_interval {
                        interval.checked_sub(&prev_interval)
                    } else {
                        prev_interval.checked_sub(&interval)
                    };
                    if let Some(abs_delta) = diff {
                        self.successive_delta_sample_count =
                            self.successive_delta_sample_count.saturating_add(1);
                        if let Some(cur_sum_deltas) = self.sum_successive_deltas {
                            match cur_sum_deltas.checked_add(&abs_delta) {
                                Some(new_sum) => self.sum_successive_deltas = Some(new_sum),
                                None => {
                                    self.sum_successive_deltas = None;
                                }
                            }
                        }
                    }
                }

                self.previous_interval = Some(interval);
                self.previous_valid_timestamp = Some(*timestamp);
            }
            Err(FlowTemporalUnavailableReason::NonMonotonicTimestamp) => {
                self.discontinuity_count = self.discontinuity_count.saturating_add(1);
                self.previous_valid_timestamp = Some(*timestamp);
                self.previous_interval = None;
            }
            Err(FlowTemporalUnavailableReason::ArithmeticOverflow) => {
                self.discontinuity_count = self.discontinuity_count.saturating_add(1);
                self.previous_valid_timestamp = Some(*timestamp);
                self.previous_interval = None;
            }
            Err(_) => {
                if self.previous_valid_timestamp.is_some() {
                    self.discontinuity_count = self.discontinuity_count.saturating_add(1);
                }
                self.previous_valid_timestamp = None;
                self.previous_interval = None;
            }
        }
    }

    #[must_use]
    pub(crate) fn finalize(self) -> FlowInterArrivalMetrics {
        let min_val = if self.interval_sample_count == 0 {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
        } else if let Some(m) = self.min_interval {
            FlowTemporalValue::Available(m)
        } else {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
        };

        let max_val = if self.interval_sample_count == 0 {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
        } else if let Some(m) = self.max_interval {
            FlowTemporalValue::Available(m)
        } else {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
        };

        let mean_val = if self.interval_sample_count == 0 {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
        } else if let Some(sum) = self.sum_intervals {
            if let Some(new_den) = sum
                .denominator()
                .checked_mul(u128::from(self.interval_sample_count))
            {
                match FlowDuration::from_fraction(sum.numerator(), new_den) {
                    Some(mean) => FlowTemporalValue::Available(mean),
                    None => FlowTemporalValue::Unavailable(
                        FlowTemporalUnavailableReason::ArithmeticOverflow,
                    ),
                }
            } else {
                FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
            }
        } else {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
        };

        let mean_delta_val = if self.successive_delta_sample_count == 0 {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InsufficientSamples)
        } else if let Some(sum_deltas) = self.sum_successive_deltas {
            if let Some(new_den) = sum_deltas
                .denominator()
                .checked_mul(u128::from(self.successive_delta_sample_count))
            {
                match FlowDuration::from_fraction(sum_deltas.numerator(), new_den) {
                    Some(mean_delta) => FlowTemporalValue::Available(mean_delta),
                    None => FlowTemporalValue::Unavailable(
                        FlowTemporalUnavailableReason::ArithmeticOverflow,
                    ),
                }
            } else {
                FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
            }
        } else {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::ArithmeticOverflow)
        };

        FlowInterArrivalMetrics::new(
            self.interval_sample_count,
            self.discontinuity_count,
            min_val,
            max_val,
            mean_val,
            self.successive_delta_sample_count,
            mean_delta_val,
        )
    }
}

/// Fixed-size factual temporal metrics accumulator.
#[derive(Debug, Clone)]
pub(crate) struct TemporalAccumulator {
    first_packet_timestamp: PacketTimestamp,
    last_packet_timestamp: PacketTimestamp,
    coverage: FlowTimestampCoverage,
    overall: SeriesAccumulator,
    a_to_b: SeriesAccumulator,
    b_to_a: SeriesAccumulator,
    same_endpoint: SeriesAccumulator,
}

impl TemporalAccumulator {
    pub(crate) fn new(direction: FlowDirection, timestamp: &PacketTimestamp) -> Self {
        let mut acc = Self {
            first_packet_timestamp: *timestamp,
            last_packet_timestamp: *timestamp,
            coverage: FlowTimestampCoverage::default(),
            overall: SeriesAccumulator::new(),
            a_to_b: SeriesAccumulator::new(),
            b_to_a: SeriesAccumulator::new(),
            same_endpoint: SeriesAccumulator::new(),
        };
        acc.observe(direction, timestamp);
        acc
    }

    pub(crate) fn observe(&mut self, direction: FlowDirection, timestamp: &PacketTimestamp) {
        match timestamp {
            PacketTimestamp::Unavailable => {
                self.coverage.unavailable_timestamps =
                    self.coverage.unavailable_timestamps.saturating_add(1);
            }
            PacketTimestamp::Available { .. } => {
                if validate_timestamp_structure(timestamp).is_ok() {
                    self.coverage.available_timestamps =
                        self.coverage.available_timestamps.saturating_add(1);
                } else {
                    self.coverage.invalid_timestamps =
                        self.coverage.invalid_timestamps.saturating_add(1);
                }
            }
        }

        if let Some(prev) = self.overall.previous_valid_timestamp {
            if validate_timestamp_structure(timestamp).is_ok() {
                if let Err(FlowTemporalUnavailableReason::NonMonotonicTimestamp) =
                    exact_duration_between(&prev, timestamp)
                {
                    self.coverage.non_monotonic_transitions =
                        self.coverage.non_monotonic_transitions.saturating_add(1);
                }
            }
        }

        self.overall.observe(timestamp);

        match direction {
            FlowDirection::AToB => self.a_to_b.observe(timestamp),
            FlowDirection::BToA => self.b_to_a.observe(timestamp),
            FlowDirection::SameEndpoint => self.same_endpoint.observe(timestamp),
        }

        self.last_packet_timestamp = *timestamp;
    }

    #[must_use]
    pub(crate) fn finalize(self) -> FlowTemporalMetrics {
        let duration = if !self.first_packet_timestamp.is_available()
            || !self.last_packet_timestamp.is_available()
        {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::TimestampUnavailable)
        } else if validate_timestamp_structure(&self.first_packet_timestamp).is_err()
            || validate_timestamp_structure(&self.last_packet_timestamp).is_err()
        {
            FlowTemporalValue::Unavailable(FlowTemporalUnavailableReason::InvalidTimestamp)
        } else {
            match exact_duration_between(&self.first_packet_timestamp, &self.last_packet_timestamp)
            {
                Ok(dur) => FlowTemporalValue::Available(dur),
                Err(reason) => FlowTemporalValue::Unavailable(reason),
            }
        };

        FlowTemporalMetrics::new(
            self.first_packet_timestamp,
            self.last_packet_timestamp,
            duration,
            self.coverage,
            self.overall.finalize(),
            self.a_to_b.finalize(),
            self.b_to_a.finalize(),
            self.same_endpoint.finalize(),
        )
    }
}

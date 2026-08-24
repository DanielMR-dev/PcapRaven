//! Explainable periodic beaconing detector over exact directional flow temporal metrics.
//!
//! Evaluates regular, low-jitter directional traffic patterns without floating-point numbers
//! or heuristic malware claims.

use crate::config::{DetectorParameterValue, DetectorParameters};
use crate::detector::{Detector, DetectorDraftSink, DetectorMetadata, IncompleteDataPolicy};
use crate::engine::DetectionInput;
use crate::error::{DetectorConfigError, DetectorExecutionError};
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceComparison, EvidenceDescription,
    EvidenceDraft, EvidenceKind, EvidenceMeasurement, EvidenceMetricKey, EvidenceRatio,
    EvidenceUnit, EvidenceValue, FindingDraft, FindingRationale, FindingSubject, FindingSummary,
    FindingTitle, FlowDirection, FlowDuration, FlowEndReason, FlowInterArrivalMetrics, FlowRecord,
    FlowTemporalValue, Severity,
};

/// Greatest common divisor for 128-bit unsigned integers.
const fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Computes an exact rational ratio `dur_num / dur_den` using cross-cancellation GCD.
fn compute_duration_ratio(
    dur_num: &FlowDuration,
    dur_den: &FlowDuration,
) -> Result<EvidenceRatio, DetectorExecutionError> {
    if dur_den.numerator() == 0 {
        return Err(DetectorExecutionError::internal_error(
            "unable to construct exact duration ratio: zero denominator",
        ));
    }
    let a = dur_num.numerator();
    let b = dur_num.denominator();
    let c = dur_den.numerator();
    let d = dur_den.denominator();

    let g1 = gcd(a, c);
    let a1 = a / g1;
    let c1 = c / g1;

    let g2 = gcd(d, b);
    let d1 = d / g2;
    let b1 = b / g2;

    let num = a1.checked_mul(d1).ok_or_else(|| {
        DetectorExecutionError::internal_error(
            "unable to construct exact duration ratio: numerator overflow",
        )
    })?;
    let den = b1.checked_mul(c1).ok_or_else(|| {
        DetectorExecutionError::internal_error(
            "unable to construct exact duration ratio: denominator overflow",
        )
    })?;

    EvidenceRatio::from_fraction(num, den).ok_or_else(|| {
        DetectorExecutionError::internal_error("unable to construct exact duration ratio")
    })
}

/// Detector identifying periodic communication patterns across directional flow intervals.
///
/// Evaluates inter-arrival timing statistics independently for both flow directions (`A -> B` and `B -> A`),
/// applying exact rational thresholds for sample count, minimum mean interval, relative jitter ratio, and spread ratio.
#[derive(Debug, Clone)]
pub struct PeriodicBeaconingDetector {
    metadata: DetectorMetadata,
}

impl PeriodicBeaconingDetector {
    /// Canonical detector ID (`behavior.periodic_beaconing`).
    pub const DETECTOR_ID: &'static str = "behavior.periodic_beaconing";
    /// Canonical detector version (`1.0.0`).
    pub const DETECTOR_VERSION: DetectorVersion = DetectorVersion::new(1, 0, 0);

    /// Parameter key for minimum interval samples (`minimum_interval_samples`).
    pub const PARAM_MINIMUM_INTERVAL_SAMPLES: &'static str = "minimum_interval_samples";
    /// Default minimum interval samples (6).
    pub const DEFAULT_MINIMUM_INTERVAL_SAMPLES: u64 = 6;
    /// Hard minimum allowed for minimum interval samples (3).
    pub const HARD_MIN_INTERVAL_SAMPLES: u64 = 3;

    /// Parameter key for maximum jitter ratio (`maximum_jitter_ratio`).
    pub const PARAM_MAXIMUM_JITTER_RATIO: &'static str = "maximum_jitter_ratio";
    /// Default maximum jitter ratio numerator (1).
    pub const DEFAULT_MAX_JITTER_NUMERATOR: u64 = 1;
    /// Default maximum jitter ratio denominator (10, meaning 10%).
    pub const DEFAULT_MAX_JITTER_DENOMINATOR: u64 = 10;
    /// Default maximum jitter ratio (1/10).
    pub const DEFAULT_MAX_JITTER_RATIO: EvidenceRatio = match EvidenceRatio::from_fraction(1, 10) {
        Some(r) => r,
        None => EvidenceRatio::ZERO,
    };

    /// Parameter key for maximum spread ratio (`maximum_spread_ratio`).
    pub const PARAM_MAXIMUM_SPREAD_RATIO: &'static str = "maximum_spread_ratio";
    /// Default maximum spread ratio numerator (1).
    pub const DEFAULT_MAX_SPREAD_NUMERATOR: u64 = 1;
    /// Default maximum spread ratio denominator (4, meaning 25%).
    pub const DEFAULT_MAX_SPREAD_DENOMINATOR: u64 = 4;
    /// Default maximum spread ratio (1/4).
    pub const DEFAULT_MAX_SPREAD_RATIO: EvidenceRatio = match EvidenceRatio::from_fraction(1, 4) {
        Some(r) => r,
        None => EvidenceRatio::ZERO,
    };

    /// Parameter key for minimum mean interval (`minimum_mean_interval`).
    pub const PARAM_MINIMUM_MEAN_INTERVAL: &'static str = "minimum_mean_interval";
    /// Default minimum mean interval in seconds (1s).
    pub const DEFAULT_MIN_MEAN_INTERVAL_SECS: u64 = 1;

    /// Fallibly creates and initializes a new periodic beaconing detector instance.
    pub fn try_new() -> Result<Self, pcapraven_domain::FindingValidationError> {
        let id = DetectorId::try_new(Self::DETECTOR_ID)?;
        let title = FindingTitle::try_new("Possible periodic beaconing behavior")?;
        let purpose = FindingSummary::try_new(
            "Identify reconstructed flow instances exhibiting highly regular directional packet inter-arrival timing using exact temporal metrics",
        )?;

        Ok(Self {
            metadata: DetectorMetadata::new(
                id,
                Self::DETECTOR_VERSION,
                title,
                purpose,
                IncompleteDataPolicy::Skip,
            ),
        })
    }

    fn parse_and_validate_parameters(
        parameters: &DetectorParameters,
    ) -> Result<(u64, EvidenceRatio, EvidenceRatio, FlowDuration), DetectorConfigError> {
        let mut min_samples = Self::DEFAULT_MINIMUM_INTERVAL_SAMPLES;
        let mut max_jitter = Self::DEFAULT_MAX_JITTER_RATIO;
        let mut max_spread = Self::DEFAULT_MAX_SPREAD_RATIO;
        let mut min_mean_interval = FlowDuration::from_secs(Self::DEFAULT_MIN_MEAN_INTERVAL_SECS);

        for param in parameters.iter() {
            let key = param.key.as_str();
            match key {
                Self::PARAM_MINIMUM_INTERVAL_SAMPLES => {
                    let val = match &param.value {
                        DetectorParameterValue::Unsigned(u) => *u,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "unsigned integer",
                            });
                        }
                    };
                    if val < Self::HARD_MIN_INTERVAL_SAMPLES as u128 {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "minimum interval samples must be at least 3",
                        });
                    }
                    if val > u64::MAX as u128 {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "minimum interval samples exceeds u64 bounds",
                        });
                    }
                    min_samples = val as u64;
                }
                Self::PARAM_MAXIMUM_JITTER_RATIO => {
                    let ratio = match &param.value {
                        DetectorParameterValue::Ratio(r) => *r,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "evidence ratio",
                            });
                        }
                    };
                    if ratio > EvidenceRatio::ONE {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum jitter ratio cannot exceed 1.0 (1/1)",
                        });
                    }
                    max_jitter = ratio;
                }
                Self::PARAM_MAXIMUM_SPREAD_RATIO => {
                    let ratio = match &param.value {
                        DetectorParameterValue::Ratio(r) => *r,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "evidence ratio",
                            });
                        }
                    };
                    if ratio > EvidenceRatio::ONE {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "maximum spread ratio cannot exceed 1.0 (1/1)",
                        });
                    }
                    max_spread = ratio;
                }
                Self::PARAM_MINIMUM_MEAN_INTERVAL => {
                    let dur = match &param.value {
                        DetectorParameterValue::Duration(d) => *d,
                        _ => {
                            return Err(DetectorConfigError::InvalidParameterType {
                                key: key.to_string(),
                                expected: "flow duration",
                            });
                        }
                    };
                    if dur.numerator() == 0 {
                        return Err(DetectorConfigError::ParameterValueOutOfRange {
                            key: key.to_string(),
                            reason: "minimum mean interval must be greater than zero",
                        });
                    }
                    min_mean_interval = dur;
                }
                _ => {
                    return Err(DetectorConfigError::UnknownParameter(key.to_string()));
                }
            }
        }

        Ok((min_samples, max_jitter, max_spread, min_mean_interval))
    }

    fn evaluate_direction(
        flow: &FlowRecord,
        direction: FlowDirection,
        metrics: &FlowInterArrivalMetrics,
        min_samples: u64,
        max_jitter: EvidenceRatio,
        max_spread: EvidenceRatio,
        min_mean_interval: FlowDuration,
    ) -> Result<Option<EvidenceDraft>, DetectorExecutionError> {
        // 1. Clean timestamps requirement: zero discontinuities
        if metrics.discontinuity_count > 0 {
            return Ok(None);
        }

        // 2. Minimum interval sample count requirement
        if metrics.interval_sample_count < min_samples {
            return Ok(None);
        }

        // 3. Minimum successive delta sample count requirement (>= min_samples - 1)
        let min_deltas = min_samples.saturating_sub(1);
        if metrics.successive_delta_sample_count < min_deltas {
            return Ok(None);
        }

        // 4. Extract mean interval
        let mean_dur = match &metrics.mean_interval {
            FlowTemporalValue::Available(d) => *d,
            FlowTemporalValue::Unavailable(_) => return Ok(None),
        };

        if mean_dur.numerator() == 0 || mean_dur < min_mean_interval {
            return Ok(None);
        }

        // 5. Extract minimum and maximum intervals
        let min_dur = match &metrics.minimum_interval {
            FlowTemporalValue::Available(d) => *d,
            FlowTemporalValue::Unavailable(_) => return Ok(None),
        };
        let max_dur = match &metrics.maximum_interval {
            FlowTemporalValue::Available(d) => *d,
            FlowTemporalValue::Unavailable(_) => return Ok(None),
        };

        // 6. Extract mean absolute successive interval delta (jitter)
        let jitter_dur = match &metrics.mean_absolute_successive_interval_delta {
            FlowTemporalValue::Available(d) => *d,
            FlowTemporalValue::Unavailable(_) => return Ok(None),
        };

        // 7. Calculate spread: max_dur - min_dur
        let spread_dur = match max_dur.checked_sub(&min_dur) {
            Some(s) => s,
            None => return Ok(None),
        };

        // 8. Check Jitter Ratio Condition: observed_jitter <= max_jitter using exact ratio
        let observed_jitter_ratio = compute_duration_ratio(&jitter_dur, &mean_dur)?;
        if observed_jitter_ratio > max_jitter {
            return Ok(None);
        }

        // 9. Check Spread Ratio Condition: observed_spread <= max_spread using exact ratio
        let observed_spread_ratio = compute_duration_ratio(&spread_dur, &mean_dur)?;
        if observed_spread_ratio > max_spread {
            return Ok(None);
        }

        // 10. Build Directional EvidenceDraft (EvidenceKind::TemporalMetric)
        let desc_text = match direction {
            FlowDirection::AToB => "A-to-B periodic inter-arrival timing metrics",
            FlowDirection::BToA => "B-to-A periodic inter-arrival timing metrics",
            FlowDirection::SameEndpoint => "Same-endpoint periodic inter-arrival timing metrics",
        };

        let desc = EvidenceDescription::try_new(desc_text).map_err(|e| {
            DetectorExecutionError::internal_error(format!("invalid evidence description: {e}"))
        })?;

        let mut builder = EvidenceDraft::builder(EvidenceKind::TemporalMetric, desc);
        builder.add_flow_reference(flow.reference).map_err(|e| {
            DetectorExecutionError::internal_error(format!("failed adding flow reference: {e}"))
        })?;

        // Add measurements in strictly increasing metric key order:
        // 1. discontinuity_count
        builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("discontinuity_count").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Unsigned(0),
                    EvidenceUnit::Count,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 2. interval_sample_count
        builder
            .add_measurement(
                EvidenceMeasurement::try_with_threshold(
                    EvidenceMetricKey::try_new("interval_sample_count").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Unsigned(metrics.interval_sample_count as u128),
                    EvidenceValue::Unsigned(min_samples as u128),
                    EvidenceComparison::GreaterThanOrEqual,
                    EvidenceUnit::Count,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 3. maximum_interval
        builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("maximum_interval").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Duration(max_dur),
                    EvidenceUnit::Seconds,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 4. mean_absolute_successive_interval_delta
        builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("mean_absolute_successive_interval_delta").map_err(
                        |e| {
                            DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                        },
                    )?,
                    EvidenceValue::Duration(jitter_dur),
                    EvidenceUnit::Seconds,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 5. mean_interval
        builder
            .add_measurement(
                EvidenceMeasurement::try_with_threshold(
                    EvidenceMetricKey::try_new("mean_interval").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Duration(mean_dur),
                    EvidenceValue::Duration(min_mean_interval),
                    EvidenceComparison::GreaterThanOrEqual,
                    EvidenceUnit::Seconds,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 6. minimum_interval
        builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("minimum_interval").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Duration(min_dur),
                    EvidenceUnit::Seconds,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 7. relative_jitter_ratio
        builder
            .add_measurement(
                EvidenceMeasurement::try_with_threshold(
                    EvidenceMetricKey::try_new("relative_jitter_ratio").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Ratio(observed_jitter_ratio),
                    EvidenceValue::Ratio(max_jitter),
                    EvidenceComparison::LessThanOrEqual,
                    EvidenceUnit::Ratio,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 8. spread_ratio
        builder
            .add_measurement(
                EvidenceMeasurement::try_with_threshold(
                    EvidenceMetricKey::try_new("spread_ratio").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Ratio(observed_spread_ratio),
                    EvidenceValue::Ratio(max_spread),
                    EvidenceComparison::LessThanOrEqual,
                    EvidenceUnit::Ratio,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        // 9. successive_delta_sample_count
        builder
            .add_measurement(
                EvidenceMeasurement::try_new(
                    EvidenceMetricKey::try_new("successive_delta_sample_count").map_err(|e| {
                        DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                    })?,
                    EvidenceValue::Unsigned(metrics.successive_delta_sample_count as u128),
                    EvidenceUnit::Count,
                )
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("measurement error: {e}"))
                })?,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "builder add measurement error: {e}"
                ))
            })?;

        let draft = builder.build().map_err(|e| {
            DetectorExecutionError::internal_error(format!("evidence build error: {e}"))
        })?;

        Ok(Some(draft))
    }
}

impl Detector for PeriodicBeaconingDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        Self::parse_and_validate_parameters(parameters).map(|_| ())
    }

    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let (min_samples, max_jitter, max_spread, min_mean_interval) =
            Self::parse_and_validate_parameters(parameters).map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "unexpected parameter validation failure: {e}"
                ))
            })?;

        for flow in input.flows() {
            // Check flow-level temporal eligibility:
            // 1. Not AnalysisStopped
            if flow.end_reason == FlowEndReason::AnalysisStopped {
                continue;
            }

            // 2. Clean temporal coverage: zero unavailable, invalid, or non-monotonic timestamps
            if flow.temporal.coverage.unavailable_timestamps > 0
                || flow.temporal.coverage.invalid_timestamps > 0
                || flow.temporal.coverage.non_monotonic_transitions > 0
            {
                continue;
            }

            // 3. Duration must be Available
            if !flow.temporal.duration.is_available() {
                continue;
            }

            let mut directional_evidence = Vec::new();

            // Evaluate Direction A -> B
            if let Some(evi_a) = Self::evaluate_direction(
                flow,
                FlowDirection::AToB,
                &flow.temporal.a_to_b_inter_arrival,
                min_samples,
                max_jitter,
                max_spread,
                min_mean_interval,
            )? {
                directional_evidence.push(evi_a);
            }

            // Evaluate Direction B -> A
            if let Some(evi_b) = Self::evaluate_direction(
                flow,
                FlowDirection::BToA,
                &flow.temporal.b_to_a_inter_arrival,
                min_samples,
                max_jitter,
                max_spread,
                min_mean_interval,
            )? {
                directional_evidence.push(evi_b);
            }

            if directional_evidence.is_empty() {
                continue;
            }

            let subject = FindingSubject::try_new(Vec::new(), vec![flow.reference], Vec::new())
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!("invalid finding subject: {e}"))
                })?;

            let title =
                FindingTitle::try_new("Possible periodic beaconing behavior").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("invalid finding title: {e}"))
                })?;

            let summary = FindingSummary::try_new(
                "Observed highly regular directional packet timing intervals consistent with possible periodic beaconing",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("invalid finding summary: {e}"))
            })?;

            let rationale = FindingRationale::try_new(
                "Directional traffic in this flow exhibits low-jitter periodic inter-arrival timing satisfying configured statistical thresholds. Periodic timing is common in application keepalives, health checks, monitoring agents, scheduled polling, and heartbeat traffic, and does not establish malicious activity without independent corroborating evidence.",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("invalid finding rationale: {e}"))
            })?;

            let draft = FindingDraft::try_new(
                subject,
                title,
                summary,
                rationale,
                Severity::Low,
                Confidence::Medium,
                directional_evidence,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("invalid finding draft: {e}"))
            })?;

            output.push(draft)?;
        }

        Ok(())
    }
}

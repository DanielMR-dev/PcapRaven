//! Explainable DNS anomaly and possible DNS tunneling detectors.
//!
//! Provides two pure heuristic detectors:
//! - [`DnsLongQueryNameDetector`]: flags complete DNS query observations containing questions with unusually long, high-octet-diversity domain names.
//! - [`DnsPossibleTunnelingDetector`]: flags flows exhibiting repeated DNS query observations with long, high-octet-diversity domain names.

use std::collections::BTreeMap;

use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, DnsMessageKind, DnsQuestion, EvidenceComparison,
    EvidenceDescription, EvidenceDraftBuilder, EvidenceKind, EvidenceMeasurement,
    EvidenceMetricKey, EvidenceRatio, EvidenceUnit, EvidenceValue, FindingDraft, FindingRationale,
    FindingSubject, FindingSummary, FindingTitle, FindingValidationError, FlowEndReason,
    FlowReference, MitreAttackId, MitreMapping, MitreMappingProvenance, MitreMappingRationale,
    MitreTactic, ObservationFlowAssociation, ObservationReference, ProtocolKind,
    ProtocolObservationData, Severity,
};

use crate::config::{DetectorParameterValue, DetectorParameters};
use crate::detector::{Detector, DetectorDraftSink, DetectorMetadata, IncompleteDataPolicy};
use crate::engine::DetectionInput;
use crate::error::{DetectorConfigError, DetectorExecutionError};

/// Calculates the exact ratio of distinct octets to total label length for a DNS label.
///
/// Returns an [`EvidenceRatio`] in canonical lowest terms. If the label is empty, returns [`EvidenceRatio::ZERO`].
/// Uses a fixed `[bool; 256]` bitmap without any floating-point numbers, heap allocations, or Shannon entropy approximations.
#[must_use]
pub fn label_octet_diversity_ratio(label: &[u8]) -> EvidenceRatio {
    if label.is_empty() {
        return EvidenceRatio::ZERO;
    }
    let mut seen = [false; 256];
    let mut distinct_count = 0u128;
    for &b in label {
        let idx = b as usize;
        if !seen[idx] {
            seen[idx] = true;
            distinct_count = match distinct_count.checked_add(1) {
                Some(c) => c,
                None => return EvidenceRatio::ZERO,
            };
        }
    }
    let length = match u128::try_from(label.len()) {
        Ok(l) => l,
        Err(_) => return EvidenceRatio::ZERO,
    };
    EvidenceRatio::from_fraction(distinct_count, length).unwrap_or(EvidenceRatio::ZERO)
}

/// Evaluated structural shape of a single DNS question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsQuestionShape {
    qname_wire_length: usize,
    maximum_label_length: usize,
    maximum_label_octet_diversity_ratio: EvidenceRatio,
    matches: bool,
}

impl DnsQuestionShape {
    fn evaluate(
        question: &DnsQuestion,
        min_qname_wire_length: usize,
        min_label_length: usize,
        min_diversity_ratio: EvidenceRatio,
    ) -> Self {
        let qname_wire_length = question.name.wire_length();
        let labels = question.name.labels();

        let mut max_qualifying_label_length = 0usize;
        let mut max_qualifying_diversity_ratio = EvidenceRatio::ZERO;

        for label in labels {
            if label.len() >= min_label_length {
                if label.len() > max_qualifying_label_length {
                    max_qualifying_label_length = label.len();
                }
                let div = label_octet_diversity_ratio(label);
                if div > max_qualifying_diversity_ratio {
                    max_qualifying_diversity_ratio = div;
                }
            }
        }

        let matches = qname_wire_length >= min_qname_wire_length
            && max_qualifying_label_length >= min_label_length
            && max_qualifying_diversity_ratio >= min_diversity_ratio;

        Self {
            qname_wire_length,
            maximum_label_length: max_qualifying_label_length,
            maximum_label_octet_diversity_ratio: max_qualifying_diversity_ratio,
            matches,
        }
    }
}

/// Detector identifying complete DNS query observations containing questions with unusually long, high-octet-diversity names.
#[derive(Debug, Clone)]
pub struct DnsLongQueryNameDetector {
    metadata: DetectorMetadata,
}

impl DnsLongQueryNameDetector {
    /// Canonical detector identifier (`dns.long_query_name`).
    pub const DETECTOR_ID: &'static str = "dns.long_query_name";
    /// Detector version (`v1.0.1`).
    pub const DETECTOR_VERSION: DetectorVersion = DetectorVersion::new(1, 0, 1);

    /// Parameter key for minimum QNAME wire length (`minimum_qname_wire_length`).
    pub const PARAM_MINIMUM_QNAME_WIRE_LENGTH: &'static str = "minimum_qname_wire_length";
    /// Default minimum QNAME wire length in octets (120).
    pub const DEFAULT_MIN_QNAME_WIRE_LENGTH: u64 = 120;

    /// Parameter key for minimum label length (`minimum_label_length`).
    pub const PARAM_MINIMUM_LABEL_LENGTH: &'static str = "minimum_label_length";
    /// Default minimum individual label length in octets (40).
    pub const DEFAULT_MIN_LABEL_LENGTH: u64 = 40;

    /// Parameter key for minimum label octet diversity ratio (`minimum_label_octet_diversity_ratio`).
    pub const PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO: &'static str =
        "minimum_label_octet_diversity_ratio";
    /// Default minimum label octet diversity ratio (1/3).
    pub const DEFAULT_MIN_LABEL_OCTET_DIVERSITY_RATIO: EvidenceRatio =
        match EvidenceRatio::from_fraction(1, 3) {
            Some(r) => r,
            None => EvidenceRatio::ZERO,
        };

    /// Hard maximum QNAME wire length limit (255 per RFC 1035).
    pub const MAX_QNAME_WIRE_LENGTH_LIMIT: u64 = 255;
    /// Hard maximum label length limit (63 per RFC 1035).
    pub const MAX_LABEL_LENGTH_LIMIT: u64 = 63;

    /// Creates and initializes a new long query name detector instance.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("canonical detector metadata is valid")
    }

    /// Fallibly creates and initializes a new long query name detector instance.
    pub fn try_new() -> Result<Self, FindingValidationError> {
        let id = DetectorId::try_new(Self::DETECTOR_ID)?;
        let title = FindingTitle::try_new("Unusually long DNS query name")?;
        let purpose = FindingSummary::try_new(
            "Identify complete DNS query observations containing questions with unusually long, high-octet-diversity domain names",
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
}

impl Default for DnsLongQueryNameDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DnsLongQueryNameDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        for param in parameters.iter() {
            let key = param.key.as_str();
            match key {
                Self::PARAM_MINIMUM_QNAME_WIRE_LENGTH => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val == 0 || *val > Self::MAX_QNAME_WIRE_LENGTH_LIMIT as u128 {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum QNAME wire length must be between 1 and 255 octets",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                Self::PARAM_MINIMUM_LABEL_LENGTH => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val == 0 || *val > Self::MAX_LABEL_LENGTH_LIMIT as u128 {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum label length must be between 1 and 63 octets",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                Self::PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO => match &param.value {
                    DetectorParameterValue::Ratio(r) => {
                        if *r > EvidenceRatio::ONE {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum label octet diversity ratio must be between 0 and 1",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "ratio",
                        });
                    }
                },
                unknown => {
                    return Err(DetectorConfigError::UnknownParameter(unknown.to_string()));
                }
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let min_qname_wire_length = match parameters.get(Self::PARAM_MINIMUM_QNAME_WIRE_LENGTH) {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "minimum_qname_wire_length exceeds host usize",
                )
            })?,
            _ => usize::try_from(Self::DEFAULT_MIN_QNAME_WIRE_LENGTH).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "default minimum_qname_wire_length exceeds host usize",
                )
            })?,
        };

        let min_label_length = match parameters.get(Self::PARAM_MINIMUM_LABEL_LENGTH) {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error("minimum_label_length exceeds host usize")
            })?,
            _ => usize::try_from(Self::DEFAULT_MIN_LABEL_LENGTH).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "default minimum_label_length exceeds host usize",
                )
            })?,
        };

        let min_diversity_ratio =
            match parameters.get(Self::PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO) {
                Some(DetectorParameterValue::Ratio(r)) => *r,
                _ => Self::DEFAULT_MIN_LABEL_OCTET_DIVERSITY_RATIO,
            };

        for obs in input.observations() {
            if obs.reference().protocol() != ProtocolKind::Dns {
                continue;
            }
            let dns = match obs.data() {
                ProtocolObservationData::Dns(d) => d,
                _ => continue,
            };

            // Inspect only complete query messages (message_kind == Query AND flags.qr == false)
            if !obs.completeness().is_complete() {
                continue;
            }
            if dns.message_kind != DnsMessageKind::Query || dns.flags.qr {
                continue;
            }

            if dns.questions.is_empty() {
                continue;
            }

            let mut question_count = 0u128;
            let mut matching_question_count = 0u128;
            let mut max_qname_wire_length = 0usize;
            let mut max_label_length = 0usize;
            let mut max_diversity_ratio = EvidenceRatio::ZERO;

            for question in &dns.questions {
                question_count = question_count.checked_add(1).ok_or_else(|| {
                    DetectorExecutionError::internal_error("question count overflow")
                })?;
                let shape = DnsQuestionShape::evaluate(
                    question,
                    min_qname_wire_length,
                    min_label_length,
                    min_diversity_ratio,
                );

                if shape.matches {
                    matching_question_count =
                        matching_question_count.checked_add(1).ok_or_else(|| {
                            DetectorExecutionError::internal_error(
                                "matching question count overflow",
                            )
                        })?;
                    if shape.qname_wire_length > max_qname_wire_length {
                        max_qname_wire_length = shape.qname_wire_length;
                    }
                    if shape.maximum_label_length > max_label_length {
                        max_label_length = shape.maximum_label_length;
                    }
                    if shape.maximum_label_octet_diversity_ratio > max_diversity_ratio {
                        max_diversity_ratio = shape.maximum_label_octet_diversity_ratio;
                    }
                }
            }

            // Emit finding only if at least one question matches the query-shape rule
            if matching_question_count == 0 {
                continue;
            }

            let subject = FindingSubject::try_new(Vec::new(), Vec::new(), vec![obs.reference()])
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "finding subject creation error: {e}"
                    ))
                })?;

            let title = FindingTitle::try_new("Unusually long DNS query name").map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding title creation error: {e}"))
            })?;

            let summary = FindingSummary::try_new(
                "A DNS query contains one or more unusually long, high-octet-diversity names meeting configured structural thresholds",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "finding summary creation error: {e}"
                ))
            })?;

            let rationale_text = format!(
                "Observed DNS query observation contains {} matching question(s) (total {}) with maximum QNAME wire length {} octets (threshold >= {}), maximum label length {} octets (threshold >= {}), and maximum label octet diversity ratio {} (threshold >= {}). Long or high-diversity query names can arise from DNS tunneling or data exfiltration, but are also commonly used by CDNs, anti-spam RBL reputation lookups, DKIM/SPF TXT records, ACME challenges, security scanners, and telemetry endpoints.",
                matching_question_count,
                question_count,
                max_qname_wire_length,
                min_qname_wire_length,
                max_label_length,
                min_label_length,
                max_diversity_ratio,
                min_diversity_ratio,
            );
            let rationale = FindingRationale::try_new(&rationale_text).map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "finding rationale creation error: {e}"
                ))
            })?;

            let evi_desc = EvidenceDescription::try_new("DNS query-name structural measurements")
                .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "evidence description creation error: {e}"
                ))
            })?;

            let mut evi_builder =
                EvidenceDraftBuilder::new(EvidenceKind::ProtocolObservation, evi_desc);
            evi_builder
                .add_observation_reference(obs.reference())
                .map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "observation reference error: {e}"
                    ))
                })?;

            // 5 Ordered measurements:
            // 1. matching_question_count
            let k_match = EvidenceMetricKey::try_new("matching_question_count").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_new(
                        k_match,
                        EvidenceValue::Unsigned(matching_question_count),
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

            // 2. maximum_label_length
            let max_label_u128 = u128::try_from(max_label_length).map_err(|_| {
                DetectorExecutionError::internal_error("max_label_length exceeds u128")
            })?;
            let min_label_u128 = u128::try_from(min_label_length).map_err(|_| {
                DetectorExecutionError::internal_error("min_label_length exceeds u128")
            })?;
            let k_label = EvidenceMetricKey::try_new("maximum_label_length").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_label,
                        EvidenceValue::Unsigned(max_label_u128),
                        EvidenceValue::Unsigned(min_label_u128),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Bytes,
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

            // 3. maximum_label_octet_diversity_ratio
            let k_div =
                EvidenceMetricKey::try_new("maximum_label_octet_diversity_ratio").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_div,
                        EvidenceValue::Ratio(max_diversity_ratio),
                        EvidenceValue::Ratio(min_diversity_ratio),
                        EvidenceComparison::GreaterThanOrEqual,
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

            // 4. maximum_qname_wire_length
            let max_qname_u128 = u128::try_from(max_qname_wire_length).map_err(|_| {
                DetectorExecutionError::internal_error("max_qname_wire_length exceeds u128")
            })?;
            let min_qname_u128 = u128::try_from(min_qname_wire_length).map_err(|_| {
                DetectorExecutionError::internal_error("min_qname_wire_length exceeds u128")
            })?;
            let k_wire = EvidenceMetricKey::try_new("maximum_qname_wire_length").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_wire,
                        EvidenceValue::Unsigned(max_qname_u128),
                        EvidenceValue::Unsigned(min_qname_u128),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Bytes,
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

            // 5. question_count
            let k_cnt = EvidenceMetricKey::try_new("question_count").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_new(
                        k_cnt,
                        EvidenceValue::Unsigned(question_count),
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

            let evidence_draft = evi_builder.build().map_err(|e| {
                DetectorExecutionError::internal_error(format!("evidence draft build error: {e}"))
            })?;

            let finding_draft = FindingDraft::try_new(
                subject,
                title,
                summary,
                rationale,
                Severity::Info,
                Confidence::Medium,
                vec![evidence_draft],
                Vec::new(),
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding draft creation error: {e}"))
            })?;

            output.push(finding_draft)?;
        }

        Ok(())
    }
}

/// Bounded scalar aggregate tracking DNS queries for one flow.
#[derive(Debug, Clone)]
struct DnsFlowAggregate {
    dns_query_observation_count: u64,
    candidate_query_count: u64,
    maximum_qname_wire_length: usize,
    maximum_label_length: usize,
    maximum_label_octet_diversity_ratio: EvidenceRatio,
    first_candidate_observation: Option<ObservationReference>,
    last_candidate_observation: Option<ObservationReference>,
}

impl DnsFlowAggregate {
    fn new() -> Self {
        Self {
            dns_query_observation_count: 0,
            candidate_query_count: 0,
            maximum_qname_wire_length: 0,
            maximum_label_length: 0,
            maximum_label_octet_diversity_ratio: EvidenceRatio::ZERO,
            first_candidate_observation: None,
            last_candidate_observation: None,
        }
    }

    fn record_query(
        &mut self,
        obs_ref: ObservationReference,
        is_candidate: bool,
        shape_qname_wire_length: usize,
        shape_label_length: usize,
        shape_diversity_ratio: EvidenceRatio,
    ) -> Result<(), DetectorExecutionError> {
        self.dns_query_observation_count = self
            .dns_query_observation_count
            .checked_add(1)
            .ok_or_else(|| {
                DetectorExecutionError::internal_error("dns query observation count overflow")
            })?;
        if is_candidate {
            self.candidate_query_count =
                self.candidate_query_count.checked_add(1).ok_or_else(|| {
                    DetectorExecutionError::internal_error("candidate query count overflow")
                })?;
            if shape_qname_wire_length > self.maximum_qname_wire_length {
                self.maximum_qname_wire_length = shape_qname_wire_length;
            }
            if shape_label_length > self.maximum_label_length {
                self.maximum_label_length = shape_label_length;
            }
            if shape_diversity_ratio > self.maximum_label_octet_diversity_ratio {
                self.maximum_label_octet_diversity_ratio = shape_diversity_ratio;
            }

            if self.first_candidate_observation.is_none() {
                self.first_candidate_observation = Some(obs_ref);
            }
            self.last_candidate_observation = Some(obs_ref);
        }
        Ok(())
    }
}

/// Detector identifying reconstructed DNS flow instances containing repeated queries with long, high-octet-diversity domain names.
#[derive(Debug, Clone)]
pub struct DnsPossibleTunnelingDetector {
    metadata: DetectorMetadata,
}

impl DnsPossibleTunnelingDetector {
    /// Canonical detector identifier (`dns.possible_tunneling`).
    pub const DETECTOR_ID: &'static str = "dns.possible_tunneling";
    /// Detector version (`v1.1.0`).
    pub const DETECTOR_VERSION: DetectorVersion = DetectorVersion::new(1, 1, 0);

    /// Parameter key for minimum total query observations (`minimum_query_observations`).
    pub const PARAM_MINIMUM_QUERY_OBSERVATIONS: &'static str = "minimum_query_observations";
    /// Default minimum query observations per flow (8).
    pub const DEFAULT_MIN_QUERY_OBSERVATIONS: u64 = 8;

    /// Parameter key for minimum candidate query ratio (`minimum_candidate_query_ratio`).
    pub const PARAM_MINIMUM_CANDIDATE_QUERY_RATIO: &'static str = "minimum_candidate_query_ratio";
    /// Default minimum candidate query ratio (3/4).
    pub const DEFAULT_MIN_CANDIDATE_QUERY_RATIO: EvidenceRatio =
        match EvidenceRatio::from_fraction(3, 4) {
            Some(r) => r,
            None => EvidenceRatio::ZERO,
        };

    /// Parameter key for minimum QNAME wire length (`minimum_qname_wire_length`).
    pub const PARAM_MINIMUM_QNAME_WIRE_LENGTH: &'static str = "minimum_qname_wire_length";
    /// Default minimum QNAME wire length in octets (120).
    pub const DEFAULT_MIN_QNAME_WIRE_LENGTH: u64 = 120;

    /// Parameter key for minimum label length (`minimum_label_length`).
    pub const PARAM_MINIMUM_LABEL_LENGTH: &'static str = "minimum_label_length";
    /// Default minimum individual label length in octets (40).
    pub const DEFAULT_MIN_LABEL_LENGTH: u64 = 40;

    /// Parameter key for minimum label octet diversity ratio (`minimum_label_octet_diversity_ratio`).
    pub const PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO: &'static str =
        "minimum_label_octet_diversity_ratio";
    /// Default minimum label octet diversity ratio (1/3).
    pub const DEFAULT_MIN_LABEL_OCTET_DIVERSITY_RATIO: EvidenceRatio =
        match EvidenceRatio::from_fraction(1, 3) {
            Some(r) => r,
            None => EvidenceRatio::ZERO,
        };

    /// Parameter key for maximum tracked DNS flows (`maximum_tracked_dns_flows`).
    pub const PARAM_MAXIMUM_TRACKED_DNS_FLOWS: &'static str = "maximum_tracked_dns_flows";
    /// Default maximum tracked DNS flows (65,536).
    pub const DEFAULT_MAX_TRACKED_DNS_FLOWS: u64 = 65_536;

    /// Hard limit for maximum tracked DNS flows (1,000,000).
    pub const HARD_MAX_TRACKED_DNS_FLOWS: u64 = 1_000_000;

    /// Creates and initializes a new possible tunneling detector instance.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new().expect("canonical detector metadata is valid")
    }

    /// Fallibly creates and initializes a new possible tunneling detector instance.
    pub fn try_new() -> Result<Self, FindingValidationError> {
        let id = DetectorId::try_new(Self::DETECTOR_ID)?;
        let title = FindingTitle::try_new("Possible DNS tunneling pattern")?;
        let purpose = FindingSummary::try_new(
            "Identify reconstructed DNS flow instances containing repeated query observations whose names exhibit unusually long, high-octet-diversity characteristics",
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
}

impl Default for DnsPossibleTunnelingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DnsPossibleTunnelingDetector {
    fn metadata(&self) -> &DetectorMetadata {
        &self.metadata
    }

    fn validate_parameters(
        &self,
        parameters: &DetectorParameters,
    ) -> Result<(), DetectorConfigError> {
        for param in parameters.iter() {
            let key = param.key.as_str();
            match key {
                Self::PARAM_MINIMUM_QUERY_OBSERVATIONS => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val < 2 || u64::try_from(*val).is_err() {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum query observations must be between 2 and 18,446,744,073,709,551,615",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                Self::PARAM_MINIMUM_CANDIDATE_QUERY_RATIO => match &param.value {
                    DetectorParameterValue::Ratio(r) => {
                        if *r == EvidenceRatio::ZERO || *r > EvidenceRatio::ONE {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum candidate query ratio must be greater than 0 and at most 1",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "ratio",
                        });
                    }
                },
                Self::PARAM_MINIMUM_QNAME_WIRE_LENGTH => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val == 0
                            || *val > DnsLongQueryNameDetector::MAX_QNAME_WIRE_LENGTH_LIMIT as u128
                        {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum QNAME wire length must be between 1 and 255 octets",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                Self::PARAM_MINIMUM_LABEL_LENGTH => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val == 0
                            || *val > DnsLongQueryNameDetector::MAX_LABEL_LENGTH_LIMIT as u128
                        {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum label length must be between 1 and 63 octets",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                Self::PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO => match &param.value {
                    DetectorParameterValue::Ratio(r) => {
                        if *r > EvidenceRatio::ONE {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "minimum label octet diversity ratio must be between 0 and 1",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "ratio",
                        });
                    }
                },
                Self::PARAM_MAXIMUM_TRACKED_DNS_FLOWS => match &param.value {
                    DetectorParameterValue::Unsigned(val) => {
                        if *val == 0 || *val > Self::HARD_MAX_TRACKED_DNS_FLOWS as u128 {
                            return Err(DetectorConfigError::ParameterValueOutOfRange {
                                key: key.to_string(),
                                reason: "maximum tracked DNS flows must be between 1 and 1,000,000",
                            });
                        }
                    }
                    _ => {
                        return Err(DetectorConfigError::InvalidParameterType {
                            key: key.to_string(),
                            expected: "unsigned integer",
                        });
                    }
                },
                unknown => {
                    return Err(DetectorConfigError::UnknownParameter(unknown.to_string()));
                }
            }
        }
        Ok(())
    }

    fn evaluate(
        &self,
        input: &DetectionInput<'_>,
        parameters: &DetectorParameters,
        output: &mut DetectorDraftSink,
    ) -> Result<(), DetectorExecutionError> {
        let min_query_obs = match parameters.get(Self::PARAM_MINIMUM_QUERY_OBSERVATIONS) {
            Some(DetectorParameterValue::Unsigned(v)) => u64::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "minimum_query_observations exceeds host u64",
                )
            })?,
            _ => Self::DEFAULT_MIN_QUERY_OBSERVATIONS,
        };

        let min_candidate_ratio = match parameters.get(Self::PARAM_MINIMUM_CANDIDATE_QUERY_RATIO) {
            Some(DetectorParameterValue::Ratio(r)) => *r,
            _ => Self::DEFAULT_MIN_CANDIDATE_QUERY_RATIO,
        };

        let min_qname_wire_length = match parameters.get(Self::PARAM_MINIMUM_QNAME_WIRE_LENGTH) {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "minimum_qname_wire_length exceeds host usize",
                )
            })?,
            _ => usize::try_from(Self::DEFAULT_MIN_QNAME_WIRE_LENGTH).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "default minimum_qname_wire_length exceeds host usize",
                )
            })?,
        };

        let min_label_length = match parameters.get(Self::PARAM_MINIMUM_LABEL_LENGTH) {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error("minimum_label_length exceeds host usize")
            })?,
            _ => usize::try_from(Self::DEFAULT_MIN_LABEL_LENGTH).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "default minimum_label_length exceeds host usize",
                )
            })?,
        };

        let min_diversity_ratio =
            match parameters.get(Self::PARAM_MINIMUM_LABEL_OCTET_DIVERSITY_RATIO) {
                Some(DetectorParameterValue::Ratio(r)) => *r,
                _ => Self::DEFAULT_MIN_LABEL_OCTET_DIVERSITY_RATIO,
            };

        let max_tracked_flows = match parameters.get(Self::PARAM_MAXIMUM_TRACKED_DNS_FLOWS) {
            Some(DetectorParameterValue::Unsigned(v)) => usize::try_from(*v).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "maximum_tracked_dns_flows exceeds host usize",
                )
            })?,
            _ => usize::try_from(Self::DEFAULT_MAX_TRACKED_DNS_FLOWS).map_err(|_| {
                DetectorExecutionError::internal_error(
                    "default maximum_tracked_dns_flows exceeds host usize",
                )
            })?,
        };

        let mut flow_aggregates: BTreeMap<FlowReference, DnsFlowAggregate> = BTreeMap::new();

        // Single linear pass over observations
        for obs in input.observations() {
            if obs.reference().protocol() != ProtocolKind::Dns {
                continue;
            }
            let dns = match obs.data() {
                ProtocolObservationData::Dns(d) => d,
                _ => continue,
            };

            // Inspect only complete query messages (message_kind == Query AND flags.qr == false)
            if !obs.completeness().is_complete() {
                continue;
            }
            if dns.message_kind != DnsMessageKind::Query || dns.flags.qr {
                continue;
            }

            // Require valid directional flow association (A->B or B->A, not SameEndpoint or Unassociated/Excluded)
            let flow_ref = match obs.flow_association() {
                ObservationFlowAssociation::Associated { flow, direction } => {
                    if direction.is_same_endpoint() {
                        continue;
                    }
                    *flow
                }
                _ => continue,
            };

            // Check if flow exists in detection input and was not stopped by analysis limit (O(log F) binary search)
            let flow_record = match input
                .flows()
                .binary_search_by_key(&flow_ref, |f| f.reference)
                .ok()
                .map(|idx| &input.flows()[idx])
            {
                Some(f) => f,
                None => continue,
            };

            if flow_record.end_reason == FlowEndReason::AnalysisStopped {
                continue;
            }

            // Evaluate if this query observation is candidate (has >= 1 question satisfying query-shape rule)
            let mut is_candidate = false;
            let mut shape_qname_wire = 0usize;
            let mut shape_label_len = 0usize;
            let mut shape_diversity = EvidenceRatio::ZERO;

            for question in &dns.questions {
                let shape = DnsQuestionShape::evaluate(
                    question,
                    min_qname_wire_length,
                    min_label_length,
                    min_diversity_ratio,
                );
                if shape.matches {
                    is_candidate = true;
                    if shape.qname_wire_length > shape_qname_wire {
                        shape_qname_wire = shape.qname_wire_length;
                    }
                    if shape.maximum_label_length > shape_label_len {
                        shape_label_len = shape.maximum_label_length;
                    }
                    if shape.maximum_label_octet_diversity_ratio > shape_diversity {
                        shape_diversity = shape.maximum_label_octet_diversity_ratio;
                    }
                }
            }

            if let Some(aggregate) = flow_aggregates.get_mut(&flow_ref) {
                aggregate.record_query(
                    obs.reference(),
                    is_candidate,
                    shape_qname_wire,
                    shape_label_len,
                    shape_diversity,
                )?;
            } else {
                if flow_aggregates.len() >= max_tracked_flows {
                    return Err(DetectorExecutionError::resource_limit(format!(
                        "exceeded maximum tracked DNS flows capacity ({max_tracked_flows})"
                    )));
                }
                let mut aggregate = DnsFlowAggregate::new();
                aggregate.record_query(
                    obs.reference(),
                    is_candidate,
                    shape_qname_wire,
                    shape_label_len,
                    shape_diversity,
                )?;
                flow_aggregates.insert(flow_ref, aggregate);
            }
        }

        // Evaluate matching flows and emit findings
        for (flow_ref, aggregate) in flow_aggregates {
            if aggregate.dns_query_observation_count < min_query_obs {
                continue;
            }
            if aggregate.candidate_query_count == 0 {
                continue;
            }

            let candidate_ratio = match EvidenceRatio::from_fraction(
                u128::from(aggregate.candidate_query_count),
                u128::from(aggregate.dns_query_observation_count),
            ) {
                Some(r) => r,
                None => continue,
            };

            if candidate_ratio < min_candidate_ratio {
                continue;
            }

            let subject =
                FindingSubject::try_new(Vec::new(), vec![flow_ref], Vec::new()).map_err(|e| {
                    DetectorExecutionError::internal_error(format!(
                        "finding subject creation error: {e}"
                    ))
                })?;

            let title = FindingTitle::try_new("Possible DNS tunneling pattern").map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding title creation error: {e}"))
            })?;

            let summary_text = format!(
                "Repeated DNS query observations within this flow contain unusually long, high-octet-diversity names in a proportion ({}) meeting configured aggregate thresholds",
                candidate_ratio
            );
            let summary = FindingSummary::try_new(&summary_text).map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "finding summary creation error: {e}"
                ))
            })?;

            let rationale_text = format!(
                "Flow contains {} DNS query observation(s), of which {} ({}) exhibit long QNAME wire length (max {} octets), long labels (max {} octets), and high label octet diversity (max {}). The pattern is consistent with possible DNS data tunneling or encoded exfiltration channels, but can also arise from benign generated identifiers, telemetry, cache keys, service discovery, security products, or application-specific opaque labels.",
                aggregate.dns_query_observation_count,
                aggregate.candidate_query_count,
                candidate_ratio,
                aggregate.maximum_qname_wire_length,
                aggregate.maximum_label_length,
                aggregate.maximum_label_octet_diversity_ratio,
            );
            let rationale = FindingRationale::try_new(&rationale_text).map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "finding rationale creation error: {e}"
                ))
            })?;

            let evi_desc = EvidenceDescription::try_new(
                "Flow-level DNS query structural and candidate proportion measurements",
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!(
                    "evidence description creation error: {e}"
                ))
            })?;

            let mut evi_builder =
                EvidenceDraftBuilder::new(EvidenceKind::RatioComparison, evi_desc);
            evi_builder.add_flow_reference(flow_ref).map_err(|e| {
                DetectorExecutionError::internal_error(format!("flow reference error: {e}"))
            })?;

            if let Some(first_obs) = aggregate.first_candidate_observation {
                evi_builder
                    .add_observation_reference(first_obs)
                    .map_err(|e| {
                        DetectorExecutionError::internal_error(format!(
                            "observation reference error: {e}"
                        ))
                    })?;
                if let Some(last_obs) = aggregate.last_candidate_observation {
                    if last_obs != first_obs {
                        evi_builder
                            .add_observation_reference(last_obs)
                            .map_err(|e| {
                                DetectorExecutionError::internal_error(format!(
                                    "observation reference error: {e}"
                                ))
                            })?;
                    }
                }
            }

            // 6 Ordered measurements:
            // 1. candidate_query_count
            let k_cand = EvidenceMetricKey::try_new("candidate_query_count").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_new(
                        k_cand,
                        EvidenceValue::Unsigned(u128::from(aggregate.candidate_query_count)),
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

            // 2. candidate_query_ratio
            let k_ratio = EvidenceMetricKey::try_new("candidate_query_ratio").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_ratio,
                        EvidenceValue::Ratio(candidate_ratio),
                        EvidenceValue::Ratio(min_candidate_ratio),
                        EvidenceComparison::GreaterThanOrEqual,
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

            // 3. dns_query_observation_count
            let k_tot = EvidenceMetricKey::try_new("dns_query_observation_count").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_tot,
                        EvidenceValue::Unsigned(u128::from(aggregate.dns_query_observation_count)),
                        EvidenceValue::Unsigned(u128::from(min_query_obs)),
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

            // 4. maximum_label_length
            let max_label_u128 = u128::try_from(aggregate.maximum_label_length).map_err(|_| {
                DetectorExecutionError::internal_error("maximum_label_length exceeds u128")
            })?;
            let min_label_u128 = u128::try_from(min_label_length).map_err(|_| {
                DetectorExecutionError::internal_error("min_label_length exceeds u128")
            })?;
            let k_label = EvidenceMetricKey::try_new("maximum_label_length").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_label,
                        EvidenceValue::Unsigned(max_label_u128),
                        EvidenceValue::Unsigned(min_label_u128),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Bytes,
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

            // 5. maximum_label_octet_diversity_ratio
            let k_div =
                EvidenceMetricKey::try_new("maximum_label_octet_diversity_ratio").map_err(|e| {
                    DetectorExecutionError::internal_error(format!("metric key error: {e}"))
                })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_div,
                        EvidenceValue::Ratio(aggregate.maximum_label_octet_diversity_ratio),
                        EvidenceValue::Ratio(min_diversity_ratio),
                        EvidenceComparison::GreaterThanOrEqual,
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

            // 6. maximum_qname_wire_length
            let max_qname_u128 =
                u128::try_from(aggregate.maximum_qname_wire_length).map_err(|_| {
                    DetectorExecutionError::internal_error("maximum_qname_wire_length exceeds u128")
                })?;
            let min_qname_u128 = u128::try_from(min_qname_wire_length).map_err(|_| {
                DetectorExecutionError::internal_error("min_qname_wire_length exceeds u128")
            })?;
            let k_wire = EvidenceMetricKey::try_new("maximum_qname_wire_length").map_err(|e| {
                DetectorExecutionError::internal_error(format!("metric key error: {e}"))
            })?;
            evi_builder
                .add_measurement(
                    EvidenceMeasurement::try_with_threshold(
                        k_wire,
                        EvidenceValue::Unsigned(max_qname_u128),
                        EvidenceValue::Unsigned(min_qname_u128),
                        EvidenceComparison::GreaterThanOrEqual,
                        EvidenceUnit::Bytes,
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

            let evidence_draft = evi_builder.build().map_err(|e| {
                DetectorExecutionError::internal_error(format!("evidence draft build error: {e}"))
            })?;

            let mitre_id = MitreAttackId::try_new("T1071.004").map_err(|e| {
                DetectorExecutionError::internal_error(format!("invalid MITRE technique ID: {e}"))
            })?;
            let mitre_rationale = MitreMappingRationale::try_new(
                "The detector identified repeated DNS query observations with unusually long, high-octet-diversity names consistent with structured data transmission over DNS. This mapping describes an analytical relationship with network protocol characteristics defined in ATT&CK T1071.004, not confirmed malware or external attribution.",
            ).map_err(|e| DetectorExecutionError::internal_error(format!("invalid MITRE rationale: {e}")))?;
            let mitre_provenance = MitreMappingProvenance::DetectorDeclared {
                detector_id: self.metadata().id().clone(),
                detector_version: self.metadata().version(),
            };
            let mitre_mapping = MitreMapping::try_new(
                mitre_id,
                "Application Layer Protocol: DNS",
                MitreTactic::CommandAndControl,
                mitre_rationale,
                mitre_provenance,
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("invalid MITRE mapping: {e}"))
            })?;

            let finding_draft = FindingDraft::try_new(
                subject,
                title,
                summary,
                rationale,
                Severity::Low,
                Confidence::Medium,
                vec![evidence_draft],
                vec![mitre_mapping],
            )
            .map_err(|e| {
                DetectorExecutionError::internal_error(format!("finding draft creation error: {e}"))
            })?;

            output.push(finding_draft)?;
        }

        Ok(())
    }
}

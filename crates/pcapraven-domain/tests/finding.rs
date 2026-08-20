//! Integration tests for domain finding records, subjects, references, and validation rules.

use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceDescription, EvidenceDraftBuilder,
    EvidenceKind, EvidenceReference, FindingDraft, FindingRationale, FindingRecord,
    FindingReference, FindingSubject, FindingSummary, FindingTitle, FindingValidationError,
    FlowReference, MitreAttackCatalogVersion, MitreAttackDomain, MitreAttackId,
    MitreAttackObjectVersion, MitreAttackRelationship, MitreMapping, MitreMappingDeclaration,
    MitreMappingProvenance, MitreMappingRationale, MitreTactic, ObservationReference,
    PacketReference, ProtocolKind, Severity,
};

fn sample_packet(ordinal: u64) -> PacketReference {
    PacketReference::new(ordinal, None, None, 64, 64, false)
}

#[test]
fn test_finding_subject_valid_and_ordered() {
    let pkts = vec![sample_packet(1), sample_packet(2)];
    let flows = vec![FlowReference::new(1), FlowReference::new(2)];
    let obs = vec![
        ObservationReference::new(1, ProtocolKind::Dns, 0),
        ObservationReference::new(2, ProtocolKind::Http, 0),
    ];

    let subject = FindingSubject::try_new(pkts.clone(), flows.clone(), obs.clone()).unwrap();
    assert_eq!(subject.packet_references(), &pkts[..]);
    assert_eq!(subject.flow_references(), &flows[..]);
    assert_eq!(subject.observation_references(), &obs[..]);
}

#[test]
fn test_finding_subject_duplicate_or_unordered_rejected() {
    // Duplicate packet
    let pkts_dup = vec![sample_packet(1), sample_packet(1)];
    let err =
        FindingSubject::try_new(pkts_dup, vec![FlowReference::new(1)], Vec::new()).unwrap_err();
    assert!(matches!(
        err,
        FindingValidationError::DuplicateSubjectPacketReference(_)
    ));

    // Out of order flow
    let flows_rev = vec![FlowReference::new(2), FlowReference::new(1)];
    let err = FindingSubject::try_new(Vec::new(), flows_rev, Vec::new()).unwrap_err();
    assert!(matches!(
        err,
        FindingValidationError::OutOfOrderSubjectFlowReference { .. }
    ));

    // Empty subject
    let err = FindingSubject::try_new(Vec::new(), Vec::new(), Vec::new()).unwrap_err();
    assert_eq!(err, FindingValidationError::EmptyFindingSubject);
}

#[test]
fn test_finding_record_valid_primary() {
    let subject = FindingSubject::try_new(
        vec![sample_packet(1)],
        vec![FlowReference::new(1)],
        Vec::new(),
    )
    .unwrap();
    let id = DetectorId::try_new("behavior.test_detector").unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let title = FindingTitle::try_new("Test Finding").unwrap();
    let summary = FindingSummary::try_new("Test finding summary").unwrap();
    let rationale =
        FindingRationale::try_new("Test finding rationale explaining the facts.").unwrap();
    let evidence_refs = vec![EvidenceReference::new(1)];

    let record = FindingRecord::try_new(
        FindingReference::new(1),
        id,
        version,
        subject,
        title,
        summary,
        rationale,
        Severity::Low,
        Confidence::Medium,
        evidence_refs.clone(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();

    assert_eq!(record.reference().id(), 1);
    assert_eq!(record.evidence_references(), &evidence_refs[..]);
    assert!(record.source_finding_references().is_empty());
    assert_eq!(record.severity(), Severity::Low);
    assert_eq!(record.confidence(), Confidence::Medium);
}

#[test]
fn test_finding_record_source_finding_references_validation() {
    let subject = FindingSubject::try_new(
        vec![sample_packet(1)],
        vec![FlowReference::new(1)],
        Vec::new(),
    )
    .unwrap();
    let id = DetectorId::try_new("behavior.test_correlator").unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let title = FindingTitle::try_new("Correlated Test Finding").unwrap();
    let summary = FindingSummary::try_new("Correlated finding summary").unwrap();
    let rationale =
        FindingRationale::try_new("Correlated rationale explaining multiple signals.").unwrap();
    let evidence_refs = vec![EvidenceReference::new(1)];

    // Valid correlated references (sorted, unique, >= 2)
    let valid_sources = vec![FindingReference::new(1), FindingReference::new(2)];
    let record = FindingRecord::try_new(
        FindingReference::new(3),
        id.clone(),
        version,
        subject.clone(),
        title.clone(),
        summary.clone(),
        rationale.clone(),
        Severity::Medium,
        Confidence::Medium,
        evidence_refs.clone(),
        valid_sources.clone(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(record.source_finding_references(), &valid_sources[..]);

    // Duplicate source finding reference
    let dup_sources = vec![FindingReference::new(1), FindingReference::new(1)];
    let err = FindingRecord::try_new(
        FindingReference::new(3),
        id.clone(),
        version,
        subject.clone(),
        title.clone(),
        summary.clone(),
        rationale.clone(),
        Severity::Medium,
        Confidence::Medium,
        evidence_refs.clone(),
        dup_sources,
        Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        FindingValidationError::DuplicateSourceFindingReference(_)
    ));

    // Out of order source finding reference
    let ooo_sources = vec![FindingReference::new(2), FindingReference::new(1)];
    let err = FindingRecord::try_new(
        FindingReference::new(3),
        id.clone(),
        version,
        subject.clone(),
        title.clone(),
        summary.clone(),
        rationale.clone(),
        Severity::Medium,
        Confidence::Medium,
        evidence_refs.clone(),
        ooo_sources,
        Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        FindingValidationError::OutOfOrderSourceFindingReference { .. }
    ));

    // Capacity exceeded (> 256)
    let mut excess_sources = Vec::new();
    for i in 1..=257 {
        excess_sources.push(FindingReference::new(i));
    }
    let err = FindingRecord::try_new(
        FindingReference::new(300),
        id,
        version,
        subject,
        title,
        summary,
        rationale,
        Severity::Medium,
        Confidence::Medium,
        evidence_refs,
        excess_sources,
        Vec::new(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        FindingValidationError::SourceFindingReferencesExceeded {
            count: 257,
            max: 256
        }
    ));
}

#[test]
fn test_finding_draft_creation() {
    let subject = FindingSubject::try_new(
        vec![sample_packet(1)],
        vec![FlowReference::new(1)],
        Vec::new(),
    )
    .unwrap();
    let title = FindingTitle::try_new("Draft Finding").unwrap();
    let summary = FindingSummary::try_new("Draft summary").unwrap();
    let rationale = FindingRationale::try_new("Draft rationale.").unwrap();

    let desc = EvidenceDescription::try_new("Test evidence").unwrap();
    let mut builder = EvidenceDraftBuilder::new(EvidenceKind::FlowMeasurement, desc);
    builder.add_flow_reference(FlowReference::new(1)).unwrap();
    let evi_draft = builder.build().unwrap();

    let draft = FindingDraft::try_new(
        subject,
        title,
        summary,
        rationale,
        Severity::Low,
        Confidence::Low,
        vec![evi_draft],
    )
    .unwrap();

    assert_eq!(draft.evidence().len(), 1);
    assert_eq!(draft.severity(), Severity::Low);
    assert_eq!(draft.confidence(), Confidence::Low);
}

#[test]
fn test_severity_and_confidence_from_str_and_ordering() {
    use std::str::FromStr;

    // Severity FromStr
    assert_eq!(Severity::from_str("info").unwrap(), Severity::Info);
    assert_eq!(Severity::from_str("informational").unwrap(), Severity::Info);
    assert_eq!(Severity::from_str("low").unwrap(), Severity::Low);
    assert_eq!(Severity::from_str("medium").unwrap(), Severity::Medium);
    assert_eq!(Severity::from_str("high").unwrap(), Severity::High);
    assert_eq!(Severity::from_str("critical").unwrap(), Severity::Critical);
    assert_eq!(Severity::from_str("  HIGH  ").unwrap(), Severity::High);
    assert!(Severity::from_str("unknown").is_err());

    // Severity Ordering
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);

    // Confidence FromStr
    assert_eq!(Confidence::from_str("low").unwrap(), Confidence::Low);
    assert_eq!(Confidence::from_str("medium").unwrap(), Confidence::Medium);
    assert_eq!(Confidence::from_str("high").unwrap(), Confidence::High);
    assert_eq!(
        Confidence::from_str("  MEDIUM  ").unwrap(),
        Confidence::Medium
    );
    assert!(Confidence::from_str("critical").is_err());

    // Confidence Ordering
    assert!(Confidence::Low < Confidence::Medium);
    assert!(Confidence::Medium < Confidence::High);
}

#[test]
fn test_mitre_attack_id_and_mapping_validation() {
    use std::str::FromStr;

    // Valid MITRE IDs
    let t1 = MitreAttackId::try_new("T1071").unwrap();
    assert_eq!(t1.as_str(), "T1071");
    assert!(!t1.is_sub_technique());

    let t2 = MitreAttackId::from_str("T1071.004").unwrap();
    assert_eq!(t2.as_str(), "T1071.004");
    assert!(t2.is_sub_technique());

    // Invalid MITRE IDs (no trim, strict formats)
    assert!(MitreAttackId::try_new("").is_err());
    assert!(MitreAttackId::try_new("1071").is_err());
    assert!(MitreAttackId::try_new("T107").is_err());
    assert!(MitreAttackId::try_new("T1071.04").is_err());
    assert!(MitreAttackId::try_new("T1071.0004").is_err());
    assert!(MitreAttackId::try_new("X1071.004").is_err());
    assert!(MitreAttackId::try_new(" T1071.004").is_err());
    assert!(MitreAttackId::try_new("T1071.004 ").is_err());
    assert!(MitreAttackId::try_new("\tT1071.004").is_err());
    assert!(MitreAttackId::try_new("t1071.004").is_err());
    assert!(MitreAttackId::try_new("T1071.4").is_err());
    assert!(MitreAttackId::try_new("T10710").is_err());

    // Valid MITRE Declaration
    let rationale = MitreMappingRationale::try_new("DNS tunneling mapping rationale.").unwrap();
    let decl = MitreMappingDeclaration::try_new(
        MitreAttackDomain::Enterprise,
        MitreAttackCatalogVersion::new(19, 2),
        t2.clone(),
        "Application Layer Protocol: DNS",
        MitreAttackObjectVersion::new(1, 4),
        MitreTactic::CommandAndControl,
        MitreAttackRelationship::Analytical,
        rationale,
    )
    .unwrap();

    assert_eq!(decl.domain(), MitreAttackDomain::Enterprise);
    assert_eq!(decl.catalog_version().to_string(), "19.2");
    assert_eq!(decl.technique_id().as_str(), "T1071.004");
    assert_eq!(decl.technique_name(), "Application Layer Protocol: DNS");
    assert_eq!(decl.technique_version().to_string(), "1.4");
    assert_eq!(decl.tactic(), MitreTactic::CommandAndControl);
    assert_eq!(decl.tactic().tactic_id(), "TA0011");
    assert_eq!(decl.relationship(), MitreAttackRelationship::Analytical);

    // Stamped Mapping with Provenance
    let prov = MitreMappingProvenance::DetectorDeclared {
        detector_id: DetectorId::try_new("dns.possible_tunneling").unwrap(),
        detector_version: DetectorVersion::new(1, 1, 1),
    };
    let mapping = MitreMapping::from_declaration(&decl, prov);

    assert_eq!(mapping.technique_id().as_str(), "T1071.004");
    assert_eq!(mapping.tactic(), MitreTactic::CommandAndControl);
    assert_eq!(mapping.tactic().tactic_id(), "TA0011");
    assert_eq!(mapping.catalog_version().to_string(), "19.2");
    assert_eq!(mapping.technique_version().to_string(), "1.4");
    assert_eq!(mapping.domain(), MitreAttackDomain::Enterprise);
    assert_eq!(mapping.relationship(), MitreAttackRelationship::Analytical);
}

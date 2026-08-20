//! Tests for finding filtering model and evaluation.

use pcapraven_detection::FindingFilter;
use pcapraven_domain::{
    Confidence, DetectorId, DetectorVersion, EvidenceReference, FindingRationale, FindingRecord,
    FindingReference, FindingSubject, FindingSummary, FindingTitle, FlowReference, MitreAttackId,
    MitreMapping, MitreMappingProvenance, MitreMappingRationale, MitreTactic, Severity,
};

fn make_test_finding(
    id: u64,
    detector: &str,
    severity: Severity,
    confidence: Confidence,
    mitre_ids: &[&str],
) -> FindingRecord {
    let finding_ref = FindingReference::new(id);
    let detector_id = DetectorId::try_new(detector).unwrap();
    let version = DetectorVersion::new(1, 0, 0);
    let subject =
        FindingSubject::try_new(Vec::new(), vec![FlowReference::new(id)], Vec::new()).unwrap();
    let title = FindingTitle::try_new(format!("Finding {id}")).unwrap();
    let summary = FindingSummary::try_new(format!("Summary {id}")).unwrap();
    let rationale = FindingRationale::try_new(format!("Rationale {id}")).unwrap();
    let evidence_refs = vec![EvidenceReference::new(id)];

    let mut mitre_mappings = Vec::new();
    for &m_id in mitre_ids {
        let mitre_id = MitreAttackId::try_new(m_id).unwrap();
        let rationale = MitreMappingRationale::try_new("Test mapping rationale").unwrap();
        let prov = MitreMappingProvenance::DetectorDeclared {
            detector_id: detector_id.clone(),
            detector_version: version,
        };
        mitre_mappings.push(
            MitreMapping::try_new(
                pcapraven_domain::MitreAttackDomain::Enterprise,
                pcapraven_domain::MitreAttackCatalogVersion::new(19, 2),
                mitre_id,
                "Test Technique",
                pcapraven_domain::MitreAttackObjectVersion::new(1, 4),
                MitreTactic::CommandAndControl,
                pcapraven_domain::MitreAttackRelationship::Analytical,
                rationale,
                prov,
            )
            .unwrap(),
        );
    }

    FindingRecord::try_new(
        finding_ref,
        detector_id,
        version,
        subject,
        title,
        summary,
        rationale,
        severity,
        confidence,
        evidence_refs,
        Vec::new(),
        mitre_mappings,
    )
    .unwrap()
}

#[test]
fn test_finding_filter_empty_matches_all() {
    let f1 = make_test_finding(
        1,
        "dns.long_query_name",
        Severity::Info,
        Confidence::Medium,
        &[],
    );
    let f2 = make_test_finding(
        2,
        "behavior.periodic_beaconing",
        Severity::Low,
        Confidence::Medium,
        &[],
    );
    let f3 = make_test_finding(
        3,
        "dns.possible_tunneling",
        Severity::Low,
        Confidence::Medium,
        &["T1071.004"],
    );
    let findings = vec![f1, f2, f3];

    let filter = FindingFilter::new();
    let filtered = filter.filter_findings(&findings);
    assert_eq!(filtered.len(), 3);
    assert_eq!(filtered[0].reference().id(), 1);
    assert_eq!(filtered[1].reference().id(), 2);
    assert_eq!(filtered[2].reference().id(), 3);
}

#[test]
fn test_finding_filter_min_severity() {
    let f1 = make_test_finding(
        1,
        "dns.long_query_name",
        Severity::Info,
        Confidence::Low,
        &[],
    );
    let f2 = make_test_finding(
        2,
        "behavior.periodic_beaconing",
        Severity::Low,
        Confidence::Medium,
        &[],
    );
    let f3 = make_test_finding(
        3,
        "behavior.possible_c2_multi_signal",
        Severity::Medium,
        Confidence::Medium,
        &["T1071.004"],
    );
    let findings = vec![f1, f2, f3];

    let filter_info = FindingFilter::new().with_min_severity(Some(Severity::Info));
    assert_eq!(filter_info.filter_findings(&findings).len(), 3);

    let filter_low = FindingFilter::new().with_min_severity(Some(Severity::Low));
    let res_low = filter_low.filter_findings(&findings);
    assert_eq!(res_low.len(), 2);
    assert_eq!(res_low[0].reference().id(), 2);
    assert_eq!(res_low[1].reference().id(), 3);

    let filter_med = FindingFilter::new().with_min_severity(Some(Severity::Medium));
    let res_med = filter_med.filter_findings(&findings);
    assert_eq!(res_med.len(), 1);
    assert_eq!(res_med[0].reference().id(), 3);

    let filter_high = FindingFilter::new().with_min_severity(Some(Severity::High));
    assert!(filter_high.filter_findings(&findings).is_empty());
}

#[test]
fn test_finding_filter_min_confidence() {
    let f1 = make_test_finding(
        1,
        "dns.long_query_name",
        Severity::Info,
        Confidence::Low,
        &[],
    );
    let f2 = make_test_finding(
        2,
        "behavior.periodic_beaconing",
        Severity::Low,
        Confidence::Medium,
        &[],
    );
    let f3 = make_test_finding(3, "custom.high_conf", Severity::High, Confidence::High, &[]);
    let findings = vec![f1, f2, f3];

    let filter_low = FindingFilter::new().with_min_confidence(Some(Confidence::Low));
    assert_eq!(filter_low.filter_findings(&findings).len(), 3);

    let filter_med = FindingFilter::new().with_min_confidence(Some(Confidence::Medium));
    let res_med = filter_med.filter_findings(&findings);
    assert_eq!(res_med.len(), 2);
    assert_eq!(res_med[0].reference().id(), 2);
    assert_eq!(res_med[1].reference().id(), 3);

    let filter_high = FindingFilter::new().with_min_confidence(Some(Confidence::High));
    let res_high = filter_high.filter_findings(&findings);
    assert_eq!(res_high.len(), 1);
    assert_eq!(res_high[0].reference().id(), 3);
}

#[test]
fn test_finding_filter_detector_id() {
    let f1 = make_test_finding(
        1,
        "dns.long_query_name",
        Severity::Info,
        Confidence::Medium,
        &[],
    );
    let f2 = make_test_finding(
        2,
        "behavior.periodic_beaconing",
        Severity::Low,
        Confidence::Medium,
        &[],
    );
    let findings = vec![f1, f2];

    let det_id = DetectorId::try_new("behavior.periodic_beaconing").unwrap();
    let filter = FindingFilter::new().with_detector_id(Some(det_id));
    let res = filter.filter_findings(&findings);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].reference().id(), 2);
}

#[test]
fn test_finding_filter_mitre_technique() {
    let f1 = make_test_finding(
        1,
        "dns.long_query_name",
        Severity::Info,
        Confidence::Medium,
        &[],
    );
    let f2 = make_test_finding(
        2,
        "dns.possible_tunneling",
        Severity::Low,
        Confidence::Medium,
        &["T1071.004"],
    );
    let findings = vec![f1, f2];

    let mitre_id = MitreAttackId::try_new("T1071.004").unwrap();
    let filter = FindingFilter::new().with_mitre_attack_id(Some(mitre_id));
    let res = filter.filter_findings(&findings);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].reference().id(), 2);

    let unmatched_mitre = MitreAttackId::try_new("T1071").unwrap();
    let filter_unmatched = FindingFilter::new().with_mitre_attack_id(Some(unmatched_mitre));
    assert!(filter_unmatched.filter_findings(&findings).is_empty());
}

#[test]
fn test_finding_filter_inclusive_and_criteria() {
    let f1 = make_test_finding(
        1,
        "dns.possible_tunneling",
        Severity::Low,
        Confidence::Low,
        &["T1071.004"],
    );
    let f2 = make_test_finding(
        2,
        "dns.possible_tunneling",
        Severity::Low,
        Confidence::Medium,
        &["T1071.004"],
    );
    let f3 = make_test_finding(
        3,
        "behavior.possible_c2_multi_signal",
        Severity::Medium,
        Confidence::Medium,
        &["T1071.004"],
    );
    let findings = vec![f1, f2, f3];

    let filter = FindingFilter::new()
        .with_min_severity(Some(Severity::Low))
        .with_min_confidence(Some(Confidence::Medium))
        .with_detector_id(Some(DetectorId::try_new("dns.possible_tunneling").unwrap()))
        .with_mitre_attack_id(Some(MitreAttackId::try_new("T1071.004").unwrap()));

    let res = filter.filter_findings(&findings);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].reference().id(), 2);
}

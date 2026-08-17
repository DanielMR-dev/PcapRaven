//! Integration tests for Phase 10 unified protocol observations and structured evidence.

use pcapraven_domain::*;

#[test]
fn test_protocol_kind_properties() {
    assert_eq!(ProtocolKind::Dns.as_str(), "DNS");
    assert_eq!(ProtocolKind::Http.as_str(), "HTTP");
    assert_eq!(ProtocolKind::Tls.as_str(), "TLS");

    assert_eq!(ProtocolKind::Dns.to_string(), "DNS");
    assert_eq!(ProtocolKind::Http.to_string(), "HTTP");
    assert_eq!(ProtocolKind::Tls.to_string(), "TLS");

    assert_eq!(ProtocolKind::Dns, ProtocolKind::Dns);
    assert_ne!(ProtocolKind::Dns, ProtocolKind::Http);
    assert!(ProtocolKind::Dns < ProtocolKind::Http);
}

#[test]
fn test_observation_reference() {
    let r1 = ObservationReference::new(0);
    let r2 = ObservationReference::new(42);

    assert_eq!(r1.id(), 0);
    assert_eq!(r2.id(), 42);
    assert_eq!(r1.to_string(), "obs:0");
    assert_eq!(r2.to_string(), "obs:42");

    assert!(r1 < r2);
}

#[test]
fn test_observation_completeness() {
    let c = ObservationCompleteness::Complete;
    let p = ObservationCompleteness::Partial;

    assert!(c.is_complete());
    assert!(!c.is_partial());
    assert_eq!(c.as_str(), "Complete");
    assert_eq!(c.to_string(), "Complete");

    assert!(!p.is_complete());
    assert!(p.is_partial());
    assert_eq!(p.as_str(), "Partial");
    assert_eq!(p.to_string(), "Partial");
}

#[test]
fn test_observation_flow_association() {
    let f_ref = FlowReference::new(10);
    let assoc = ObservationFlowAssociation::Associated(f_ref);
    assert!(assoc.is_associated());
    assert!(!assoc.is_excluded());
    assert!(!assoc.is_unassociated());
    assert_eq!(assoc.flow_reference(), Some(f_ref));
    assert_eq!(assoc.exclusion_reason(), None);
    assert_eq!(assoc.to_string(), "Associated(Flow(10))");

    let excl = ObservationFlowAssociation::Excluded(FlowExclusionReason::MissingNetworkLayer);
    assert!(!excl.is_associated());
    assert!(excl.is_excluded());
    assert!(!excl.is_unassociated());
    assert_eq!(excl.flow_reference(), None);
    assert_eq!(
        excl.exclusion_reason(),
        Some(FlowExclusionReason::MissingNetworkLayer)
    );
    assert_eq!(excl.to_string(), "Excluded(MissingNetworkLayer)");

    let unassoc = ObservationFlowAssociation::Unassociated;
    assert!(!unassoc.is_associated());
    assert!(!unassoc.is_excluded());
    assert!(unassoc.is_unassociated());
    assert_eq!(unassoc.flow_reference(), None);
    assert_eq!(unassoc.exclusion_reason(), None);
    assert_eq!(unassoc.to_string(), "Unassociated");
}

#[test]
fn test_protocol_observation_data_and_completeness_derivation() {
    let pkt = PacketReference::new(1, None, None, 100, 100, false);

    // 1. DNS complete & partial
    let dns_complete = DnsObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        transport: DnsTransport::Udp,
        source_ip: IpAddress::Ipv4([192, 168, 1, 1]),
        destination_ip: IpAddress::Ipv4([192, 168, 1, 2]),
        source_port: 53535,
        destination_port: 53,
        message_kind: DnsMessageKind::Query,
        transaction_id: 0x1234,
        flags: DnsFlags::from_u16(0x0100),
        opcode: 0,
        response_code: 0,
        effective_response_code: 0,
        declared_qdcount: 1,
        declared_ancount: 0,
        declared_nscount: 0,
        declared_arcount: 0,
        questions: Vec::new(),
        records: Vec::new(),
        edns: None,
        completeness: DnsObservationCompleteness::Complete,
    };
    let data_dns_comp = ProtocolObservationData::Dns(dns_complete);
    assert_eq!(data_dns_comp.protocol_kind(), ProtocolKind::Dns);
    assert!(data_dns_comp.is_dns());
    assert!(!data_dns_comp.is_http());
    assert!(!data_dns_comp.is_tls());
    assert!(data_dns_comp.as_dns().is_some());
    assert!(data_dns_comp.as_http().is_none());
    assert!(data_dns_comp.as_tls().is_none());
    assert_eq!(
        data_dns_comp.completeness(),
        ObservationCompleteness::Complete
    );

    let mut dns_partial = data_dns_comp.as_dns().unwrap().clone();
    dns_partial.completeness = DnsObservationCompleteness::Partial {
        reason: "Truncated",
    };
    let data_dns_part = ProtocolObservationData::Dns(dns_partial);
    assert_eq!(
        data_dns_part.completeness(),
        ObservationCompleteness::Partial
    );

    // 2. HTTP complete & partial
    let http_complete = HttpObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 1]),
        destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
        source_port: 54321,
        destination_port: 80,
        version: HttpVersion::Http11,
        message_kind: HttpMessageKind::Request,
        request: Some(HttpRequestMetadata {
            method: HttpByteString::new(b"GET".to_vec()),
            target: HttpByteString::new(b"/".to_vec()),
        }),
        response: None,
        headers: HttpSelectedHeaders::default(),
        framing: HttpFramingMetadata::default(),
        declared_field_count: 1,
        header_section_bytes: 40,
        completeness: HttpObservationCompleteness::Complete,
    };
    let data_http_comp = ProtocolObservationData::Http(http_complete);
    assert_eq!(data_http_comp.protocol_kind(), ProtocolKind::Http);
    assert!(data_http_comp.is_http());
    assert!(data_http_comp.as_http().is_some());
    assert_eq!(
        data_http_comp.completeness(),
        ObservationCompleteness::Complete
    );

    let mut http_partial = data_http_comp.as_http().unwrap().clone();
    http_partial.completeness = HttpObservationCompleteness::Partial {
        reason: "HeaderLimit",
    };
    let data_http_part = ProtocolObservationData::Http(http_partial);
    assert_eq!(
        data_http_part.completeness(),
        ObservationCompleteness::Partial
    );

    // 3. TLS complete & partial
    let tls_complete = TlsObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 1]),
        destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
        source_port: 54321,
        destination_port: 443,
        record_version: TlsVersion::Tls12,
        handshake_kind: TlsHandshakeKind::ClientHello,
        client_hello: Some(TlsClientHelloMetadata {
            legacy_version: TlsVersion::Tls12,
            session_id_length: 0,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            server_name: None,
            supported_versions: vec![TlsVersion::Tls13],
            supported_groups: vec![],
            signature_algorithms: vec![],
            alpn_protocols: vec![],
            key_share_groups: vec![],
            has_pre_shared_key: false,
            has_early_data: false,
            extensions: vec![],
        }),
        server_hello: None,
        declared_record_bytes: 512,
        declared_handshake_bytes: 508,
        completeness: TlsObservationCompleteness::Complete,
    };
    let data_tls_comp = ProtocolObservationData::Tls(tls_complete);
    assert_eq!(data_tls_comp.protocol_kind(), ProtocolKind::Tls);
    assert!(data_tls_comp.is_tls());
    assert!(data_tls_comp.as_tls().is_some());
    assert_eq!(
        data_tls_comp.completeness(),
        ObservationCompleteness::Complete
    );

    let mut tls_partial = data_tls_comp.as_tls().unwrap().clone();
    tls_partial.completeness = TlsObservationCompleteness::Partial;
    let data_tls_part = ProtocolObservationData::Tls(tls_partial);
    assert_eq!(
        data_tls_part.completeness(),
        ObservationCompleteness::Partial
    );
}

#[test]
fn test_protocol_observation_construction_and_accessors() {
    let pkt = PacketReference::new(1, None, None, 100, 100, false);
    let obs_ref = ObservationReference::new(5);
    let flow_assoc = ObservationFlowAssociation::Associated(FlowReference::new(2));

    let http_obs = HttpObservation {
        packet: pkt,
        timestamp: PacketTimestamp::Unavailable,
        source_ip: IpAddress::Ipv4([192, 168, 1, 1]),
        destination_ip: IpAddress::Ipv4([93, 184, 216, 34]),
        source_port: 54321,
        destination_port: 80,
        version: HttpVersion::Http11,
        message_kind: HttpMessageKind::Request,
        request: Some(HttpRequestMetadata {
            method: HttpByteString::new(b"GET".to_vec()),
            target: HttpByteString::new(b"/".to_vec()),
        }),
        response: None,
        headers: HttpSelectedHeaders::default(),
        framing: HttpFramingMetadata::default(),
        declared_field_count: 1,
        header_section_bytes: 40,
        completeness: HttpObservationCompleteness::Complete,
    };

    let obs = ProtocolObservation::new(
        obs_ref,
        pkt,
        flow_assoc,
        ProtocolObservationData::Http(http_obs.clone()),
    );

    assert_eq!(obs.reference(), obs_ref);
    assert_eq!(obs.packet_reference(), &pkt);
    assert_eq!(obs.flow_association(), &flow_assoc);
    assert_eq!(obs.completeness(), ObservationCompleteness::Complete);
    assert_eq!(obs.protocol_kind(), ProtocolKind::Http);
    assert!(obs.data().is_http());

    let obs_explicit_partial = ProtocolObservation::with_completeness(
        obs_ref,
        pkt,
        flow_assoc,
        ObservationCompleteness::Partial,
        ProtocolObservationData::Http(http_obs),
    );
    assert_eq!(
        obs_explicit_partial.completeness(),
        ObservationCompleteness::Partial
    );
}

#[test]
fn test_protocol_observation_collection() {
    assert!(ProtocolObservationCollection::new(0).is_err());

    let mut coll = ProtocolObservationCollection::new(2).unwrap();
    assert_eq!(coll.capacity(), 2);
    assert_eq!(coll.len(), 0);
    assert!(coll.is_empty());
    assert!(!coll.is_truncated());

    let pkt = PacketReference::new(1, None, None, 100, 100, false);
    let obs1 = ProtocolObservation::new(
        ObservationReference::new(1),
        pkt,
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt,
            timestamp: PacketTimestamp::Unavailable,
            source_ip: IpAddress::Ipv4([10, 0, 0, 1]),
            destination_ip: IpAddress::Ipv4([10, 0, 0, 2]),
            source_port: 1000,
            destination_port: 80,
            version: HttpVersion::Http11,
            message_kind: HttpMessageKind::Request,
            request: None,
            response: None,
            headers: HttpSelectedHeaders::default(),
            framing: HttpFramingMetadata::default(),
            declared_field_count: 0,
            header_section_bytes: 0,
            completeness: HttpObservationCompleteness::Complete,
        }),
    );
    let obs2 = ProtocolObservation::new(
        ObservationReference::new(2),
        pkt,
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt,
            timestamp: PacketTimestamp::Unavailable,
            source_ip: IpAddress::Ipv4([10, 0, 0, 1]),
            destination_ip: IpAddress::Ipv4([10, 0, 0, 2]),
            source_port: 1001,
            destination_port: 80,
            version: HttpVersion::Http11,
            message_kind: HttpMessageKind::Request,
            request: None,
            response: None,
            headers: HttpSelectedHeaders::default(),
            framing: HttpFramingMetadata::default(),
            declared_field_count: 0,
            header_section_bytes: 0,
            completeness: HttpObservationCompleteness::Complete,
        }),
    );
    let obs3 = ProtocolObservation::new(
        ObservationReference::new(3),
        pkt,
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt,
            timestamp: PacketTimestamp::Unavailable,
            source_ip: IpAddress::Ipv4([10, 0, 0, 1]),
            destination_ip: IpAddress::Ipv4([10, 0, 0, 2]),
            source_port: 1002,
            destination_port: 80,
            version: HttpVersion::Http11,
            message_kind: HttpMessageKind::Request,
            request: None,
            response: None,
            headers: HttpSelectedHeaders::default(),
            framing: HttpFramingMetadata::default(),
            declared_field_count: 0,
            header_section_bytes: 0,
            completeness: HttpObservationCompleteness::Complete,
        }),
    );

    assert!(coll.push(obs1));
    assert_eq!(coll.len(), 1);
    assert!(!coll.is_empty());
    assert!(!coll.is_truncated());

    assert!(coll.push(obs2));
    assert_eq!(coll.len(), 2);
    assert!(!coll.is_truncated());

    // 3rd push must fail and mark is_truncated
    assert!(!coll.push(obs3));
    assert_eq!(coll.len(), 2);
    assert!(coll.is_truncated());

    let count = coll.iter().count();
    assert_eq!(count, 2);

    let vec = coll.into_vec();
    assert_eq!(vec.len(), 2);
}

#[test]
fn test_schema_version_anchors() {
    let cur = SchemaVersion::CURRENT;
    assert_eq!(cur.major(), 1);
    assert_eq!(cur.minor(), 0);
    assert_eq!(cur.to_string(), "v1.0");

    let v1_0 = SchemaVersion::new(1, 0);
    let v1_1 = SchemaVersion::new(1, 1);
    let v2_0 = SchemaVersion::new(2, 0);

    assert!(v1_1.is_compatible_with(&v1_0));
    assert!(v1_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v1_1));
    assert!(!v2_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v2_0));
}

#[test]
fn test_evidence_reference_and_kind() {
    let r = EvidenceReference::new(42);
    assert_eq!(r.id(), 42);
    assert_eq!(r.to_string(), "evi:42");

    let kinds = [
        (EvidenceKind::PacketMeasurement, "PacketMeasurement"),
        (EvidenceKind::FlowMeasurement, "FlowMeasurement"),
        (EvidenceKind::ProtocolObservation, "ProtocolObservation"),
        (EvidenceKind::TemporalMetric, "TemporalMetric"),
        (EvidenceKind::RatioComparison, "RatioComparison"),
        (EvidenceKind::StructuralAnomaly, "StructuralAnomaly"),
    ];

    for (k, expected) in kinds {
        assert_eq!(k.as_str(), expected);
        assert_eq!(k.to_string(), expected);
    }
}

#[test]
fn test_evidence_description_and_metric_key() {
    let desc = EvidenceDescription::new("Valid description\x1b[31m colored text");
    assert_eq!(desc.as_str(), "Valid description [31m colored text");

    let key = EvidenceMetricKey::new("metric.key\x00with_null");
    assert_eq!(key.as_str(), "metric.key_with_null");
}

#[test]
fn test_evidence_ratio_rational_arithmetic_and_comparison() {
    let r1 = EvidenceRatio::from_fraction(6, 8).unwrap();
    assert_eq!(r1.numerator(), 3);
    assert_eq!(r1.denominator(), 4);
    assert_eq!(r1.to_exact_string(), "3/4");
    assert_eq!(r1.to_string(), "3/4");

    let r_zero = EvidenceRatio::from_fraction(0, 10).unwrap();
    assert_eq!(r_zero, EvidenceRatio::ZERO);
    assert_eq!(r_zero.numerator(), 0);
    assert_eq!(r_zero.denominator(), 1);

    assert!(EvidenceRatio::from_fraction(5, 0).is_none());

    let r_int = EvidenceRatio::from_integer(10);
    assert_eq!(r_int.numerator(), 10);
    assert_eq!(r_int.denominator(), 1);

    // Exact ordering test across fractions
    let series = [
        EvidenceRatio::from_fraction(1, 3).unwrap(),
        EvidenceRatio::from_fraction(1, 2).unwrap(),
        EvidenceRatio::from_fraction(2, 3).unwrap(),
        EvidenceRatio::from_fraction(3, 4).unwrap(),
        EvidenceRatio::from_fraction(1, 1).unwrap(),
        EvidenceRatio::from_fraction(5, 4).unwrap(),
        EvidenceRatio::from_fraction(10, 1).unwrap(),
    ];

    for window in series.windows(2) {
        assert!(
            window[0] < window[1],
            "expected {:?} < {:?}",
            window[0],
            window[1]
        );
        assert!(
            window[1] > window[0],
            "expected {:?} > {:?}",
            window[1],
            window[0]
        );
    }

    // Huge numbers overflow-free comparison
    let r_huge1 = EvidenceRatio::from_fraction(u128::MAX - 1, u128::MAX).unwrap();
    let r_huge2 = EvidenceRatio::ONE;
    assert!(r_huge1 < r_huge2);
}

#[test]
fn test_evidence_value_and_unit() {
    let val_int = EvidenceValue::Integer(-42);
    let val_uint = EvidenceValue::Unsigned(100);
    let val_ratio = EvidenceValue::Ratio(EvidenceRatio::ONE);
    let val_bool = EvidenceValue::Boolean(true);
    let val_text = EvidenceValue::Text("test_value".to_string());

    assert!(val_int.is_numeric());
    assert!(val_uint.is_numeric());
    assert!(val_ratio.is_numeric());
    assert!(!val_bool.is_numeric());
    assert!(!val_text.is_numeric());

    assert_eq!(val_int.to_string(), "-42");
    assert_eq!(val_uint.to_string(), "100");
    assert_eq!(val_ratio.to_string(), "1/1");
    assert_eq!(val_bool.to_string(), "true");
    assert_eq!(val_text.to_string(), "test_value");

    let units = [
        (EvidenceUnit::Bytes, "bytes"),
        (EvidenceUnit::Packets, "packets"),
        (EvidenceUnit::Nanoseconds, "ns"),
        (EvidenceUnit::Microseconds, "us"),
        (EvidenceUnit::Milliseconds, "ms"),
        (EvidenceUnit::Seconds, "s"),
        (EvidenceUnit::Ratio, "ratio"),
        (EvidenceUnit::Count, "count"),
        (EvidenceUnit::PercentageInteger, "%"),
        (
            EvidenceUnit::Custom("custom_unit".to_string()),
            "custom_unit",
        ),
    ];

    for (u, expected) in units {
        assert_eq!(u.as_str(), expected);
        assert_eq!(u.to_string(), expected);
    }
}

#[test]
fn test_evidence_comparison() {
    let comps = [
        (EvidenceComparison::Equal, "=="),
        (EvidenceComparison::NotEqual, "!="),
        (EvidenceComparison::LessThan, "<"),
        (EvidenceComparison::LessThanOrEqual, "<="),
        (EvidenceComparison::GreaterThan, ">"),
        (EvidenceComparison::GreaterThanOrEqual, ">="),
        (EvidenceComparison::InRange, "in_range"),
        (EvidenceComparison::OutsideRange, "outside_range"),
    ];

    for (c, expected) in comps {
        assert_eq!(c.as_str(), expected);
        assert_eq!(c.to_string(), expected);
    }
}

#[test]
fn test_evidence_measurement() {
    let m1 = EvidenceMeasurement::new(
        EvidenceMetricKey::new("packet_count"),
        EvidenceValue::Unsigned(100),
        EvidenceUnit::Packets,
    );
    assert_eq!(m1.key.as_str(), "packet_count");
    assert_eq!(m1.observed_value, EvidenceValue::Unsigned(100));
    assert!(m1.threshold_value.is_none());
    assert!(m1.comparison.is_none());
    assert_eq!(m1.unit, EvidenceUnit::Packets);

    let m2 = EvidenceMeasurement::with_threshold(
        EvidenceMetricKey::new("payload_ratio"),
        EvidenceValue::Ratio(EvidenceRatio::from_fraction(3, 4).unwrap()),
        EvidenceValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Ratio,
    );
    assert_eq!(m2.key.as_str(), "payload_ratio");
    assert_eq!(
        m2.observed_value,
        EvidenceValue::Ratio(EvidenceRatio::from_fraction(3, 4).unwrap())
    );
    assert_eq!(
        m2.threshold_value,
        Some(EvidenceValue::Ratio(
            EvidenceRatio::from_fraction(1, 2).unwrap()
        ))
    );
    assert_eq!(m2.comparison, Some(EvidenceComparison::GreaterThan));
}

#[test]
fn test_evidence_limitation() {
    let lims = [
        (EvidenceLimitation::TruncatedPayload, "TruncatedPayload"),
        (
            EvidenceLimitation::MissingNetworkLayer,
            "MissingNetworkLayer",
        ),
        (
            EvidenceLimitation::IncompleteHandshake,
            "IncompleteHandshake",
        ),
        (
            EvidenceLimitation::PacketCountBudgetReached,
            "PacketCountBudgetReached",
        ),
        (
            EvidenceLimitation::ObservationBudgetReached,
            "ObservationBudgetReached",
        ),
        (EvidenceLimitation::FlowBudgetReached, "FlowBudgetReached"),
        (
            EvidenceLimitation::HeaderBudgetExceeded,
            "HeaderBudgetExceeded",
        ),
    ];

    for (l, expected) in lims {
        assert_eq!(l.as_str(), expected);
        assert_eq!(l.to_string(), expected);
    }
}

#[test]
fn test_evidence_record_full_workflow() {
    let mut record = EvidenceRecord::new(
        EvidenceReference::new(1),
        EvidenceKind::RatioComparison,
        EvidenceDescription::new("Observed asymmetric traffic ratio"),
    );

    record.add_packet_reference(PacketReference::new(1, None, None, 100, 100, false));
    record.add_flow_reference(FlowReference::new(0));
    record.add_observation_reference(ObservationReference::new(42));
    record.add_measurement(EvidenceMeasurement::with_threshold(
        EvidenceMetricKey::new("bytes_a_to_b_ratio"),
        EvidenceValue::Ratio(EvidenceRatio::from_fraction(9, 10).unwrap()),
        EvidenceValue::Ratio(EvidenceRatio::from_fraction(1, 2).unwrap()),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Ratio,
    ));
    record.add_limitation(EvidenceLimitation::TruncatedPayload);

    assert_eq!(record.reference, EvidenceReference::new(1));
    assert_eq!(record.kind, EvidenceKind::RatioComparison);
    assert_eq!(
        record.description.as_str(),
        "Observed asymmetric traffic ratio"
    );
    assert_eq!(record.packet_references.len(), 1);
    assert_eq!(record.flow_references.len(), 1);
    assert_eq!(record.observation_references.len(), 1);
    assert_eq!(record.measurements.len(), 1);
    assert_eq!(record.limitations.len(), 1);
    assert_eq!(record.schema_version, SchemaVersion::CURRENT);
}

#[test]
fn test_evidence_ratio_grid_ordering() {
    let test_numerators: [u64; 10] = [0, 1, 2, 3, 5, 7, 10, 100, 999, 10000];
    let test_denominators: [u64; 9] = [1, 2, 3, 4, 7, 10, 100, 999, 10000];

    for &n1 in &test_numerators {
        for &d1 in &test_denominators {
            let r1 = EvidenceRatio::from_fraction(n1 as u128, d1 as u128).unwrap();
            for &n2 in &test_numerators {
                for &d2 in &test_denominators {
                    let r2 = EvidenceRatio::from_fraction(n2 as u128, d2 as u128).unwrap();

                    let prod1 = (n1 as u128) * (d2 as u128);
                    let prod2 = (n2 as u128) * (d1 as u128);
                    let expected_ord = prod1.cmp(&prod2);

                    assert_eq!(
                        r1.cmp(&r2),
                        expected_ord,
                        "comparison mismatch for {}/{} vs {}/{}",
                        n1,
                        d1,
                        n2,
                        d2
                    );
                }
            }
        }
    }
}

//! Integration tests for unified protocol observations and structured evidence model.

use pcapraven_domain::*;

#[test]
fn test_protocol_kind_properties() {
    assert_eq!(ProtocolKind::Dns.as_str(), "DNS");
    assert_eq!(ProtocolKind::Http.as_str(), "HTTP");
    assert_eq!(ProtocolKind::Tls.as_str(), "TLS");

    assert_eq!(ProtocolKind::Dns.as_str_lowercase(), "dns");
    assert_eq!(ProtocolKind::Http.as_str_lowercase(), "http");
    assert_eq!(ProtocolKind::Tls.as_str_lowercase(), "tls");

    assert_eq!(ProtocolKind::Dns.to_string(), "DNS");
    assert_eq!(ProtocolKind::Http.to_string(), "HTTP");
    assert_eq!(ProtocolKind::Tls.to_string(), "TLS");

    assert_eq!(ProtocolKind::Dns, ProtocolKind::Dns);
    assert_ne!(ProtocolKind::Dns, ProtocolKind::Http);
    assert!(ProtocolKind::Dns < ProtocolKind::Http);
    assert!(ProtocolKind::Http < ProtocolKind::Tls);
}

#[test]
fn test_observation_reference_structural_determinism_and_ordering() {
    let r_dns_0 = ObservationReference::new(1, ProtocolKind::Dns, 0);
    let r_dns_1 = ObservationReference::new(1, ProtocolKind::Dns, 1);
    let r_http_0 = ObservationReference::new(1, ProtocolKind::Http, 0);
    let r_tls_0 = ObservationReference::new(1, ProtocolKind::Tls, 0);
    let r_pkt2_dns = ObservationReference::new(2, ProtocolKind::Dns, 0);

    assert_eq!(r_dns_0.packet_ordinal(), 1);
    assert_eq!(r_dns_0.protocol(), ProtocolKind::Dns);
    assert_eq!(r_dns_0.ordinal_within_packet(), 0);

    assert_eq!(r_dns_0.to_string(), "obs:1:dns:0");
    assert_eq!(r_dns_1.to_string(), "obs:1:dns:1");
    assert_eq!(r_http_0.to_string(), "obs:1:http:0");
    assert_eq!(r_tls_0.to_string(), "obs:1:tls:0");
    assert_eq!(r_pkt2_dns.to_string(), "obs:2:dns:0");

    // Total ordering: packet_ordinal -> protocol -> ordinal_within_packet
    assert!(r_dns_0 < r_dns_1);
    assert!(r_dns_1 < r_http_0);
    assert!(r_http_0 < r_tls_0);
    assert!(r_tls_0 < r_pkt2_dns);
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
fn test_observation_flow_association_and_direction_preservation() {
    let f_ref = FlowReference::new(10);
    let assoc = ObservationFlowAssociation::Associated {
        flow: f_ref,
        direction: FlowDirection::AToB,
    };
    assert!(assoc.is_associated());
    assert!(!assoc.is_excluded());
    assert!(!assoc.is_unassociated());
    assert_eq!(assoc.flow_reference(), Some(f_ref));
    assert_eq!(assoc.flow_direction(), Some(FlowDirection::AToB));
    assert_eq!(assoc.exclusion_reason(), None);
    assert_eq!(assoc.to_string(), "Associated(Flow(10), A->B)");

    let assoc_b_to_a = ObservationFlowAssociation::Associated {
        flow: f_ref,
        direction: FlowDirection::BToA,
    };
    assert_eq!(assoc_b_to_a.flow_direction(), Some(FlowDirection::BToA));

    let assoc_same = ObservationFlowAssociation::Associated {
        flow: f_ref,
        direction: FlowDirection::SameEndpoint,
    };
    assert_eq!(
        assoc_same.flow_direction(),
        Some(FlowDirection::SameEndpoint)
    );

    let excl = ObservationFlowAssociation::Excluded(FlowExclusionReason::MissingNetworkLayer);
    assert!(!excl.is_associated());
    assert!(excl.is_excluded());
    assert!(!excl.is_unassociated());
    assert_eq!(excl.flow_reference(), None);
    assert_eq!(excl.flow_direction(), None);
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
    assert_eq!(unassoc.flow_direction(), None);
    assert_eq!(unassoc.exclusion_reason(), None);
    assert_eq!(unassoc.to_string(), "Unassociated");
}

#[test]
fn test_observation_flow_association_from_packet_association() {
    let pkt1 = PacketReference::new(1, None, None, 100, 100, false);
    let pkt2 = PacketReference::new(2, None, None, 100, 100, false);

    let flow_pkt_assoc =
        FlowPacketAssociation::new(FlowReference::new(5), pkt1, FlowDirection::AToB);

    // Matching packet ordinal succeeds
    let assoc =
        ObservationFlowAssociation::from_flow_packet_association(&pkt1, &flow_pkt_assoc).unwrap();
    assert_eq!(assoc.flow_reference(), Some(FlowReference::new(5)));
    assert_eq!(assoc.flow_direction(), Some(FlowDirection::AToB));

    // Mismatched packet ordinal fails
    let err = ObservationFlowAssociation::from_flow_packet_association(&pkt2, &flow_pkt_assoc)
        .unwrap_err();
    assert_eq!(
        err,
        ObservationError::FlowAssociationPacketMismatch {
            observation_packet_ordinal: 2,
            association_packet_ordinal: 1,
        }
    );
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
    assert_eq!(data_dns_comp.packet_reference(), &pkt);
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
    assert_eq!(data_http_comp.packet_reference(), &pkt);
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
    assert_eq!(data_tls_comp.packet_reference(), &pkt);
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
fn test_protocol_observation_invariant_validation() {
    let pkt1 = PacketReference::new(1, None, None, 100, 100, false);

    let http_obs = HttpObservation {
        packet: pkt1,
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

    // Valid observation construction
    let valid_ref = ObservationReference::new(1, ProtocolKind::Http, 0);
    let flow_assoc = ObservationFlowAssociation::Associated {
        flow: FlowReference::new(2),
        direction: FlowDirection::AToB,
    };

    let obs = ProtocolObservation::try_new(
        valid_ref,
        flow_assoc,
        ProtocolObservationData::Http(http_obs.clone()),
    )
    .unwrap();

    assert_eq!(obs.reference(), valid_ref);
    assert_eq!(obs.packet_reference(), &pkt1);
    assert_eq!(obs.flow_association(), &flow_assoc);
    assert_eq!(obs.completeness(), ObservationCompleteness::Complete);
    assert_eq!(obs.protocol_kind(), ProtocolKind::Http);

    // Mismatched packet ordinal in reference
    let bad_pkt_ref = ObservationReference::new(2, ProtocolKind::Http, 0);
    let err_pkt = ProtocolObservation::try_new(
        bad_pkt_ref,
        flow_assoc,
        ProtocolObservationData::Http(http_obs.clone()),
    )
    .unwrap_err();
    assert_eq!(
        err_pkt,
        ObservationError::PacketReferenceMismatch {
            reference_packet_ordinal: 2,
            payload_packet_ordinal: 1,
        }
    );

    // Mismatched protocol in reference
    let bad_proto_ref = ObservationReference::new(1, ProtocolKind::Dns, 0);
    let err_proto = ProtocolObservation::try_new(
        bad_proto_ref,
        flow_assoc,
        ProtocolObservationData::Http(http_obs.clone()),
    )
    .unwrap_err();
    assert_eq!(
        err_proto,
        ObservationError::ProtocolMismatch {
            reference_protocol: ProtocolKind::Dns,
            payload_protocol: ProtocolKind::Http,
        }
    );

    // Partial payload MUST produce Partial observation (completeness is strictly derived)
    let mut partial_http_obs = http_obs;
    partial_http_obs.completeness = HttpObservationCompleteness::Partial {
        reason: "Truncated",
    };
    let partial_obs = ProtocolObservation::try_new(
        valid_ref,
        flow_assoc,
        ProtocolObservationData::Http(partial_http_obs),
    )
    .unwrap();
    assert_eq!(partial_obs.completeness(), ObservationCompleteness::Partial);
}

#[test]
fn test_protocol_observation_collection_hard_bounds_and_ordering() {
    // 0 capacity rejected
    assert_eq!(
        ProtocolObservationCollection::new(0).unwrap_err(),
        ProtocolObservationCollectionError::ZeroCapacity
    );

    // Above hard max rejected
    assert_eq!(
        ProtocolObservationCollection::new(
            ProtocolObservationCollection::HARD_MAX_OBSERVATIONS + 1
        )
        .unwrap_err(),
        ProtocolObservationCollectionError::CapacityAboveHardMaximum {
            requested: ProtocolObservationCollection::HARD_MAX_OBSERVATIONS + 1,
            maximum: ProtocolObservationCollection::HARD_MAX_OBSERVATIONS,
        }
    );

    let mut coll = ProtocolObservationCollection::new(2).unwrap();
    assert_eq!(coll.capacity(), 2);
    assert_eq!(coll.len(), 0);
    assert!(coll.is_empty());
    assert!(!coll.is_truncated());

    let pkt1 = PacketReference::new(1, None, None, 100, 100, false);
    let pkt2 = PacketReference::new(2, None, None, 100, 100, false);
    let pkt3 = PacketReference::new(3, None, None, 100, 100, false);

    let obs1 = ProtocolObservation::try_new(
        ObservationReference::new(1, ProtocolKind::Http, 0),
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt1,
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
    )
    .unwrap();

    let obs2 = ProtocolObservation::try_new(
        ObservationReference::new(2, ProtocolKind::Http, 0),
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt2,
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
    )
    .unwrap();

    let obs3 = ProtocolObservation::try_new(
        ObservationReference::new(3, ProtocolKind::Http, 0),
        ObservationFlowAssociation::Unassociated,
        ProtocolObservationData::Http(HttpObservation {
            packet: pkt3,
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
    )
    .unwrap();

    assert!(coll.push(obs1.clone()).is_ok());
    assert_eq!(coll.len(), 1);

    // Duplicate insertion rejected and transactional
    let dup_err = coll.push(obs1).unwrap_err();
    assert_eq!(
        dup_err,
        ProtocolObservationCollectionError::DuplicateReference(ObservationReference::new(
            1,
            ProtocolKind::Http,
            0
        ))
    );
    assert_eq!(coll.len(), 1);

    assert!(coll.push(obs2).is_ok());
    assert_eq!(coll.len(), 2);

    // Out of order insertion rejected
    let mut out_of_order_coll = ProtocolObservationCollection::new(10).unwrap();
    out_of_order_coll.push(obs3.clone()).unwrap();
    let ooo_err = out_of_order_coll
        .push(
            ProtocolObservation::try_new(
                ObservationReference::new(1, ProtocolKind::Http, 0),
                ObservationFlowAssociation::Unassociated,
                ProtocolObservationData::Http(HttpObservation {
                    packet: pkt1,
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
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        ooo_err,
        ProtocolObservationCollectionError::OutOfOrderReference {
            previous: ObservationReference::new(3, ProtocolKind::Http, 0),
            attempted: ObservationReference::new(1, ProtocolKind::Http, 0),
        }
    );

    // Capacity reached: explicit ResourceLimit error and marked is_truncated
    let limit_err = coll.push(obs3).unwrap_err();
    assert_eq!(
        limit_err,
        ProtocolObservationCollectionError::ResourceLimit { capacity: 2 }
    );
    assert!(coll.is_truncated());
    assert_eq!(coll.len(), 2);
}

#[test]
fn test_schema_version_anchors() {
    assert_eq!(PROTOCOL_OBSERVATION_SCHEMA_VERSION.major(), 1);
    assert_eq!(PROTOCOL_OBSERVATION_SCHEMA_VERSION.minor(), 0);
    assert_eq!(EVIDENCE_SCHEMA_VERSION.major(), 1);
    assert_eq!(EVIDENCE_SCHEMA_VERSION.minor(), 0);
    assert_eq!(SchemaVersion::CURRENT, EVIDENCE_SCHEMA_VERSION);

    let v1_0 = SchemaVersion::new(1, 0);
    let v1_1 = SchemaVersion::new(1, 1);
    let v2_0 = SchemaVersion::new(2, 0);

    assert!(v1_1.is_compatible_with(&v1_0));
    assert!(v1_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v1_1));
    assert!(!v2_0.is_compatible_with(&v1_0));
}

#[test]
fn test_evidence_description_validation() {
    // Valid description
    let d = EvidenceDescription::try_new("Observed asymmetric traffic ratio").unwrap();
    assert_eq!(d.as_str(), "Observed asymmetric traffic ratio");

    // Empty description rejected
    assert_eq!(
        EvidenceDescription::try_new("").unwrap_err(),
        EvidenceValidationError::EmptyDescription
    );

    // Exact max (512 bytes) accepted
    let exact_512 = "a".repeat(512);
    assert!(EvidenceDescription::try_new(&exact_512).is_ok());

    // 513 bytes rejected
    let over_512 = "a".repeat(513);
    assert_eq!(
        EvidenceDescription::try_new(&over_512).unwrap_err(),
        EvidenceValidationError::DescriptionTooLong {
            length: 513,
            max: 512,
        }
    );

    // Control characters rejected
    assert_eq!(
        EvidenceDescription::try_new("Text with \x00 NUL").unwrap_err(),
        EvidenceValidationError::DescriptionControlCharacter { byte: 0 }
    );
    assert_eq!(
        EvidenceDescription::try_new("Text with \x1b ESC").unwrap_err(),
        EvidenceValidationError::DescriptionControlCharacter { byte: 0x1b }
    );
    assert_eq!(
        EvidenceDescription::try_new("Text with \r CR").unwrap_err(),
        EvidenceValidationError::DescriptionControlCharacter { byte: 0x0d }
    );
    assert_eq!(
        EvidenceDescription::try_new("Text with \n LF").unwrap_err(),
        EvidenceValidationError::DescriptionControlCharacter { byte: 0x0a }
    );
    assert_eq!(
        EvidenceDescription::try_new("Text with \t TAB").unwrap_err(),
        EvidenceValidationError::DescriptionControlCharacter { byte: 0x09 }
    );
}

#[test]
fn test_evidence_metric_key_validation() {
    let valid_keys = [
        "packet_count",
        "flow.duration",
        "interval_mean",
        "observed-ratio",
        "dns.query_count",
        "a1",
        "test_123.metric-name",
    ];
    for &k in &valid_keys {
        assert!(
            EvidenceMetricKey::try_new(k).is_ok(),
            "key {k} should be valid"
        );
    }

    // Empty rejected
    assert_eq!(
        EvidenceMetricKey::try_new("").unwrap_err(),
        EvidenceValidationError::EmptyMetricKey
    );

    // Uppercase rejected
    assert!(EvidenceMetricKey::try_new("Packet_Count").is_err());

    // Whitespace rejected
    assert!(EvidenceMetricKey::try_new("foo bar").is_err());

    // Leading punctuation rejected
    assert!(EvidenceMetricKey::try_new(".metric").is_err());
    assert!(EvidenceMetricKey::try_new("-metric").is_err());

    // Control characters rejected
    assert!(EvidenceMetricKey::try_new("foo\x00bar").is_err());
    assert!(EvidenceMetricKey::try_new("foo\nbar").is_err());

    // Exact max 64 accepted
    let exact_64 = "a".repeat(64);
    assert!(EvidenceMetricKey::try_new(&exact_64).is_ok());

    // 65 bytes rejected
    let over_64 = "a".repeat(65);
    assert!(EvidenceMetricKey::try_new(&over_64).is_err());
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
        assert!(window[0] < window[1]);
        assert!(window[1] > window[0]);
    }

    // Huge numbers overflow-free comparison
    let r_huge1 = EvidenceRatio::from_fraction(u128::MAX - 1, u128::MAX).unwrap();
    let r_huge2 = EvidenceRatio::ONE;
    assert!(r_huge1 < r_huge2);
}

#[test]
fn test_evidence_measurement_validation() {
    let key = EvidenceMetricKey::try_new("packet_count").unwrap();

    // Valid measurement without threshold
    let m1 = EvidenceMeasurement::try_new(
        key.clone(),
        EvidenceValue::Unsigned(100),
        EvidenceUnit::Packets,
    )
    .unwrap();
    assert_eq!(m1.key().as_str(), "packet_count");
    assert_eq!(m1.observed_value(), &EvidenceValue::Unsigned(100));
    assert!(m1.threshold_value().is_none());
    assert!(m1.comparison().is_none());

    // Valid measurement with threshold
    let ratio_key = EvidenceMetricKey::try_new("ratio_metric").unwrap();
    let r_obs = EvidenceRatio::from_fraction(3, 4).unwrap();
    let r_thresh = EvidenceRatio::from_fraction(1, 2).unwrap();
    let m2 = EvidenceMeasurement::try_with_threshold(
        ratio_key,
        EvidenceValue::Ratio(r_obs),
        EvidenceValue::Ratio(r_thresh),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Ratio,
    )
    .unwrap();
    assert_eq!(m2.observed_value(), &EvidenceValue::Ratio(r_obs));
    assert_eq!(m2.threshold_value(), Some(&EvidenceValue::Ratio(r_thresh)));
    assert_eq!(m2.comparison(), Some(EvidenceComparison::GreaterThan));

    // Incompatible value and threshold types (Unsigned vs Ratio)
    let incomp_err = EvidenceMeasurement::try_with_threshold(
        key.clone(),
        EvidenceValue::Unsigned(100),
        EvidenceValue::Ratio(r_thresh),
        EvidenceComparison::GreaterThan,
        EvidenceUnit::Packets,
    )
    .unwrap_err();
    assert_eq!(
        incomp_err,
        EvidenceValidationError::IncompatibleUnitAndValue
    );

    // Incompatible unit and value (Ratio unit with Unsigned value)
    let unit_err = EvidenceMeasurement::try_new(
        key.clone(),
        EvidenceValue::Unsigned(50),
        EvidenceUnit::Ratio,
    )
    .unwrap_err();
    assert_eq!(unit_err, EvidenceValidationError::IncompatibleUnitAndValue);

    // Percentage > 100 rejected
    let pct_key = EvidenceMetricKey::try_new("loss_pct").unwrap();
    let pct_err = EvidenceMeasurement::try_new(
        pct_key,
        EvidenceValue::Unsigned(101),
        EvidenceUnit::PercentageInteger,
    )
    .unwrap_err();
    assert_eq!(
        pct_err,
        EvidenceValidationError::PercentageOutOfRange { value: 101 }
    );
}

#[test]
fn test_evidence_record_builder_bounds_and_uniqueness() {
    let desc = EvidenceDescription::try_new("Valid evidence record").unwrap();
    let mut builder = EvidenceRecord::builder(
        EvidenceReference::new(1),
        EvidenceKind::ProtocolFact,
        desc.clone(),
    );

    // Cannot build empty evidence record
    assert_eq!(
        builder.clone().build().unwrap_err(),
        EvidenceValidationError::EmptyEvidenceRecord
    );

    let pkt1 = PacketReference::new(1, None, None, 100, 100, false);
    let pkt2 = PacketReference::new(2, None, None, 100, 100, false);
    builder.add_packet_reference(pkt1).unwrap();

    // Duplicate packet reference rejected
    assert_eq!(
        builder.add_packet_reference(pkt1).unwrap_err(),
        EvidenceValidationError::DuplicatePacketReference(pkt1)
    );

    // Out-of-order packet reference rejected
    let mut ooo_builder = builder.clone();
    ooo_builder.add_packet_reference(pkt2).unwrap();
    assert_eq!(
        ooo_builder.add_packet_reference(pkt1).unwrap_err(),
        EvidenceValidationError::OutOfOrderPacketReference {
            previous: 2,
            attempted: 1
        }
    );

    // Flow references duplicate and ordering
    builder.add_flow_reference(FlowReference::new(1)).unwrap();
    assert_eq!(
        builder
            .add_flow_reference(FlowReference::new(1))
            .unwrap_err(),
        EvidenceValidationError::DuplicateFlowReference(FlowReference::new(1))
    );

    // Observation references duplicate and ordering
    let obs_ref1 = ObservationReference::new(1, ProtocolKind::Http, 0);
    builder.add_observation_reference(obs_ref1).unwrap();
    assert_eq!(
        builder.add_observation_reference(obs_ref1).unwrap_err(),
        EvidenceValidationError::DuplicateObservationReference(obs_ref1)
    );

    // Measurements unique metric keys
    let m1 = EvidenceMeasurement::try_new(
        EvidenceMetricKey::try_new("metric_a").unwrap(),
        EvidenceValue::Unsigned(10),
        EvidenceUnit::Count,
    )
    .unwrap();
    builder.add_measurement(m1.clone()).unwrap();

    assert_eq!(
        builder.add_measurement(m1).unwrap_err(),
        EvidenceValidationError::DuplicateMetricKey(
            EvidenceMetricKey::try_new("metric_a").unwrap()
        )
    );

    // Limitations unique and sorted
    builder
        .add_limitation(EvidenceLimitation::TruncatedPayload)
        .unwrap();
    assert_eq!(
        builder
            .add_limitation(EvidenceLimitation::TruncatedPayload)
            .unwrap_err(),
        EvidenceValidationError::DuplicateLimitation(EvidenceLimitation::TruncatedPayload)
    );

    // Build successful record
    let record = builder.build().unwrap();
    assert_eq!(record.reference(), EvidenceReference::new(1));
    assert_eq!(record.kind(), EvidenceKind::ProtocolFact);
    assert_eq!(record.description().as_str(), "Valid evidence record");
    assert_eq!(record.packet_references().len(), 1);
    assert_eq!(record.flow_references().len(), 1);
    assert_eq!(record.observation_references().len(), 1);
    assert_eq!(record.measurements().len(), 1);
    assert_eq!(record.limitations().len(), 1);
    assert_eq!(record.schema_version(), EVIDENCE_SCHEMA_VERSION);
}

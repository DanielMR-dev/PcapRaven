---
name: connection-behavior-detection
description: Explainable repeated low-volume flow behavior detection in PcapRaven.
---

# Connection Behavior Detection Skill

This skill documents requirements and procedures for implementing, testing, and reviewing
explainable connection behavior detectors in PcapRaven.

## Core Invariants

1. **Deterministic Canonical Keys:** Use `ConnectionPeerKey` (`TransportProtocol`, `peer_a <= peer_b` where ports are excluded).
2. **Checked Arithmetic:** Use `checked_add` for all byte and packet counter aggregations.
3. **Bounded State:** Tracked peers must be bounded by `maximum_tracked_peer_groups` ($1..=1\_000\_000$).
4. **Flow Qualification Rules:**
   - Exclude flows with `end_reason == AnalysisStopped`.
   - Exclude flows with same-address peers (`endpoint_a.address == endpoint_b.address`); peer addresses must be distinct.
   - `temporal.duration` must be Available.
   - Clean timestamps (`unavailable_timestamps == 0`, `invalid_timestamps == 0`, `non_monotonic_transitions == 0`).
   - Exclude flows with `traffic.same_endpoint.packet_count > 0`.
   - Exclude truncated packets (`traffic.total.truncated_packet_count == 0`).
   - Exclude empty flows (`total.packet_count == 0`).
5. **Candidate Flow Rules:**
   - `total.packet_count <= maximum_packets_per_flow`.
   - `total.wire_bytes <= maximum_wire_bytes_per_flow`.
   - `flow_duration <= maximum_flow_duration`.
6. **Ordered Structured Evidence:** Measurements must be added in strict lexicographical order:
   - `candidate_flow_count`
   - `candidate_flow_ratio`
   - `eligible_flow_instance_count`
   - `maximum_candidate_duration`
   - `maximum_candidate_packet_count`
   - `maximum_candidate_wire_bytes`
7. **No Floating-Point Arithmetic:** Zero `f32`/`f64` usage.
8. **Balanced Rationale:** Do not assert confirmed malware or command-and-control without definitive evidence; note benign alternatives.

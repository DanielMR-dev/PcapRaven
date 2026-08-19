# Connection Behavior & Cross-Detector C2 Correlation Specifications

## 1. Overview

This document specifies the Phase 14 explainable connection behavior detector (`RepeatedLowVolumeFlowDetector`) and cross-detector finding correlator (`PossibleC2MultiSignalCorrelator`) in PcapRaven.

These heuristics provide explainable, deterministic detection over normalized flow statistics, temporal metrics, and protocol observations without unbounded memory allocation, floating-point arithmetic, raw packet payload copies, or unevidenced malware / C2 assertions.

---

## 2. `RepeatedLowVolumeFlowDetector` (`behavior.repeated_low_volume_flows`)

### 2.1 Metadata and Contracts
- **Detector Identifier:** `behavior.repeated_low_volume_flows`
- **Detector Version:** `v1.0.0`
- **Incomplete Data Policy:** `IncompleteDataPolicy::Skip`
- **Default Severity:** `Severity::Low`
- **Default Confidence:** `Confidence::Medium`
- **Finding Title:** `Repeated low-volume flow pattern`

### 2.2 Endpoint Canonicalization (`ConnectionPeerKey`)
Flows are grouped by canonical port-agnostic peer pair:
```rust
ConnectionPeerKey {
    transport: TransportProtocol, // TCP or UDP
    peer_a: IpAddress,           // min(endpoint_a.address, endpoint_b.address)
    peer_b: IpAddress,           // max(endpoint_a.address, endpoint_b.address)
}
```
Port numbers are intentionally excluded to aggregate across ephemeral ports and repeated connections between communicating hosts.

### 2.3 Flow Eligibility Rules
A flow record is eligible for aggregation if and only if:
1. `flow.end_reason != FlowEndReason::AnalysisStopped` (complete lifecycle flow).
2. Peer addresses are distinct (`endpoint_a.address != endpoint_b.address`).
3. `flow.temporal.duration` is `FlowTemporalValue::Available(duration)`.
4. Clean timestamps: `unavailable_timestamps == 0`, `invalid_timestamps == 0`, `non_monotonic_transitions == 0`.
5. `flow.traffic.total.truncated_packet_count == 0`.
6. `flow.traffic.total.packet_count > 0` (non-empty flow).
7. `flow.traffic.same_endpoint.packet_count == 0` (valid bidirectional endpoint communication).

### 2.4 Candidate Low-Volume Flow Rule
An eligible flow is a candidate when all are true:
1. `flow.traffic.total.packet_count <= maximum_packets_per_flow`
2. `flow.traffic.total.wire_bytes <= maximum_wire_bytes_per_flow`
3. `flow_duration <= maximum_flow_duration`

### 2.5 Configuration Parameters
| Parameter Key | Type | Valid Range | Default |
|---|---|---|---|
| `minimum_eligible_flow_instances` | `Unsigned` | `2..=u64::MAX` | `6` |
| `minimum_candidate_flow_ratio` | `Ratio` | `0 < r <= 1` | `3/4` |
| `maximum_packets_per_flow` | `Unsigned` | `1..=u64::MAX` | `20` |
| `maximum_wire_bytes_per_flow` | `Unsigned` | `1..=u64::MAX` | `32_768` |
| `maximum_flow_duration` | `Duration` | `> 0` | `60s` |
| `maximum_tracked_peer_groups` | `Unsigned` | `1..=1_000_000` | `65_536` |

### 2.6 Structured Evidence Schema
- **Evidence Kind:** `EvidenceKind::RatioComparison`
- **Description:** `Repeated low-volume flow aggregate measurements`
- **Measurements (Strict Lexicographical Order):**
  1. `candidate_flow_count` (`Count`): Total qualifying candidate flows observed.
  2. `candidate_flow_ratio` (`Ratio`): Ratio of candidate flows to eligible instances ($\ge \text{minimum\_candidate\_flow\_ratio}$).
  3. `eligible_flow_instance_count` (`Count`): Total eligible flow instances observed ($\ge \text{minimum\_eligible\_flow\_instances}$).
  4. `maximum_candidate_duration` (`Seconds`): Maximum duration observed among candidate flows ($\le \text{maximum\_flow\_duration}$).
  5. `maximum_candidate_packet_count` (`Packets`): Maximum packet count observed among candidate flows ($\le \text{maximum\_packets\_per\_flow}$).
  6. `maximum_candidate_wire_bytes` (`Bytes`): Maximum wire bytes observed among candidate flows ($\le \text{maximum\_wire_bytes\_per\_flow}$).

---

## 3. `PossibleC2MultiSignalCorrelator` (`behavior.possible_c2_multi_signal`)

### 3.1 Metadata and Contracts
- **Correlator Identifier:** `behavior.possible_c2_multi_signal`
- **Correlator Logic Version:** `v1.1.0`
- **Required Primary Detector IDs:** `["behavior.periodic_beaconing", "dns.possible_tunneling"]`
- **Severity:** `Severity::Medium`
- **Confidence:** `Confidence::Medium`
- **Finding Title:** `Possible multi-signal C2-like behavior`

### 3.2 Correlation Mechanics
1. Runs post-primary-evaluation during the detection engine pipeline over an immutable snapshot of primary findings.
2. Preflights required primary detector registration and cross-registry identifier uniqueness before evaluation.
3. Indexes primary findings by single `FlowReference` in $O(P \log P)$ time using `BTreeMap`.
4. Identifies pairs of primary findings where:
   - Finding A is `behavior.periodic_beaconing`.
   - Finding B is `dns.possible_tunneling`.
   - Finding A and Finding B share the same `FlowReference`.
5. Emits a `CorrelationDraft` with:
   - `source_finding_references`: `[finding_a.reference(), finding_b.reference()]` (sorted and deduplicated).
   - `evidence_references`: Exact union of `evidence_references` from finding A and finding B (sorted and deduplicated).
   - `subject`: Exactly the single shared `FlowReference` (zero packet or observation references).
   - **Zero New Evidence Records:** Reuses existing evidence records from primary findings to prevent duplicate metric tracking.

### 3.3 Explainable Rationale
"Two independent detector signals (periodic beaconing and possible DNS tunneling) co-occur on the same network flow. While this multi-signal correlation increases investigative relevance, it does not establish confirmed malware, command-and-control, or data exfiltration. Benign alternatives include periodic DNS telemetry, monitoring software, generated scheduled lookups, service discovery, heartbeat mechanisms, security software, or automated infrastructure management."

---

## 4. Invariants & Security Controls
1. **Zero Floats:** All measurements and threshold evaluations use exact integers and rational arithmetic (`EvidenceRatio`, `FlowDuration`).
2. **Deterministic Output:** Peer keys are tracked via `BTreeMap` and findings are emitted in canonical sorted order.
3. **Bounded Memory:** Tracked peer collections are strictly bounded by `maximum_tracked_peer_groups` and correlator sinks are bounded by the engine's finding capacity.
4. **Checked Arithmetic:** All aggregations use `checked_add` and propagate structured `DetectorExecutionError::resource_limit` on overflow.
5. **No Speculative C2 Assertions:** Rationales explicitly describe technical facts and benign alternative explanations (telemetry, background sync, health checks, CDNs).

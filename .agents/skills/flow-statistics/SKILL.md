---
name: flow-statistics
description: Use for PcapRaven directional flow traffic statistics and exact temporal metric design, implementation, and review.
---

# Flow Statistics and Temporal Metrics Skill

This skill governs the design, implementation, review, and verification of
factual bidirectional traffic statistics and exact rational temporal metrics in
`pcapraven-flows` and `pcapraven-domain`.

## Core Responsibilities

- `pcapraven-domain` owns the immutable domain types: `FlowTrafficCounters`,
  `FlowTrafficStatistics`, `FlowDuration`, `FlowTemporalUnavailableReason`,
  `FlowTemporalValue`, `FlowTimestampCoverage`, `FlowInterArrivalMetrics`, and
  `FlowTemporalMetrics`.
- `pcapraven-flows` owns online fixed-size accumulators, checked counter updates,
  and exact timestamp/duration arithmetic.

## Invariants and Rules

### 1. Factual Measurements Only (No Security Interpretations)
- Flow statistics and temporal metrics are purely factual measurements.
- Never label measurements as "suspicious", "beaconing", "C2", or "anomalous".
- Detection rules and periodicity scoring belong strictly to Phase 12.

### 2. Directional Traffic Counter Invariants
- For every completed `FlowRecord`:
  - `total.packet_count == a_to_b.packet_count + b_to_a.packet_count + same_endpoint.packet_count`
  - `total.captured_bytes == a_to_b.captured_bytes + b_to_a.captured_bytes + same_endpoint.captured_bytes`
  - `total.wire_bytes == a_to_b.wire_bytes + b_to_a.wire_bytes + same_endpoint.wire_bytes`
  - `total.truncated_packet_count == a_to_b.truncated_packet_count + b_to_a.truncated_packet_count + same_endpoint.truncated_packet_count`
- `captured_bytes` is the sum of `PacketReference.captured_len`.
- `wire_bytes` is the sum of `PacketReference.original_len`.
- Truncation count reflects `PacketReference.truncated`.

### 3. Exact Rational Duration (Zero Floats)
- Never use `f32` or `f64` for duration, intervals, means, successive deltas, or timeouts.
- Use `FlowDuration` (`numerator: u128`, `denominator: u128`) reduced to lowest terms via GCD.
- Zero duration has canonical representation `0 / 1`.
- Denominator must never be zero.
- Decimal and binary timestamp resolutions and signed offsets are combined via exact LCM/GCD arithmetic.

### 4. Timestamp Validation and Gaps
- An unavailable, invalid, or non-monotonic timestamp must never panic.
- Missing/invalid/non-monotonic timestamps must never be bridged across intervals.
- Non-monotonic timestamps never produce negative intervals; they record a discontinuity and re-anchor the temporal series.

### 5. Inter-Arrival Sample Requirements
- `minimum_interval`, `maximum_interval`, and `mean_interval` require `interval_sample_count >= 1`.
- `mean_absolute_successive_interval_delta` requires `successive_delta_sample_count >= 1`.
- When sample requirements are not met, return `FlowTemporalValue::Unavailable(InsufficientSamples)`.

### 6. Fixed-Size Memory Bounds (No Vectors)
- `ActiveFlowState` must never store `Vec<FlowDuration>`, `Vec<PacketTimestamp>`, `Vec<NormalizedPacket>`, or payload byte vectors.
- Online metrics must be calculated with fixed-size scalar accumulators ($O(1)$ memory per active flow).

### 7. Lifecycle Attribution and Transactionality
- Packets trigger statistics updates only on their associated `FlowReference`.
- Reset (`RST`) packets are fully counted in the terminating flow before closure.
- Failed packet observations (`observe(...) -> Err`) must never mutate active flow state, packet ordinals, or counters.

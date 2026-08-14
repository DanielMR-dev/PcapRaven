---
name: flow-reconstruction
description: Use for PcapRaven bidirectional flow reconstruction design, implementation, and review involving flow keys, directions, lifecycle boundaries, timeouts, SYN/RST/FIN semantics, and state limits.
---

# Flow Reconstruction Review

## Preconditions

1. Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/DOMAIN_MODEL.md`,
   `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, and the current roadmap phase.
2. Confirm flow reconstruction implementation is allowed. Phase 4 permits
   deterministic bidirectional flow reconstruction; Phase 5 flow statistics,
   temporal metrics, application decoders, and detections remain out of scope.
3. Verify that input to the flow reconstructor consists strictly of normalized
   domain records (`NormalizedPacket`) without direct raw capture dependencies.

## Flow Reconstruction Checklist

- **Canonical Key Invariant:** Ensure `FlowKey` canonicalizes endpoints by
  deterministic binary total ordering (`endpoint_a <= endpoint_b`) so that forward
  and reverse packets map to the identical key.
- **Direction Assignment:** Verify `FlowDirection` explicitly distinguishes `AToB`,
  `BToA`, and `SameEndpoint` (when source and destination endpoints are identical).
- **Packet Ordering:** Require strictly increasing `capture_record_ordinal` values.
  Do not sort or reorder input. Fail deterministically on duplicate/decreasing ordinals.
- **FlowReference Stability:** Assign monotonic zero-based flow instance ordinals
  using checked arithmetic. Distinguish sequential 5-tuple reuse across lifecycles.
- **Timestamp Arithmetic & Timeouts:** Use exact integer/fraction arithmetic without
  floating-point numbers. Handle decimal and binary timestamp resolutions and signed
  offsets. Unavailable timestamps must never fabricate timeouts.
- **TCP Lifecycle:**
  - Initial SYN (SYN=1, ACK=0) retransmissions before handshake completion must
    remain in the same flow instance.
  - A new initial SYN arriving after activity/midstream must close the prior flow
    with `TcpNewInitialSyn` and start a new flow.
  - An RST packet must be associated with the active flow before terminating it with
    `TcpReset`.
  - A FIN packet must not force immediate flow closure without subsequent timeout or
    explicit termination.
- **UDP Lifecycle:** Model flow instances purely by key continuity and idle timeout.
- **Finite Resource Bounds:** Enforce configurable caps on `maximum_tracked_flows`
  and `maximum_flow_instances`. Reject non-deterministic eviction.
- **Memory Non-Retention:** Flow reconstructor internal state must never retain
  `NormalizedPacket`, transport payloads, or raw packet byte vectors.
- **Deterministic Output:** Finalization must return completed records ordered by
  `FlowReference` ordinal.
- **Verification Evidence:** Validate with focused unit/boundary tests, `proptest`
  properties for key reversibility/bounds/determinism, and the `fuzz_flow_reconstructor`
  fuzz target.
- **Prohibition:** Strictly forbid packet counters, byte totals, duration, rates,
  inter-arrival metrics, and temporal statistics (Phase 5 scope).

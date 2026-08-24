---
name: dns-detection
description: Use for PcapRaven explainable DNS anomaly and possible tunneling detection over normalized DNS observations.
---

# Explainable DNS Anomaly and Possible Tunneling Detection Skill

This skill governs the design, implementation, review, and verification of explainable DNS anomaly and possible tunneling detectors (`DnsLongQueryNameDetector`, `DnsPossibleTunnelingDetector`) in `pcapraven-detection`.

## Core Responsibilities

- Detect individual long DNS queries and repetitive high-diversity tunneling patterns over normalized DNS observations.
- Implement the `Detector` trait for two detectors:
  1. `DnsLongQueryNameDetector` (`dns.long_query_name`, v1.0.1, policy `Skip`, severity `Info`, confidence `Medium`)
  2. `DnsPossibleTunnelingDetector` (`dns.possible_tunneling`, v1.1.1, policy `Skip`, severity `Low`, confidence `Medium`)
- Compute exact rational `label_octet_diversity_ratio` using fixed `[bool; 256]` memory without floating-point math or Shannon entropy.
- Enforce strict parameter validation (e.g. `minimum_query_observations: 2..=u64::MAX`) and bounded scalar flow aggregation.
- Emit structured `EvidenceDraft`s with factual measurements and threshold comparisons.

## Invariants and Rules

### 1. Label Octet Diversity vs Entropy
- All diversity evaluations MUST use the exact rational formula: `distinct label octets / label length` (`EvidenceRatio`).
- Continuous, approximate, or floating-point entropy (e.g. Shannon entropy, log2) is strictly forbidden.
- Always use the canonical terminology: `label_octet_diversity_ratio` or `label octet diversity`.

### 2. Zero Floats and Exact Arithmetic
- All parameters, ratios, lengths, and counts use exact types (`u128`, `EvidenceRatio`, `EvidenceValue`).
- No floating-point types (`f32`, `f64`) are permitted.

### 3. Canonical Query Classification
- Query observations are filtered strictly with `completeness.is_complete() && message_kind == DnsMessageKind::Query && flags.qr == false`.
- Response messages, non-query kinds, or contradictory records (`qr: true` with `Query` or `qr: false` with `Response`) are ignored.

### 4. Causally Coherent Evidence
- For each question, qualifying labels are those where `label.len() >= minimum_label_length`. Diversity must come from a qualifying label.
- Evidence maxima (`maximum_qname_wire_length`, `maximum_label_length`, `maximum_label_octet_diversity_ratio`) are computed strictly from matching questions. Non-matching questions or short unrelated labels must not inflate causal evidence.

### 5. Flow-Level Bounded State and $O(\log F)$ Lookup
- Flow existence is verified via binary search on `input.flows()` ($O(\log F)$).
- Flow aggregation for tunneling detection uses a finite `BTreeMap<FlowReference, DnsFlowAggregate>` bounded by `maximum_tracked_dns_flows`.
- Exceeding the map capacity returns `DetectorExecutionError::resource_limit(...)`.

### 6. Non-Attribution & Cautious Explanations
- Long or high-diversity DNS queries are common in legitimate infrastructure (CDNs, anti-spam reputation services, DKIM/SPF TXT records, DNSSEC, security scanners).
- Rationales must state factual observations and clearly present benign alternatives without asserting confirmed C2 or malware.

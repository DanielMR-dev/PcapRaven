# DNS Anomaly and Possible Tunneling Detectors

## 1. Overview and Scope

This document defines the analytical contracts, mathematical formulations, configuration parameters, and evidence structures for PcapRaven's Phase 13 DNS heuristic detectors:

1. **Unusually Long DNS Query Name Detector** (`dns.long_query_name`)
2. **Possible DNS Tunneling Pattern Detector** (`dns.possible_tunneling`)

Both detectors interpret normalized DNS protocol observations produced during capture analysis, operating strictly within the Detection Engine architecture (`pcapraven-detection`).

### Non-Attribution Principle

In accordance with PcapRaven's detection model (`docs/DETECTION_MODEL.md`), these heuristics identify factual structural and statistical anomalies. They **never** assert confirmed malware presence, data exfiltration, or Command-and-Control (C2) without external corroboration. Legitimate network operations (CDNs, anti-spam reputation queries, DKIM/SPF TXT lookups, DNSSEC validation, antivirus telemetry, security scanners) routinely utilize long or high-diversity domain names.

---

## 2. Unusually Long DNS Query Name Detector (`dns.long_query_name`)

Flags complete DNS query observations containing questions with domain names or individual labels that exhibit unusually long, high-octet-diversity characteristics.

### 2.1 Contract

- **Detector Identifier:** `dns.long_query_name`
- **Detector Version:** `v1.0.1`
- **Incomplete Data Policy:** `Skip` (skips partial or truncated capture inputs)
- **Target Subject:** Originating DNS observation reference (`FindingSubject { observation_references: [obs.reference()] }`)
- **Severity:** `Info`
- **Confidence:** `Medium`

### 2.2 Parameters

| Parameter Key | Type | Default Value | Valid Range | Description |
| :--- | :--- | :--- | :--- | :--- |
| `minimum_qname_wire_length` | `Unsigned` | `120` | `1..=255` | Threshold for total expanded wire length of the queried domain name. |
| `minimum_label_length` | `Unsigned` | `40` | `1..=63` | Threshold for maximum individual label length within the domain name. |
| `minimum_label_octet_diversity_ratio` | `Ratio` | `1/3` (0.333...) | `0..=1` | Threshold for maximum label octet diversity ratio across qualifying labels. |

### 2.3 Evaluation Logic

1. Filters for complete `ProtocolKind::Dns` observations representing canonical query messages (`completeness.is_complete()` AND `message_kind == DnsMessageKind::Query` AND `flags.qr == false`).
2. Evaluates questions in the message:
   - Computes total expanded wire length ($L_{wire}$).
   - Finds qualifying labels satisfying $\text{label.len()} \ge \text{minimum\_label\_length}$.
   - Computes maximum qualifying label length ($L_{label,qual}$) and maximum qualifying label octet diversity ratio ($R_{div,qual}$).
   - A question matches if $L_{wire} \ge \text{min\_qname} \land L_{label,qual} \ge \text{min\_label} \land R_{div,qual} \ge \text{min\_div}$.
3. Structural evidence metrics ($L_{wire,max}$, $L_{label,max}$, $R_{div,max}$) are derived strictly from questions where $\text{matches} == \text{true}$, ensuring causally coherent evidence.
4. Emits a finding draft containing one `EvidenceKind::ProtocolObservation` record with 5 ordered measurements:
   - `matching_question_count`: `Unsigned` (Count)
   - `maximum_label_length`: `Unsigned` (Bytes) with threshold comparison ($\ge \text{min\_label\_length}$)
   - `maximum_label_octet_diversity_ratio`: `Ratio` with threshold comparison ($\ge \text{min\_diversity}$)
   - `maximum_qname_wire_length`: `Unsigned` (Bytes) with threshold comparison ($\ge \text{min\_qname\_wire\_length}$)
   - `question_count`: `Unsigned` (Count)

---

## 3. Possible DNS Tunneling Pattern Detector (`dns.possible_tunneling`)

Flags reconstructed flows exhibiting repetitive query volume where queries contain long names and high label octet diversity in a significant proportion, characteristic of encoded data exfiltration or bidirectional tunneling channels.

### 3.1 Contract

- **Detector Identifier:** `dns.possible_tunneling`
- **Detector Version:** `v1.1.1`
- **Incomplete Data Policy:** `Skip`
- **Target Subject:** Flow reference (`FindingSubject { flow_references: [flow.reference] }`)
- **Severity:** `Low`
- **Confidence:** `Medium`

### 3.2 Exact Metric: Label Octet Diversity Ratio

To ensure 100% deterministic, float-free, and bounded execution, PcapRaven computes the **Label Octet Diversity Ratio** rather than continuous or approximate entropy formulas.

#### Definition

For a label octet sequence $S = [b_0, b_1, \dots, b_{N-1}]$ of length $N$:

$$\text{label\_octet\_diversity\_ratio}(S) = \frac{|\{b \in S\}|}{N} = \frac{\text{count of distinct byte values in } S}{N}$$

- Computed using a fixed-size `[bool; 256]` bitmap with zero heap allocations.
- Returns an exact rational `EvidenceRatio` reduced to lowest terms via GCD.
- Range: $[1/N, 1/1]$. An empty label returns `0/1`.

### 3.3 Parameters

| Parameter Key | Type | Default Value | Valid Range | Description |
| :--- | :--- | :--- | :--- | :--- |
| `minimum_query_observations` | `Unsigned` | `8` | `2..=u64::MAX` | Minimum eligible complete DNS query observations required within a single flow. |
| `minimum_candidate_query_ratio` | `Ratio` | `3/4` (0.75) | `0 < r <= 1` | Minimum proportion of candidate queries to total queries within the flow. |
| `minimum_qname_wire_length` | `Unsigned` | `120` | `1..=255` | Minimum total wire length for a candidate query question. |
| `minimum_label_length` | `Unsigned` | `40` | `1..=63` | Minimum individual label length for candidate evaluation. |
| `minimum_label_octet_diversity_ratio` | `Ratio` | `1/3` (0.333...) | `0..=1` | Minimum label octet diversity ratio on candidate labels. |
| `maximum_tracked_dns_flows` | `Unsigned` | `65,536` | `1..=1,000,000` | Capacity limit for active tracked DNS flows. |

### 3.4 Evaluation Logic

1. Aggregates DNS query observations per flow in a bounded `BTreeMap<FlowReference, DnsFlowAggregate>`.
2. Evaluates each DNS query observation:
   - Validates canonical query criteria (`completeness.is_complete()` AND `message_kind == DnsMessageKind::Query` AND `flags.qr == false`).
   - Requires directional flow association (`AToB` or `BToA`, excluding `SameEndpoint`, `Unassociated`, `Excluded`).
   - Performs $O(\log F)$ binary search on `input.flows()` to verify flow existence and exclude `AnalysisStopped` flows.
   - Evaluates questions: marks query as candidate if at least one question matches ($L_{wire} \ge \text{min\_qname} \land L_{label,qual} \ge \text{min\_label} \land R_{div,qual} \ge \text{min\_div}$).
   - Flow aggregate structural maxima are updated strictly from matching questions of candidate observations.
3. If `flow_aggregates.len() >= maximum_tracked_dns_flows` when encountering an untracked flow, execution returns `DetectorExecutionError::ResourceLimitExceeded`.
4. After evaluating all observations in the input slice, emits finding drafts for flows satisfying:
   - $\text{dns\_query\_observation\_count} \ge \text{minimum\_query\_observations}$
   - AND $\text{candidate\_query\_count} > 0$
   - AND $\text{candidate\_query\_ratio} = \frac{\text{candidate\_query\_count}}{\text{dns\_query\_observation\_count}} \ge \text{minimum\_candidate\_query\_ratio}$
5. Each finding contains one `EvidenceKind::RatioComparison` record referencing the flow and boundary candidate observations (first and last), with 6 ordered measurements:
   - `candidate_query_count`: `Unsigned` (Count)
   - `candidate_query_ratio`: `Ratio` ($\ge \text{min\_candidate\_ratio}$)
   - `dns_query_observation_count`: `Unsigned` (Count $\ge \text{min\_query\_observations}$)
   - `maximum_label_length`: `Unsigned` (Bytes $\ge \text{min\_label\_length}$)
   - `maximum_label_octet_diversity_ratio`: `Ratio` ($\ge \text{min\_diversity}$)
   - `maximum_qname_wire_length`: `Unsigned` (Bytes $\ge \text{min\_qname\_wire\_length}$)

# Periodic Beaconing Detector (`behavior.periodic_beaconing`)

## 1. Overview and Contract

The **Periodic Beaconing Detector** (`behavior.periodic_beaconing`) evaluates reconstructed flow records to identify directional communication streams exhibiting regular, low-jitter periodic timing patterns.

- **Detector Identifier:** `behavior.periodic_beaconing`
- **Detector Version:** `v1.0.0`
- **Incomplete Data Policy:** `Skip` (does not evaluate truncated or partial captures)
- **Target Subject:** Flow instances (`FindingSubject [flow.reference]`)
- **Default Severity:** `Low`
- **Default Confidence:** `Medium`

### Non-Attribution Principle

Periodic network transmissions occur frequently in benign software architectures, including NTP synchronization, MQTT telemetry, keep-alive heartbeats, metrics pollers, and cloud service health checks.

In accordance with PcapRaven's authoritative detection principles (`docs/DETECTION_MODEL.md`), this detector identifies factual timing regularities. It **never** asserts confirmed malware presence or Command-and-Control (C2) activity without external corroborating evidence.

---

## 2. Eligibility Requirements

A reconstructed flow is eligible for periodic beaconing evaluation if:

1. **Clean Timestamps:** The direction under evaluation contains zero temporal discontinuities (`discontinuity_count == 0`).
2. **Sufficient Samples:** The number of observed inter-arrival interval samples equals or exceeds `minimum_interval_samples` ($N \ge 6$ by default, minimum 3).
3. **Sufficient Mean Interval:** The exact mean inter-arrival duration equals or exceeds `minimum_mean_interval` ($\mu \ge 1\text{s}$ by default).
4. **Availability:** Mean interval, minimum interval, maximum interval, and mean absolute successive difference (jitter) metrics are all available.

---

## 3. Directional Evaluation and Mathematical Invariants

Evaluation is performed **independently** for each direction of traffic:
- **Direction A -> B:** (`a_to_b_inter_arrival`)
- **Direction B -> A:** (`b_to_a_inter_arrival`)

Same-endpoint traffic is not evaluated.

### Zero Floating-Point Arithmetic

All mathematical operations, ratios, and comparisons are performed using **exact rational arithmetic** (`FlowDuration` and `EvidenceRatio`) with checked unsigned 128-bit operations. Floating-point numbers (`f32`, `f64`) are strictly prohibited across the evaluation pipeline.

### Exact Rational Formulas

Let:
- $\mu = N_\mu / D_\mu$ be the exact mean inter-arrival duration (`FlowDuration`).
- $\delta_{MAD} = N_\delta / D_\delta$ be the mean absolute successive interval difference (`FlowDuration`).
- $\text{min} = N_{min} / D_{min}$ and $\text{max} = N_{max} / D_{max}$ be the minimum and maximum observed intervals.
- $\text{spread} = \text{max} - \text{min} = N_s / D_s$ (`FlowDuration`).
- $J_{max} = N_j / D_j$ be the configured `maximum_jitter_ratio` (`EvidenceRatio`).
- $S_{max} = N_s / D_s$ be the configured `maximum_spread_ratio` (`EvidenceRatio`).

#### 1. Jitter Condition

$$\frac{\delta_{MAD}}{\mu} \le J_{max} \iff \frac{N_\delta \cdot D_\mu}{D_\delta \cdot N_\mu} \le \frac{N_j}{D_j}$$

Cross-multiplication with checked integer multiplication:

$$(N_\delta \cdot D_\mu) \cdot D_j \le (D_\delta \cdot N_\mu) \cdot N_j$$

#### 2. Spread Condition

$$\frac{\text{spread}}{\mu} \le S_{max} \iff \frac{N_s \cdot D_\mu}{D_s \cdot N_\mu} \le \frac{N_s}{D_s}$$

Cross-multiplication with checked integer multiplication:

$$(N_s \cdot D_\mu) \cdot D_{smax} \le (D_s \cdot N_\mu) \cdot N_{smax}$$

---

## 4. Configuration Parameters

Detectors accept the following parameters via `DetectorParameters`:

| Parameter Key | Type | Default Value | Valid Range | Description |
| :--- | :--- | :--- | :--- | :--- |
| `minimum_interval_samples` | `Unsigned` | `6` | `3..=u64::MAX` | Minimum inter-arrival samples required for evaluation. |
| `maximum_jitter_ratio` | `Ratio` | `1/10` (10%) | `0..=1` | Maximum allowable ratio of mean jitter to mean interval. |
| `maximum_spread_ratio` | `Ratio` | `1/4` (25%) | `0..=1` | Maximum allowable ratio of interval spread to mean interval. |
| `minimum_mean_interval` | `Duration` | `1s` | `> 0s` | Minimum required mean inter-arrival duration. |

---

## 5. Finding and Evidence Structure

When a flow satisfies the statistical criteria in one or both directions:

1. **Finding Draft:**
   - **Subject:** `FindingSubject` referencing the single matching flow (`[flow.reference]`).
   - **Title:** `"Possible periodic beaconing behavior"`
   - **Summary:** `"Observed highly regular directional packet timing intervals consistent with possible periodic beaconing"`
   - **Rationale:** Explains the observed statistical regularity, provides context on common benign causes (application keepalives, health checks, monitoring agents, scheduled polling, heartbeat traffic), and cautions against unsupported attribution.
   - **Severity:** `Severity::Low`
   - **Confidence:** `Confidence::Medium`

2. **Evidence Drafts (1 or 2 per finding):**
   - **Kind:** `EvidenceKind::TemporalMetric`
   - **Description:** `"A-to-B periodic inter-arrival timing metrics"` (or `"B-to-A periodic inter-arrival timing metrics"`)
   - **References:** Flow reference of the subject flow.
   - **Measurements (strictly ordered by metric key):**
     1. `discontinuity_count`: `EvidenceValue::Unsigned(0)` (Count)
     2. `interval_sample_count`: `EvidenceValue::Unsigned` (Count $\ge N_{min}$)
     3. `maximum_interval`: `EvidenceValue::Duration` (Seconds)
     4. `mean_absolute_successive_interval_delta`: `EvidenceValue::Duration` (Seconds)
     5. `mean_interval`: `EvidenceValue::Duration` (Seconds $\ge \mu_{min}$)
     6. `minimum_interval`: `EvidenceValue::Duration` (Seconds)
     7. `relative_jitter_ratio`: `EvidenceValue::Ratio` (Ratio $\le J_{max}$)
     8. `spread_ratio`: `EvidenceValue::Ratio` (Ratio $\le S_{max}$)
     9. `successive_delta_sample_count`: `EvidenceValue::Unsigned` (Count)

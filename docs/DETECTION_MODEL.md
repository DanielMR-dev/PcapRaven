# Detection Model

## Purpose and Status

This document defines the target contract for detectors and findings. No
detector or detection engine exists in Phase 0.

## Separation from Parsing

Capture and protocol parsers create normalized domain records and diagnostics.
They do not assign threat meaning, severity, confidence, or MITRE ATT&CK
mappings. Detectors consume normalized observations, flows, statistics, and
capture completeness metadata. Detectors never parse external packet bytes.

This separation allows parsers to be tested for factual correctness and
detectors to be tested against synthetic domain inputs without requiring raw
captures for every rule.

## Detector Contract

Each detector has a stable namespaced identifier, an independently versioned
logic version, a concise purpose, declared input requirements, tunable
parameters with validated bounds, and deterministic output behavior. A
detector must:

- Consume only normalized domain information.
- State minimum data and sample requirements.
- Define measurements, thresholds, and edge-case behavior.
- Account for incomplete or unreliable input.
- Produce zero or more valid findings without mutating inputs.
- Attach sufficient evidence for an analyst to reproduce the rationale.
- Use cautious language proportional to the evidence.
- Avoid hidden external enrichment or network access.

Detector identifiers remain stable when implementation changes. A semantic
logic change increments the detector version so results remain explainable.

## Finding Requirements

Every finding must answer:

1. What possible or suspicious behavior was detected?
2. Which detector and detector version produced it?
3. Why did the detector produce it?
4. What structured evidence supports it?
5. Which flows, observations, and packets are involved?
6. What is its severity?
7. What is its confidence?
8. Which MITRE ATT&CK mappings apply, if any?

A finding without sufficient evidence is invalid and must not be emitted. A
finding may explicitly state that no MITRE mapping applies; mappings are not
added merely to make output appear comprehensive.

## Severity

Severity expresses the potential security impact if the interpretation is
correct. It does not express certainty.

| Value | Meaning |
| --- | --- |
| `info` | Context or weakly security-relevant behavior useful for investigation. |
| `low` | Limited potential impact or an early indicator that merits context. |
| `medium` | Meaningful suspicious behavior with plausible security relevance. |
| `high` | Potentially serious behavior that warrants prompt investigation. |
| `critical` | Potential for exceptional impact requiring urgent attention if confirmed. |

The ordering is `info < low < medium < high < critical`. Detector documentation
must explain its assigned severity and avoid inflating severity based on
confidence.

## Confidence

Confidence expresses how strongly the available evidence supports the
detector's interpretation. It does not express impact.

| Value | Meaning |
| --- | --- |
| `low` | Evidence is limited, ambiguous, or substantially affected by missing context. |
| `medium` | Multiple or reasonably specific observations support the interpretation, with plausible alternatives. |
| `high` | Strong, specific, and internally consistent evidence supports the interpretation, while still remaining heuristic unless the rule is definitive by design. |

The ordering is `low < medium < high`. A high-severity, low-confidence finding
and a low-severity, high-confidence finding are both valid combinations.

## Language and Certainty

PcapRaven describes heuristic results as "possible," "potential," or
"suspicious" behavior. Periodicity, unusual DNS characteristics, or
connection patterns alone do not prove malware or command-and-control. Findings
must state credible benign alternatives where they materially affect
interpretation.

Detector names and summaries must not use categorical claims such as "malware
detected" or "confirmed C2" unless a future non-heuristic detector has evidence
that actually establishes that fact and the model is formally revised.

## Evidence and Rationale

Evidence follows [the domain evidence model](DOMAIN_MODEL.md#evidence-model).
A detector records the measurements it used, including sample count, duration,
threshold, observed value, and relevant direction where applicable. The
rationale connects those facts to the detector rule in plain language.

For example, a future periodicity finding would identify the flow, packet time
series or derived intervals, sample count, regularity statistic, configured
threshold, capture gaps, and the exact comparison that matched. It would not
merely state "beaconing detected."

## Incomplete Data

Detectors must declare whether they can operate on truncated or partial data.
They may suppress a finding, reduce confidence according to a documented rule,
or emit a finding with an explicit limitation. They must not silently treat
missing values as zero, absence, or normal behavior.

Parser diagnostics are contextual input, not automatic security evidence.
Resource limits that omit required samples must be reflected in completion
state and detector behavior.

## Finding Identity, Ordering, and Deduplication

Finding identity is deterministic for the same tool version, configuration,
and normalized input. It is derived from stable detector and subject identity,
not processing order or randomized hashes. Exact encoding is deferred until
the detection engine and report schemas are designed.

Detectors define a subject and deduplication scope. Duplicate evidence is
collapsed without losing distinct affected references. Findings are ordered by
stable detector identifier and subject/evidence keys after any explicit
severity ordering required by a report. Concurrency must not alter results.

## MITRE ATT&CK Mappings

A mapping includes a valid technique or sub-technique identifier, name, and a
short explanation of why the observed behavior is relevant. It describes an
analytical relationship, not attribution or confirmation that the technique
occurred. Mapping versions or knowledge-base context must be recorded when the
schema is finalized so mappings can be audited over time.

## Target Detector Families

Later roadmap phases plan only these initial families:

- Periodic beaconing heuristics over flow temporal metrics.
- DNS anomaly and possible tunneling heuristics over normalized DNS and flow
  information.
- Connection and C2-like behavioral heuristics over normalized communication
  patterns.

These are roadmap intentions, not implemented capabilities or guaranteed
findings. Each detector requires its own specification, tests, threshold
rationale, and false-positive analysis before release.

## Filtering

Severity and confidence filtering occurs over emitted findings using the two
independent orderings above. Filtering changes presentation/result selection,
not the detector's assigned values or evidence. Reports should retain enough
metadata to make active filters visible.

## Validation Expectations

Future detector tests must cover matches, non-matches, threshold boundaries,
insufficient samples, incomplete captures, deterministic identity/order,
deduplication, and calibrated language. Golden tests should ensure every
finding answers all eight required questions.

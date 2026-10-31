# WP7 statistical reporting and UWF analysis specification (COSE-D-26-04000)

Version 1.0, 15 September 2026.

- **Scope.** It implements protocol v1.1 §10–§11 for the evidence produced in WP4 (static) and WP5 (replay).
- **Status of the tests.** The primary comparison family was prespecified in protocol v1.1 before any comparative result and is kept intact. Every other test named here was specified **after** the WP4/WP5 results were seen. Those tests are labelled exploratory, post hoc and unadjusted, and they cannot replace or reinterpret the primary family.
- **NF-UQ.** It is absent (WP6 deferred under D3), so the NF-UQ domain units of §11 do not occur.

## 1. Units and replicates

- **Unit.** The AIT reporting and inferential unit is the held-out scenario (n = 8).
- **Not replicates:**
  - critical intervals (32);
  - alerts;
  - top-k positions;
  - tie seeds;
  - grid points;
  - identifier hold-out groups (5 per scenario);
  - forward-chaining folds;
  - replay rates;
  - individual replays (1,616).
- **Hold-out and forward chaining.** Identifier hold-out results are reported per scenario × group but summarized per scenario. Forward chaining has 5 eligible test scenarios and is descriptive only.
- **Dependence.** Training folds overlap, so every p-value is a conditional consistency analysis over these eight scenarios, not deployment inference. No bootstrap over scenarios, alerts or telemetry rows is used.

## 2. Descriptive summaries (always reported, independently of p-values)

For each ranker and metric:
- **Per-scenario values** for every unit.
- **Macro mean:** the mean over scenarios of per-scenario values or ratios.
- **Pooled total or pooled percentage:** Σ numerator / Σ denominator over scenarios, labelled "pooled".
- **Median and range over scenarios.**
- **Paired differences** against the named comparator: per scenario, with mean, median and range, and the numbers of positive, negative and zero differences.

**Naming denominators.**
- Coverage@100: covered intervals out of 4 per scenario (32 pooled).
- FP@100: out of 100 positions per scenario (800 pooled).
- Replay FP investigations: out of the investigations of that scenario and rate. At 12 alerts/hour these total 11,508 over the eight scenarios **for each full-stream ranker**; the per-scenario counts (1,148–1,727) depend on horizon length.
- Critical recall: out of the scenario's critical alerts (9,204 pooled).

## 3. Primary comparison family (protocol v1.1 §11; unchanged)

- **Six paired comparisons.** The S1 selection (primary rule) against the A selection, the M selection and P, each on critical-step interval coverage@100 (eligible intervals) and on FP@100. Static R1 evaluation under the declared order.
- **Difference.** S1 minus comparator, per scenario.
- **Test.** Exact two-sided paired sign-flip randomisation test on the mean difference. It enumerates all 2⁸ = 256 sign patterns, counts patterns with |mean| ≥ |observed mean| (numerical tolerance 1e-12), and keeps zero differences in the enumeration. All-zero differences give p = 1.
- **Multiplicity.** Holm adjustment across the six tests, with family-wise α = 0.05.
- **Attainable p.** The smallest attainable two-sided p is 2/256 = 0.0078. It lies below the first Holm threshold (0.05/6 = 0.0083) only when all eight scenario differences share one sign and the enumeration has no ties at the observed magnitude. This is stated with the results.
- **Assumption.** Exchangeability of difference signs under the null of no paired effect; limited by overlapping training folds (§1).

## 4. Exploratory tests (post hoc, unadjusted)

Specified after the WP4/WP5 results, to describe the identifier-level contrasts that the results made central. They are reported with unadjusted p and the same procedure and limitations. No family-wise claim is made from them.

| ID | Contrast (difference = first − second) | Metrics |
| --- | --- | --- |
| X1 | S1_key selection (primary rule) − S1 selection (primary rule) | static coverage@100 (covered intervals), static FP@100, replay covered intervals at 12/h, replay FP investigations at 12/h |
| X2 | S0_key (κ = 1) − P | same four |
| X3 | R_severity_key (c·ĥ_key) − P | same four |

## 5. Delay, censoring and alert-level retrieval (replay)

At 12 alerts/hour (and the three sensitivity rates in supplementary tables), for P, S1, S0_key, S1_key, R_severity_key, O_severity and FIFO, per scenario:

- **Coverage and delay, always together:**
  - intervals covered, and intervals never investigated (censored at the horizon);
  - median delay among covered intervals;
  - restricted mean delay with censored intervals set to their censoring time, labelled a lower bound.
- **Alert level:**
  - critical alerts, critical alerts investigated, starved critical alerts and the starved share;
  - critical recall within 1, 4 and 24 hours over all critical alerts;
  - the share of investigated critical alerts that were investigated within 24 hours, labelled as conditional on investigation.
- **FP burden:** false-positive investigations and interval-positive investigations.
- **Reading rule.** No statement about fast investigation may be made without the number of intervals and critical alerts left uninvestigated beside it.

## 6. Null-result language

- **"No observed advantage"** is used when paired differences are zero in every scenario or inconsistent in sign, and the primary family shows no Holm-adjusted difference.
- **Equivalence.** Statistical equivalence, non-inferiority or "comparable performance" as a claim would require a separately justified equivalence margin and analysis. Neither was declared, so no such claim is made.
- **Exploratory p-values** are never described as confirming an effect.
- **Capacity.** Weak replay capacity response is described as limited sensitivity within the tested overload regime, not as robustness to analyst capacity.

## 7. UWF supporting analysis (protocol v1.1 §10)

- **Name and role.** "ATT&CK mapping coverage and crosswalk consistency", supporting only. UWF-ZeekData24 supplies tactic and technique labels and frequencies, not an independent severity or impact reference. Both severity tables compared are author-defined (`configs/severity_mapping.yaml`):
  1. `mitre_tactic_severity`;
  2. the AIT phase severities projected onto tactics through the author's `ait_phase_to_mitre_tactic` crosswalk, using the maximum over mapped phases (the historical definition); the mean is shown as a sensitivity.
- **Inputs.** The verified local copy `~/soc_revision_data/uwf_zeekdata24/csv` (8 files), with SHA-256 recorded.
- **Tables:**
  - rows per file;
  - attack and benign rows;
  - tactic label mapping coverage;
  - technique and CVE coverage;
  - all seven observed attack tactics with row frequencies and shares;
  - both severity assignments;
  - the five overlapping tactics;
  - exact disagreements (tactic-table severity minus crosswalk severity);
  - techniques per tactic.
- **Statistics** (five overlapping tactics):
  - Spearman and Kendall τ-b, unweighted;
  - mean absolute discrepancy, both unweighted and weighted by UWF row frequency;
  - Jaccard similarity of the tactic sets with severity ≥ θ, for θ ∈ {7.5, 8.0, 8.5}. The inclusive rule is ≥, and ties at θ are included; each set is listed;
  - leave-one-tactic-out influence on Spearman, Kendall, weighted discrepancy and Jaccard at θ = 8.0.
- **Duplicate-row check.**
  - Exact duplicates of full rows within and across tactic files.
  - Duplicates of connection identity (uid; community_id with ts) across tactic files, particularly the three 326-row tactics.
  - Rows whose technique, binary or CVE label field reads "Duplicate".
- **No bootstrap over telemetry rows.** No claim of independent severity validation. With five tactics, correlations are fragile, and the influence analysis is shown for that reason.

## 8. Artifact inventory

`artifact_inventory.md` accounts for:
- every run and replay;
- configuration and registry identity;
- eligibility restrictions;
- reporting denominators;
- output locations and hashes;
- analyses **not** performed. These include the replay of duplicate suppression, identifier hold-out, forward chaining and ablations; the §6.2 expanded vector; WP6; and an expert study.

# WP4 stage 2: run and reporting specification (COSE-D-26-04000)

Version 1.0, 14 September 2026. **Declared before any comparative AIT result was produced.** Stage 2 runs only after [metric_verification.json](../wp3/metric_verification.json) and [fitting_boundary_verification.json](fitting_boundary_verification.json) are both verified and not stale.

This document fixes the runs, outer candidates, diagnostics, subsets, derived definitions and table layouts that stage 2 reports. Implementation: `scripts/revision/wp4_stage2_run.py` (gated runs and per-fold evaluations) and `scripts/revision/wp4_stage2_tables.py` (tables). Both were exercised end to end on synthetic data before any AIT run, and their hashes are recorded in each run manifest. The protocol v1.1 rules, the metric contract v1.1 and the frozen registry (157 candidates, SHA-256 `e2f088ed…cb23a`) are used unchanged.

**No change in response to results.**
- Grids, selection rules, runs, diagnostics and definitions below are not changed after any stage-2 result is seen.
- A defect found afterwards may be corrected only if it contradicts this specification, the metric contract or the fitting specification. Such a correction is logged in the protocol change log with "revised results seen: yes", and both the uncorrected and corrected outputs are kept.
- Anything not declared here is labelled exploratory.

## 1. Runs

All runs use the nested pipeline (`ComparisonPipeline.run_outer_fold`) and all 157 candidates. Every executed fold's trace is verified with `verify_fold_trace`; a failed verification stops the run.

| Run | Splits | Input policy | Role |
| --- | --- | --- | --- |
| R1 | LOSO, 8 folds | primary: flat + table, detector_class | **primary comparison** (both selection rules recorded; primary rule is the headline) |
| R2 | LOSO | secondary: asset_profile + ambiguity_aware | prespecified secondary policy (selected after held-out inspection in the original study) |
| R3 | LOSO | flat + table with reliability global_class, detector_only, native_key, none (4 runs) | calibration ablation (detector_class is R1) |
| R4 | LOSO | flat with uncertainty constant_0.5, purity_only, precision_only, ambiguity_aware ("historical combined"), zero (5 runs) | uncertainty ablation (table is R1) |
| R5 | LOSO | asset_profile + table | context ablation (flat is R1) |
| R6 | LOSO × identifier groups 0–4 (40 folds) | primary | strict identifier hold-out |
| R7 | forward chaining: russellmitchell, shaw, wheeler, wilson, harrison | primary | no future scenario content in fitting |

- **Order.** R1 is run and evaluated first, then R2–R7. No run is skipped or re-parameterized because of an earlier run's result.
- **Failures.** Fit failures, fallbacks, NA metrics and empty sets are recorded with counts. A fold is never dropped.

## 2. Outer candidates per fold

- The 12 untuned references.
- The candidate chosen by the **primary rule** in each of the 10 tuned families: W, A, M, C, L1, L2, S1, S2, S1_key, S2_key.
- The candidate chosen by the **secondary (NDCG) rule** in each tuned family, where different.

Tables are labelled by family and rule. The selected candidate_id, its inner macro values, the counts remaining after each selection step, and fallback flags are reported for every fold.

## 3. Evaluations

Notation: n is the held-out queue length, and K = {10, 25, 50, 100, 250, 500, 1000}.

| ID | Evaluation | Runs and candidates |
| --- | --- | --- |
| E1 | Full static queue report (metric contract §5–6): every budget in K and every queue fraction; efforts to 50/80/90% critical recall and to 50/80/100% interval coverage; first critical rank; covered, eligible and defined interval counts | all runs, all outer candidates |
| E2 | Tie diagnostics (contract §7.1) at every k in K, and exact expectations under random within-block order (FP, precision, attack and critical recall, NDCG) at every k in K | all runs, all outer candidates |
| E3 | Seeded within-block permutations, seeds 0–99, at every k in K: median, 2.5 and 97.5 percentiles, minimum and maximum of FP, critical recall, attack recall, eligible and all-defined coverage, NDCG and first critical rank. Also the per-seed covered-interval counts at k = 100 | R1 and R2, all outer candidates (not run for R3–R7) |
| E4 | Near ties: queue metrics at every k in K with scores rounded to 4 significant digits (contract §7.3) | R1 and R2, all outer candidates |
| E5 | Within-detector queues for Wazuh and Suricata (contract §9); native references additionally within each Suricata record type; score availability of both native references by detector and record type | R1, all outer candidates |
| E6 | Duplicate units representative_own and static_cluster at 60, 300 and 900 s, all k in K, with mixed-label and member-conferred cluster counts (contract §10) | R1, all outer candidates |
| E7 | Subgroups, each both **in the mixed queue** (`subgroup_in_mixed_queue`) and **ranked within the subgroup** (`restrict_queue`), at every k in K (contract §9a) | R1: mapped vs unmapped alerts (fold's outer mapping), unseen vs seen identifiers. R6: held-out-group identifiers vs the rest |
| E8 | Critical-alert deferral audit (Section 4) | all runs |
| E9 | Calibration diagnostics (Section 5) | R1 and R3 |
| E10 | Ranking agreement with R1 (Section 5), and recall and coverage curves | R3, R4, R5 |
| E11 | Context token audit: held-out alerts whose asset factor q ≠ 1, split by whether host/IP fields or native key/category fields supply the matching token (label-free) | R5 |
| E12 | Selection and execution records: selections, inner macro values, fallback flags, learned fallbacks, fit-record fallback counts, trace verification, runtime | all runs |

## 4. Critical-alert deferral audit (protocol §7.8)

- **Coefficients.** γ = 1 + κ·u·ln h for S0 (κ = 1) and for the primary-rule-selected S1. The `_key` variants use h_key, and S2 uses γ = h^(κ·u).
- **Coefficient counts.** Counts and fractions of held-out alerts with γ ≤ 0 and with γ ≤ 0.1, by scenario, detector, mapping status and z.
- **Deep deferral.** A critical alert (z = 1) is deep-deferred under a candidate if its rank exceeds ⌈n/2⌉. For each fold, report the deep-deferred count and share and the queue-fraction percentiles (10, 50, 90) of critical-alert ranks. Candidates: untuned P, H, S0 and O_severity, plus the primary-rule selections of W, A, S1 and S2.
- **Causes.** For every deep-deferred critical alert, each cause below is recorded; several can apply, and counts are by candidate and fold:
  1. **Mapping rejection.** The key is unmapped in the fold's M(S). Which thresholds failed (support < 5, positives < 3, precision < 0.5, purity < 0.7, or no positives) comes from the fold's fit record.
  2. **Low reliability.** The key is mapped and its class height is ≤ 0.2. Whether the height was clipped at 0.05 and its fallback code are also recorded.
  3. **Severity reversal.** γ ≤ 0 (S0 and S1 family only).
  4. **Tie-rule displacement.** The alert belongs to a score block that crosses the ⌈n/2⌉ cutoff.
  5. **Recurring benign signatures ahead.** The share of the first ⌈n/2⌉ positions held by interval-labeled negatives from keys with training precision < 0.5 and training support ≥ 1,000 (fold's fit record). This is reported as a fold-level share per candidate, alongside the deep-deferred counts.

## 5. Calibration and ranking agreement

- **Target.** h estimates P(interval-labeled positive | detector, class). It is evaluated against held-out y only; this is not verified maliciousness.
- **Brier score.** Mean (h − y)² over held-out alerts, per fold and variant; h = 1 under `none`.
- **Reliability diagram.** Ten equal-width bins [0, 0.1), …, [0.9, 1.0], with h = 1.0 in the last bin. Each bin reports alert count, mean h and observed y share.
- **Heights.** Per class and per key height tables with fallback codes (from the fit records).
- **Mapping coverage.** The share of held-out alerts mapped to a class, reported separately from every calibration quantity.
- **Ranking agreement** with R1, on the held-out queue, per fold. Candidates: primary-rule selections of every tuned family plus untuned P, H and S0.
  - Spearman correlation of scores (average ranks for ties; NA if either score is constant).
  - Top-100 overlap: |top-100 of the variant ∩ top-100 of R1| / 100 under the declared order.
- **Recall and coverage curves.** Critical recall, attack recall and all-defined interval coverage at the ranks unique(⌈logspace(0, log10 n, 200)⌉) ∪ K ∪ {n}.

## 6. Tables

Scenarios are the inferential units. No alert-level pooled significance test is reported, and paired tests are WP7.

- **T1, primary endpoint** (R1, primary rule). One row per outer candidate.
  - For each of the 8 scenarios: covered critical intervals out of the scenario's defined intervals (4 on AIT, all containing alerts), and FP@100.
  - Summary columns: number of scenarios at each covered count 0–4; macro coverage (steps of 1/32); median and range of FP@100.
  - Primary coverage changes only in 25-percentage-point steps per scenario, and the table states this.
- **T2, ties** (R1, primary rule), placed beside T1 in the main comparison with the same rows and scenarios.
  - At k = 100: top-100 positions decided by the tie rule (`order_share`), whether the cutoff block crosses k, and the cutoff block size.
  - Per-scenario 2.5–97.5 percentile and min–max range of covered intervals over seeds 0–99.
  - Exact expected FP@100.
  - Near-tie coverage and FP at k = 100.
- **T3, deep queue** (R1). Alert-level critical recall at k = 100 and 1,000, efforts to 50/80/90% critical recall (queue fraction), and first critical rank, per scenario.
- **T4, failures and NA.** Fit failures, fallback counts, learned-model fallbacks, NA metric counts, empty eligible sets, and selection fallback flags, for every run.
- **T5, deferral.** Section 4.
- **Secondary tables.**
  - R1 under the secondary selection rule; R2.
  - R3–R5 with E9 and E10.
  - R6 and R7 in the T1/T2 layout (hold-out adds held-out-group subgroup columns).
  - E5 within-detector, E6 duplicates and E7 subgroups.

## 7. Language

- **Coverage.** "Covered critical-step interval" means an alert in the top k lies inside that interval; it does not mean the attack step was identified.
- **Heights.** They are interval-label frequencies.
- **Unseen identifiers.** LOSO unseen-identifier subgroups are nearly empty on AIT (at most 99 alerts per fold); statements about new identifiers rest on R6.
- **Superiority.** No superiority statement is made from WP4 tables alone (protocol §12).

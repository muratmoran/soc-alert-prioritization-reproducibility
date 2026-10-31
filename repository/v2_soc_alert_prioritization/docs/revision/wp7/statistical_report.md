# WP7 statistical reporting and UWF supporting analysis (COSE-D-26-04000)

15 September 2026. Produced under [analysis_specification.md](analysis_specification.md).

- **Sources.** Numbers come from `scripts/revision/wp7_statistics.py`, `wp7_uwf_crosswalk.py` and `wp7_artifact_inventory.py`. The inputs are the hash-checked WP4 stage-2 tables and WP5 replay outputs ([wp7_manifest.json](wp7_manifest.json)).
- **NF-UQ.** Not reported (WP6 deferred).

## 1. Units, procedure and limitations

- **Unit.** Every AIT statistic below uses the held-out scenario (n = 8) as the unit. Intervals, alerts, investigations, tie seeds, grid points, hold-out groups, rates and replays are not replicates.
- **Procedure.** Exact two-sided paired sign-flip randomisation test on the mean per-scenario difference, enumerating all 256 sign patterns, with zero differences retained.
  - The primary family uses Holm adjustment across its six tests.
  - The smallest attainable p is 2/256 = 0.0078, which is below the first Holm threshold (0.0083) only when all eight differences share a sign.
- **Limitations.**
  - Training folds overlap, so p-values are conditional consistency analyses over these eight scenarios, not deployment inference.
  - Eight scenarios from one testbed family cannot establish generalization.
  - No bootstrap is used.
  - No equivalence margin was declared, so absence of a difference is not evidence of equivalence.

## 2. Primary comparison family (prespecified, unchanged)

Static R1 evaluation, k = 100. Differences are the S1 selection minus the comparator.

| Test | Metric | S1 macro mean | Comparator macro mean | Mean difference | + / − / 0 scenarios | Exact p | Holm p |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: |
| S1 − A | coverage@100 | 0.25 | 0.25 | 0 | 0 / 0 / 8 | 1.00 | 1.00 |
| S1 − A | FP@100 | 29.75 | 29.00 | +0.75 | 2 / 1 / 5 | 0.75 | 1.00 |
| S1 − M | coverage@100 | 0.25 | 0.25 | 0 | 0 / 0 / 8 | 1.00 | 1.00 |
| S1 − M | FP@100 | 29.75 | 30.00 | −0.25 | 0 / 1 / 7 | 1.00 | 1.00 |
| S1 − P | coverage@100 | 0.25 | 0.25 | 0 | 0 / 0 / 8 | 1.00 | 1.00 |
| S1 − P | FP@100 | 29.75 | 29.75 | 0 | 0 / 0 / 8 | 1.00 | 1.00 |

- **Reading.** The constrained class-level SGFN selection shows **no observed advantage** over the tuned additive, tuned multiplicative or probability-proxy scores in these eight scenarios.
  - Its coverage@100 is identical in every scenario.
  - Its FP@100 differs from A in three scenarios (by 2–6 positions, in both directions) and from M in one (2 positions); it is identical to P.
- **Not claimed.** This is not a claim of statistical equivalence.

## 3. Exploratory contrasts (post hoc, unadjusted)

These were specified after the WP4/WP5 results, to describe the identifier-level findings. Each p-value is unadjusted and confirms nothing.

| ID | Contrast | Outcome | First macro mean | Second macro mean | Mean difference (range) | + / − / 0 | Exact p (unadjusted) |
| --- | --- | --- | ---: | ---: | --- | --- | ---: |
| X1 | S1_key − S1 | static covered intervals@100 | 2.63 | 1.00 | +1.63 (0 to +2) | 7 / 0 / 1 | 0.016 |
| X1 | S1_key − S1 | static FP@100 | 74.6 | 29.8 | +44.9 | 7 / 1 / 0 | 0.016 |
| X1 | S1_key − S1 | replay covered intervals (12/h) | 3.75 | 1.63 | +2.13 (+1 to +3) | 8 / 0 / 0 | 0.008 |
| X1 | S1_key − S1 | replay FP investigations (12/h) | 1,376.6 | 1,160.6 | +216.0 (+93 to +378) | 8 / 0 / 0 | 0.008 |
| X2 | S0_key − P | static covered intervals@100 | 2.63 | 1.00 | +1.63 | 7 / 0 / 1 | 0.016 |
| X2 | S0_key − P | static FP@100 | 77.6 | 29.8 | +47.9 | 7 / 1 / 0 | 0.016 |
| X2 | S0_key − P | replay covered intervals (12/h) | 3.50 | 1.63 | +1.88 (+1 to +2) | 8 / 0 / 0 | 0.008 |
| X2 | S0_key − P | replay FP investigations (12/h) | 1,168.1 | 1,160.6 | +7.5 (−7 to +45) | 5 / 2 / 1 | 0.19 |
| X3 | R_severity_key − P | static covered intervals@100 | 2.25 | 1.00 | +1.25 | 6 / 0 / 2 | 0.031 |
| X3 | R_severity_key − P | static FP@100 | 76.5 | 29.8 | +46.8 | 7 / 1 / 0 | 0.016 |
| X3 | R_severity_key − P | replay covered intervals (12/h) | 3.13 | 1.63 | +1.50 (0 to +2) | 7 / 0 / 1 | 0.016 |
| X3 | R_severity_key − P | replay FP investigations (12/h) | 1,163.5 | 1,160.6 | +2.9 (−8 to +28) | 3 / 2 / 3 | 0.69 |

Per-scenario differences are in [per_scenario_effects.csv](per_scenario_effects.csv) and [figures/paired_effects_exploratory.pdf](figures/paired_effects_exploratory.pdf).

**Consistent patterns** (descriptive; the p-values are exploratory):
- **Coverage.** Identifier-level variants cover more critical intervals than the corresponding class-level scores, statically and in overloaded replay, in every or nearly every scenario.
- **FP burden, static.** In the static top 100 they carry about 45–48 more FPs per scenario.
- **FP burden, replay.** It depends on the formula:
  - S1_key makes more FP investigations than S1 in all eight scenarios (+216 per scenario).
  - S0_key and the simpler severity–precision score R_severity_key make FP investigations close to P's, with small differences in both directions.
- **Conclusion.** Identifier-level methods are therefore not interchangeable.

## 4. Descriptive summaries: macro, pooled and median

Values are for the primary static evaluation (k = 100) and the primary replay (P1, 12 alerts/hour); all rankers and rates are in [descriptives.csv](descriptives.csv).

- **Macro mean:** the mean over scenarios of each scenario's ratio.
- **Pooled:** Σ numerator / Σ denominator.
- **Median:** over scenarios.

| Ranker | Static coverage@100: pooled (covered/32), macro, median | Static FP@100: pooled (count/800), median, range | Replay coverage: pooled, median | Replay FP investigations: pooled share (count/11,508), median share | Replay critical recall by horizon: pooled (count/9,204), macro, median |
| --- | --- | --- | --- | --- | --- |
| P, S1 | 8/32; 0.25; 0.25 | 238/800; 18; 8–95 | 13/32; 0.50 | 0.807 (9,285); 0.827 | 0.0058 (53); 0.025; 0.009 |
| A | 8/32; 0.25; 0.25 | 232/800; 17; 8–97 | 13/32; 0.50 | 0.807 (9,285); 0.827 | 0.0055 (51); 0.022; 0.009 |
| M | 8/32; 0.25; 0.25 | 240/800; 18; 8–97 | 13/32; 0.50 | 0.807 (9,285); 0.827 | 0.0055 (51); 0.022; 0.009 |
| S0_key | 21/32; 0.66; 0.75 | 621/800; 77; 61–90 | 28/32; 0.875 | 0.812 (9,345); 0.830 | 0.0192 (177); 0.075; 0.029 |
| R_severity_key | 18/32; 0.56; 0.625 | 612/800; 77.5; 53–90 | 25/32; 0.875 | 0.809 (9,308); 0.827 | 0.0117 (108); 0.042; 0.022 |
| S1_key | 21/32; 0.66; 0.75 | 597/800; 77; 50–90 | 30/32; 1.00 | 0.957 (11,013); 0.958 | 0.0280 (258); 0.097; 0.047 |
| O_severity | 8/32; 0.25; 0.25 | 771/800; 96.5; 95–97 | 8/32; 0.25 | 0.998 (11,479); 0.997 | 0.0032 (29); 0.013; 0.005 |
| FIFO | 0/32; 0; 0 | 800/800; 100; 100 | 0/32; 0 | 1.000 (11,508); 1.000 | 0 (0); 0; 0 |

- **Macro, pooled and median differ.** Critical recall shows this clearly. For S1_key, the macro mean (0.097) is more than three times the pooled value (0.028). Small scenarios such as wardbeck (85 critical alerts) weigh equally in the macro mean, whereas harrison (3,385) and wilson (2,956) dominate the pooled total.
- **The replay denominator of 11,508 investigations** is the eight-scenario total **for each full-stream ranker**. Every ranker makes the same number of investigations per scenario (1,148–1,727, depending on horizon length), because the analyst idles only when nothing is waiting.

## 5. Coverage, delay and uninvestigated work together

Primary replay (P1, 12 alerts/hour); per scenario rows are in [delay_censoring.csv](delay_censoring.csv).

| Ranker | Intervals covered / never investigated (of 32) | Median delay of covered intervals (median over scenarios, h) | Restricted mean delay, censored at horizon (median over scenarios, lower bound, h) | Critical alerts investigated / starved (of 9,204) | Investigated critical alerts started within 24 h of arrival |
| --- | --- | ---: | ---: | --- | --- |
| S1_key | 30 / 2 | 0.43 | 0.69 | 258 / 8,946 | all (100% in every scenario) |
| S0_key | 28 / 4 | 0.45 | 1.66 | 177 / 9,027 | all |
| R_severity_key | 25 / 7 | 0.25 | 1.79 | 108 / 9,096 | all |
| P, S1 | 13 / 19 | 0.18 | 11.85 | 53 / 9,151 | all |
| O_severity | 8 / 24 | 0.03 | 20.16 | 29 / 9,175 | all |
| FIFO | 0 / 32 | — | 23.03 | 0 / 9,204 | — |

- **Fast service conceals the uninvestigated majority.** Every critical alert that any ranker investigated was investigated within 24 hours of arriving, and most covered intervals were reached within an hour of their first alert. Yet at least 97% of critical alerts were never investigated by any ranker.
- **Summary measures differ.** The median delay of covered intervals varies by scenario, from 0.04 to 11.1 hours for P. The WP5 tables give the median over all covered intervals pooled (for example 0.06 h for P), which is a different summary.
- **The censoring-aware restricted mean** separates the rankers mainly through never-investigated intervals.
- **Reading rule.** Delay statistics must be read with the uninvestigated counts beside them.

## 6. Sensitivity within the tested overload regime

Pooled over the eight scenarios ([replay_rates.csv](replay_rates.csv)):

| Rate | Investigations per ranker | P covered | S0_key covered | S1_key covered |
| ---: | ---: | ---: | ---: | ---: |
| 6/h | 5,756 | 9 | 26 | 30 |
| 12/h | 11,508 | 13 | 28 | 30 |
| 30/h | 28,764 | 13 | 28 | 30 |
| 60/h | 56,941 | 13 | 28 | 30 |

Every tested rate remained heavily overloaded: at 60/h, 2.1% of all arrivals were investigated. The flat response is **limited sensitivity within the tested overload regime**, not robustness to analyst capacity.

## 7. Generalization evidence (descriptive)

- **Strict identifier hold-out** ([holdout_forward.csv](holdout_forward.csv)).
  - S1_key covers 9, 20, 8, 8 and 8 of 32 intervals across the five hold-out groups, against 21 without hold-out.
  - P covers 8, 2, 8, 8 and 8.
  - The identifier-level coverage advantage does not persist reliably when identifiers are withheld from fitting.
- **Forward chaining** (5 eligible test scenarios). S1_key covers 13 of 20 intervals and P covers 5.
- **LOSO unseen identifiers.** 113 alerts, none critical: essentially no evidence about retrieving critical alerts from new identifiers.

## 8. UWF-ZeekData24: ATT&CK mapping coverage and crosswalk consistency (supporting)

- **What UWF provides.** Tactic and technique labels and their frequencies. Both severity tables compared are **author-defined**: the tactic severity table, and AIT phase severities projected onto tactics through the author's crosswalk. The agreement statistics measure the internal consistency of the author's own mappings and **provide no independent severity validation**.
- **Coverage** ([uwf/uwf_summary.json](uwf/uwf_summary.json)):
  - 95,871 rows: 47,906 benign and 47,965 attack;
  - every attack row has a tactic present in the severity table;
  - 97.98% have a valid ATT&CK technique ID (970 rows carry the value "Duplicate");
  - 0% carry a CVE.

**The seven observed tactics** ([uwf/uwf_tactics.csv](uwf/uwf_tactics.csv)):

| Tactic | Rows (share of attack rows) | Tactic-table severity | Crosswalk severity (max over AIT phases) | Difference |
| --- | --- | ---: | ---: | ---: |
| Credential Access | 43,494 (90.68%) | 8.5 | 6.5 (cracking) | +2.0 |
| Reconnaissance | 2,909 (6.06%) | 2.5 | 3.0 (network/service scans, dirb, wpscan) | −0.5 |
| Initial Access | 561 (1.17%) | 7.0 | — (no AIT phase) | — |
| Defense Evasion | 326 (0.68%) | 8.0 | — (no AIT phase) | — |
| Persistence | 326 (0.68%) | 8.0 | 8.5 (webshell) | −0.5 |
| Privilege Escalation | 326 (0.68%) | 9.5 | 9.5 | 0 |
| Exfiltration | 23 (0.05%) | 9.5 | 9.0 (dnsteal, data_exfiltration) | +0.5 |

**Consistency over the five overlapping tactics** ([uwf/uwf_agreement_thresholds.csv](uwf/uwf_agreement_thresholds.csv), [uwf/uwf_leave_one_tactic_out.csv](uwf/uwf_leave_one_tactic_out.csv)):
- **Rank agreement.** Spearman 0.872 and Kendall τ-b 0.738, both unweighted over five tactic scores.
- **Discrepancy.** Mean absolute discrepancy is 0.70 unweighted but **1.88 frequency-weighted**. The weighted value is dominated by Credential Access: 90.68% of attack rows, with a 2-point disagreement.
- **Threshold sensitivity** (set = tactics with severity ≥ θ, inclusive):

  | θ | Jaccard | Notes |
  | --- | ---: | --- |
  | 7.5 | 0.75 | same sets as 8.0 |
  | 8.0 | 0.75 | the tactic table adds Credential Access |
  | 8.5 | 0.50 | Persistence drops from the tactic-table set |

  Using the mean rather than the maximum over mapped AIT phases gives the same correlations and Jaccard values, with weighted discrepancy 1.86.
- **Leave-one-tactic-out influence.**
  - Removing Credential Access raises Spearman to 0.949, Kendall to 0.913 and Jaccard to 1.0, and lowers weighted discrepancy to 0.45.
  - Removing Reconnaissance lowers Spearman to 0.738.
  - With five tactics, the correlations are fragile.

**Duplicate-row check** (connection identity = all non-label fields):
- **No exact full-row duplicates**, including labels.
- **The same 326 connections appear in the Persistence, Privilege Escalation and Defense Evasion files.** All 326 are shared by all three, and 34 of them also appear in Initial Access.
  - 328 attack connections occur in more than one tactic file.
  - The Persistence and Privilege Escalation rows, and 318 Initial Access rows, carry "Duplicate" as technique, binary and CVE label.
- **Consequence.** The three 326-row tactics are not independent observations but multi-tactic labels of the same connections, and attack-row totals count those connections more than once.

**Not claimed.** No independent severity validation. No inference from telemetry rows. No bootstrap.

## 9. Inventory and absent analyses

[artifact_inventory.md](artifact_inventory.md) reconciles every run, replay, configuration, eligibility restriction and reporting denominator. It records explicitly that the following were not performed:
- replay of duplicate suppression, identifier hold-out, forward chaining and ablations R3–R5;
- the deferred §6.2 expanded vector;
- WP6 (NF-UQ);
- an independent severity study;
- equivalence analyses and bootstrapping.

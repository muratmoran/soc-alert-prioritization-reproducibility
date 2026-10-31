# Revised evaluation protocol v1 (COSE-D-26-04000)

Frozen 14 September 2026 at the end of WP0, before any revised comparison was run. Author sign-off is pending on decisions D1–D4 (Section 13).

## 0. Status and honesty statement

- **Retrospective redesign.** This is a redesign after review, not a preregistration. AIT, NF-UQ-NIDS-v2 and UWF-ZeekData24 were all analysed for the submitted manuscript, and the audit (`claim_evidence_audit.md`) documents test-fold configuration selection in that work. Freezing this protocol limits further outcome-driven choices; it does not make the datasets untouched.
- **Inputs used to write it.** Only the reviews, the revision plan, code inspection and historical results. No revised experiment has been run.
- **Change control.** Any change after freeze is recorded in Section 14 with date, reason and whether revised results had been seen. Changes made after seeing revised results are labelled *exploratory*, and their analyses cannot replace a primary analysis.
- **Bug fixes.** A bug fix that changes results is applied to all methods and logged.

## 1. Research questions

| RQ | Question | Primary evidence |
| --- | --- | --- |
| RQ1 | At a fixed investigation budget, what trade-off does uncertainty-aware scoring produce between false-positive burden and critical-alert / critical-episode coverage? | AIT static ranking, Sections 4–5 |
| RQ2 | Does the SGFN interaction improve on tuned additive, multiplicative, probability-based and learned methods using the same information? | AIT matched-input comparison, Section 6 |
| RQ3 | How do calibration quality, unseen detector identifiers, repeated alerts and chronological arrival affect the trade-off? | AIT ablations, strict unseen-identifier, deduplication, replay (Sections 7–8) |
| RQ4 | What transfers across NF-UQ source domains when selection and calibration use source data only? | NF-UQ redesign (Section 9); conditional on D3 |

UWF-ZeekData24 is a supporting analysis of mapping coverage and crosswalk consistency. It has no RQ.

## 2. Information boundary

Every pipeline component belongs to exactly one of three roles:

| Role | Fields | May use labels of |
| --- | --- | --- |
| Ranking-time input | timestamp, detector, native key/category/name, host/IP, detector native score, mapped phase, s, q, u, h, learned-model features built from these | none |
| Fitted from training data | native-key mapping, reliability heights, detector priors, scaling constants, learned rankers, tuned hyperparameters, NF-UQ detectors and emission thresholds | training scenarios/domains of the current (outer or inner) fold only |
| Evaluation only | `is_attack`, `true_attack_phase`, `true_severity`, `is_critical`, label intervals, episode identifiers, NF-UQ true category | held-out scenario/domain, and only after the queue is fixed |

Enforcement:
- **API separation.** Fit functions receive training alerts with labels; score functions receive held-out alerts with evaluation columns removed.
- **Label-mutation invariance.** For every primary pipeline, mutating held-out labels must leave sample membership, fitted components, scores and queue order unchanged (`tests/test_information_boundary.py`, extended per pipeline).
- **Subgroup summaries.** Subgroup reports conditioned on held-out labels (e.g. "critical alerts that were unmapped") are allowed as evaluation-only analyses.

## 3. Populations

- **AIT.** All 2,655,821 alerts produced by `load_ait_alerts` from the 16 detector JSON files and `labels.csv`, across eight scenarios. No alert is excluded. Row counts per scenario are reported.
- **Label construction (AIT).** An alert's evaluation phases are *all* label intervals containing its timestamp (half-open [start, end)), replacing the historical first-interval rule. Its evaluation severity s* is the maximum severity over those phases (benign 0). Overlapping intervals (dirb/wpscan in wheeler and wilson) are listed in the data table.
- **Interval-label limitation.** Labels mark time windows, not individual alerts, so benign background alerts inside a window are counted as attacks. This is a ground-truth limitation that is reported (Reviewer 1, point 3), not corrected.
- **NF-UQ.** See Section 9.
- **UWF.** The public CSV subset (95,871 rows) used in the submission.

## 4. Evaluation target and metric contract

### 4.1 Definitions

| Symbol | Definition |
| --- | --- |
| $y_i$ | 1 if the alert lies in any attack interval, else 0 |
| $s_i^*$ | maximum configured phase severity over the alert's evaluation phases (`configs/severity_mapping.yaml`) |
| $\tau$ | critical threshold; **primary τ = 8.0**, prespecified sensitivity τ ∈ {7.0, 9.0} |
| $z_i$ | $y_i \cdot 1[s_i^* \ge \tau]$ |
| $r_i$ | $y_i \cdot s_i^*$ (graded relevance; no extra critical bonus) |
| Critical episode | a (scenario, label interval) with phase severity ≥ τ; an alert covers the episodes whose intervals contain it |

### 4.2 Metrics

- **DCG and NDCG.** $\mathrm{DCG@}k=\sum_{j=1}^{\min(k,n)} r_{(j)}/\log_2(j+1)$ with **linear gain**, and $\mathrm{NDCG@}k=\mathrm{DCG@}k/\mathrm{IDCG@}k$. IDCG is computed from the same queue. If IDCG = 0 the value is *not applicable* and counted, not scored 0. Exponential gain $2^{r}-1$ is a labelled sensitivity analysis.
- **Recall and precision.**
  - Critical recall@k = $\sum_{j\le k} z_{(j)} / \sum_i z_i$.
  - Attack recall@k is defined analogously with $y$.
  - Precision@k = $\sum_{j\le k} y_{(j)}/\min(k,n)$.
  - FP@k = $\min(k,n) - \sum_{j\le k} y_{(j)}$.
  - A zero denominator means *not applicable*.
- **Critical-episode coverage@k.** The share of critical episodes that have at least one alert in the queue and at least one alert in the top k. Episodes with no alert are reported separately as *not alertable*.
- **First-critical rank.** Reported with prevalence; "none" if the queue has no critical alert, and never averaged as 0.
- **Queue fraction to critical recall.** The smallest fraction of the queue reaching 50%, 80% and 90% critical recall.
- **Depths.** k ∈ {10, 25, 50, 100, 250, 500, 1000} plus queue fractions {0.1%, 1%, 5%, 10%, 25%, 50%}. A queue shorter than k is flagged.

### 4.3 Primary static endpoints

- **Primary (reported jointly):** critical recall@100 and FP@100.
- **Key secondary:** critical-episode coverage@100 and linear NDCG@100.
- **Always shown:** recall-versus-budget curves for critical alerts, attacks and critical episodes, and the FP-versus-critical-coverage trade-off over the full k grid.
- **No acceptability threshold.** No practical recall tolerance is prespecified. When methods trade FP burden against critical coverage, the result is reported as a Pareto trade-off, not as an acceptable loss.

### 4.4 Policy dependence

- **Severity-independent target.** Binary attack relevance ($y$) is reported alongside the policy-based target.
- **Severity-policy perturbations**, fixed now and applied to $s^*$ (evaluation) and $s$ (ranking) together:
  - (a) all phase severities +0.5 or −0.5 in rank-preserving blocks;
  - (b) swap the order of the two lowest critical phases;
  - (c) set `default_unknown` to the median mapped severity (3.0).

  Perturbation (c) also applies to the historical severity baseline, whose weakness depends on `default_unknown` (audit, Section 4.1).
- **External utility.** No external utility target is available. The conclusion is limited to policy-based relevance plus attack and episode coverage unless decision D4 adds an expert study.

## 5. Ordering, ties and duplicates

- **Primary order.** Score descending, then timestamp ascending, then a label-independent stable key. The key is the SHA-256 of `"cose04000|" + alert_id`, replacing the lexicographic `alert_id` tie-break that favoured AMiner files. NaN scores go last.
- **Tie diagnostics** per method and fold: number of distinct scores, tied-block sizes, fraction of top-k positions in tied blocks, and whether a tied block crosses k.
- **Tie sensitivity.**
  - 100 seeded within-block permutations (seeds 0–99) give recall, FP and first-critical rank as median and 2.5–97.5 percentile ranges.
  - Expected tie-averaged NDCG is computed exactly.
  - These characterise tie uncertainty, not sampling uncertainty.
- **Near-tie sensitivity.** Scores rounded to 4 significant digits before ordering.
- **Native score.** Reported whole-stream as historically defined, but with AMiner alerts given no native score (NaN, ordered last) instead of the calibrated height. Within-detector native ordering is reported for Wazuh and Suricata separately.
- **Duplicates (arrival-time only).**
  - Grouping key: (detector, native key, host), with rolling windows of 1, 5 and 15 minutes.
  - The representative is the first alert in the window.
  - The cluster's evaluation outcome is the maximum $s^*$ and any $y$. Clusters with mixed labels are counted and published.
  - Labels never form or suppress clusters.

## 6. AIT splits, fitting and comparison families

### 6.1 Splits

- **Outer.** Leave-one-scenario-out over eight scenarios.
- **Cross-fitting inside a training set.** For each training scenario g, the native-key mapping is learned on the other training scenarios and applied to g. Reliability heights and detector priors are estimated on these out-of-fold mapped alerts. The mapping used for held-out scoring is learned on all training scenarios. Scenario IDs used at every stage are logged in split manifests.
- **Inner selection.** Leave-one-training-scenario-out (7 inner folds). Each inner fold refits every component on 6 scenarios, including cross-fitting within those 6. Selection uses the macro mean over inner validation scenarios.
- **Fixed mapping constants.** Mapping thresholds keep the historical constants (support ≥ 5, positives ≥ 3, precision ≥ 0.5, purity ≥ 0.7). They are declared, not tuned.

### 6.2 Common inputs

- **Primary common vector: (c, u, h)**, with identical missing-value handling for every method.
- **Primary input policy: flat context (q = 1) and table uncertainty.** These were the defaults before any held-out result existed.
- **Secondary policy.** The historical asset_profile + ambiguity_aware policy is a separate secondary analysis, labelled as selected after held-out inspection.
- **Reliability target.** Shrunk binary attack precision (λ = 50, clip [0.05, 0.95]).
- **Unseen (detector, class) fallback.** The support-weighted detector-level attack precision from training, not the unweighted mean of class heights. Fallback counts are published.
- **Expanded vector.** The expanded operational comparison adds detector identity, native score, mapping support and alert age, and is labelled separately.
- **Scaling.** $c/10$ and $u/0.5$, using the declared ranges, not fitted.

### 6.3 Comparison families and grids

| Family | Score | Grid (selection by inner folds) |
| --- | --- | --- |
| O. Operational references | oldest-first; newest-first; native score; severity $c$; reliability $h$ | untuned |
| H. Historical weighted | $0.7c + 3h$ | untuned reference |
| W. Tuned two-input weighted | $\alpha\,c/10 + (1-\alpha)h$ | α ∈ {0, 0.1, …, 1} (11) |
| A. Tuned additive | $a\,c/10 + b\,h - d\,u/0.5$ with $a+b+d=1$ | simplex, step 0.1 (66) |
| M. Tuned multiplicative | $c\,h^{a}e^{-bu}$ | a ∈ {0, 0.25, 0.5, 1, 2, 4}; b ∈ {0, 1, 2, 4, 8} (30) |
| P. Probability risk proxy | $h\,c$, where h estimates P(attack \| detector, mapped class) | untuned; assumes calibrated probability, cardinal proxy impact, equal costs |
| C. Cost-sensitive | $h\,c - (1-h)C_{FP}$, rank-equivalent to $h(c+C_{FP})$ (disclosed) | $C_{FP}$ ∈ {0, 1, 2.5, 5, 10} (5) |
| L1. Learned probability | L2 logistic regression for $y$ on standardised (c, u, h); score $\hat p\,c$ | C ∈ {0.01, 1, 100} (3) |
| L2. Learned pointwise ranker | `HistGradientBoostingRegressor` on $r_i/10$ with features (c, u, h) | max_depth ∈ {2, 3}; learning_rate 0.1; max_iter 200; l2 1.0 (2) |
| R. Historical rule evidence | $\hat\rho(\text{key})$ and $c\,\hat\rho(\text{key})$, with key precision shrunk to detector prior, λ = 50, cross-fitted | untuned |
| S0. SGFN historical | $c + \kappa u c \ln h$ with κ = 1 | untuned reference (outside the monotone domain) |
| S1. SGFN constrained | same form, κ inside $\kappa\,u_{\max}\ln(1/h_{\min}) \le 1$ with $u_{\max} = 0.5$, $h_{\min} = 0.05$ | κ ∈ {0, 0.1, …, 0.6, 0.6676} (8) |
| S2. SGFN exponential | $c\,h^{\kappa u}$ | κ ∈ {0, 0.5, 1, 2, 4, 8} (6) |

- **Learned-model training data.**
  - Label-independent uniform subsample of at most 300,000 alerts per inner training set, seed 42.
  - Sample weights equalise scenarios.
  - Features are computed with cross-fitted mappings and heights, so no training alert's own label shapes its features.
- **R is compared at matching granularity.** Family R uses identifier-level evidence, so it is compared with an identifier-level SGFN variant (h from key precision) in addition to the class-level primary.
- **Compute.** Candidate counts and runtime are reported per family.

### 6.4 Selection objective

- **Single objective (D1): macro linear NDCG@100** over inner validation scenarios.
  - Ties go to the simpler candidate: fewer non-zero parameters, then the grid order listed above.
  - NA inner folds are excluded and counted.
- **Exploratory alternative.** Selection by macro critical recall@100 is reported as exploratory only.

## 7. AIT diagnostics and ablations (RQ3)

All of these use the Section 6 split machinery and the primary input policy unless stated.

1. **Scenario data table:** alert counts, attack/benign/critical counts, detector shares, label intervals and critical episodes, native-key counts, train/test key overlap, mapping coverage, unmapped fraction.
2. **Seen versus unseen identifiers.** Unseen means (detector, native key) absent from the outer training scenarios. Metrics are reported within each subgroup and as subgroup coverage in the mixed queue.
3. **Strict identifier hold-out.**
   - Test keys are grouped by (detector, normalised rule identifier).
   - 5 key groups are assigned by SHA-256 of the key string modulo 5.
   - For group g, every alert with a key in g is removed from all fitting sources and scored with the fixed fallback.
   - Evaluated within the LOSO outer fold.
4. **Forward-chaining across scenarios.**
   - A scenario's extent is [min, max] of its alert timestamps; this is label-independent.
   - For each test scenario, fitting uses only scenarios whose extent ends before the test scenario's extent starts. Test scenarios with fewer than two such scenarios are skipped and listed.
   - Label windows suggest the calendar order santos, fox, wardbeck, russellmitchell, shaw, wheeler, wilson, harrison, with santos/fox and shaw/wheeler overlapping. The final eligibility list is computed from alert timestamps and published before metrics are read.
   - This tests "no future content in fitting". It is not a deployment chronology: scenario clocks are never concatenated into one stream.
   - Within-scenario temporal splits are not used, because attack phases are sequential and would separate fitted and scored phases by construction.
5. **Calibration ablation:** detector-class, global-class, detector-only, native-key precision, no reliability (h = 1).
   - Compared on heights, Brier score and reliability diagrams against $y$, Spearman correlation between rankings, top-k overlap, and full recall curves.
6. **Uncertainty ablation:** u constant 0.5; table only; purity-only $0.35(1-\text{purity})$; precision-only $0.35(1-\text{precision})$; historical combined; no uncertainty effect (u = 0). All methods receive the same u in each comparison.
7. **Context ablation:** flat versus asset_profile. The token hits that come from native key/category content, as opposed to host/IP, are audited.
8. **Critical-alert deferral audit:**
   - count and fraction of alerts with severity coefficient $1+\kappa u\ln h \le 0$ and $\le 0.1$, by scenario, detector, mapping status and $z$;
   - the causes of deferral for low-confidence critical alerts.

## 8. Chronological replay (WP5)

- **Arrivals.** Alerts arrive at their AIT timestamps; mappings, heights and rankers are frozen from outer-training scenarios.
- **Service.** One analyst, non-preemptive, equal service time.
  - **Primary rate: 12 alerts/hour.** Sensitivity rates: 6, 30 and 60.
  - These are assumptions, not measured SOC rates.
- **Horizon.** From the scenario's first alert to its last alert, working 24 hours a day. There is no initial backlog and no draining after the horizon; uninvestigated alerts and episodes are reported as censored.
- **Event order at equal time.** Arrivals at time t are enqueued before the free analyst selects at t.
- **Selection.** From the current backlog by method score with the Section 5 tie rule; FIFO uses the oldest arrival.
- **Metrics:**
  - critical-episode coverage by horizon;
  - time from an episode's first alert to its first investigation, with censoring;
  - critical recall within 1, 4 and 24 hours;
  - FP investigations; queue age; peak backlog;
  - starvation, i.e. critical alerts that were never investigated.
- **Wrappers.** No aging or exploration wrapper in v1. Adding one requires an amendment that applies it to all methods.
- **Integrity checks:**
  - no selection before arrival;
  - never more than one alert in service;
  - service accounting sums to the horizon;
  - held-out label mutation does not change traces;
  - identical arrivals across methods.

## 9. NF-UQ-NIDS-v2 redesign (WP6; conditional on D3)

- **Population.**
  - All categories and benign rows in each domain.
  - If the full domain is infeasible, use a label-independent uniform sample: keep row index i if `SHA-256("cose04000|" + i) mod 10^6 < p·10^6`.
  - p is set per domain before labels are read, from compute budget only, and recorded in an amendment.
- **Splits.**
  - Outer: one target domain held out.
  - Inside the three source domains: leave-one-source-domain-out selection of detector configuration, emission threshold and ranker settings.
- **Calibration.** Reliability comes from out-of-fold predictions on source rows only, with target P(attack | detector, predicted class) as in AIT. Never from rows used to fit that detector.
- **Detector candidates.** Logistic regression, random forest and histogram gradient boosting with fixed small grids declared in the WP6 amendment. All candidates are reported for all domains.
- **Eligibility.** A source-validation eligibility rule may be set in the amendment. There is no target-F1 threshold.
- **Queue.** Every emitted alert in the evaluated target sample is ranked. True categories only stratify reports after ordering.
- **Reporting.** End-to-end attack and critical recall relative to the evaluated flow population, so non-emitted attacks count as misses.
- **Ordering keys.** Synthetic row-index timestamps are not used as time; ties use the Section 5 hash key.
- **Feature audit.** L4 ports, DNS_QUERY_ID and other identifier-like fields are removed from the primary feature set and tested in a separate sensitivity analysis.
- **Historical benchmark.** The old shared-category balanced sample is kept only as a secondary controlled benchmark, labelled as selected on true categories.

## 10. UWF (WP7)

- **Name and role.** "ATT&CK mapping coverage and crosswalk consistency", supporting only.
- **Tables.** All seven tactics, the five overlapping tactics, frequencies, both severity assignments, disagreements, technique coverage, and a check for duplicated rows across tactic files.
- **Statistics.**
  - Unweighted Spearman and Kendall correlations with frequency-weighted mean absolute discrepancy.
  - Jaccard at thresholds {7.5, 8.0, 8.5}.
  - Leave-one-tactic-out influence.
  - No bootstrap over telemetry rows.

## 11. Statistical reporting (WP7)

- **Units.** Scenarios (AIT, n = 8) and domains (NF-UQ, n = 4).
- **Descriptives.** Every unit is reported, with macro mean, median, range and paired absolute differences; micro summaries are shown separately.
- **Primary comparison family (6 tests).** S1 selected versus A, M and P, on critical recall@100 and FP@100.
  - Two-sided exact paired sign-flip randomisation test on the mean difference, enumerating all $2^8$ sign patterns.
  - Holm adjustment within the family.
  - With n = 8 the smallest attainable two-sided p is 2/256 = 0.0078, below the first Holm threshold of 0.0083 only when all eight folds agree. This is stated in the paper.
- **Dependence.** Training folds overlap, so tests and intervals are conditional consistency analyses over these scenarios, not deployment inference. No bootstrap is applied to fold scores in the main text.
- **Replicates.** Alerts, tie seeds, grid points and capacity settings are never counted as replicates.
- **All other comparisons are exploratory and unadjusted.** Tests are not expanded after unfavourable results.

## 12. Seeds, failures and claim language

- **Seeds.** Seed 42 for sampling and model fitting; seeds 0–99 for tie permutations; seed 42 plus fold index for any stress perturbation.
- **Failure handling.**
  - Empty queues, failed fits and NA metrics are reported with counts.
  - A failed fit uses the declared fallback (h fallback; for learned models, the family's simplest grid point) and is logged.
  - A fold is never dropped.
- **Claim language** follows plan Section 15, and in particular:
  - no "reduced analyst effort" or "improved critical retrieval" from first-critical rank alone;
  - no superiority claim unless the S1-versus-competitor primary tests support it and the trade-off curves agree;
  - equal performance is reported as a simplicity or transparency argument only if those properties are explicitly evaluated.

## 13. Author decisions requested before WP2–WP6 runs

| ID | Decision | Default in v1 | Alternatives |
| --- | --- | --- | --- |
| D1 | Single tuning objective for all tuned families | Macro linear NDCG@100 | Macro critical recall@100; macro critical-episode coverage@100 |
| D2 | Alert-level versus episode-level primary critical endpoint | Alert-level critical recall@100 (plan), episode coverage as key secondary | Episode coverage@100 as primary: dnsteal windows contribute about 94% of critical alerts, so alert-level recall mostly measures one phase |
| D3 | NF-UQ scope | Attempt the redesign by streaming the 13.7 GB iCloud file chunkwise; drop the domain-shift claim if infeasible | Free or attach disk; or remove NF-UQ from the paper now |
| D4 | Independent severity or impact reference | Not in scope; conclusions limited to policy-based relevance plus attack/episode coverage | Blind expert annotation study (WP3.3 design) |

## 14. Change log

| Date | Change | Revised results seen? | Classification |
| --- | --- | --- | --- |
| 2026-09-14 | v1 frozen | No | — |

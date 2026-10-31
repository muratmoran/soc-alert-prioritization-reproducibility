# Revised evaluation protocol v1.1 (COSE-D-26-04000)

Amended 14 September 2026 following WP0, resolving D1–D4 at the user's request before revised comparisons. The original `protocol_v1.md` is preserved. This amendment records the assistant's requested methodological decisions; it does not assert a separate author signature.

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
| Archived RQ4 | What transfers across NF-UQ source domains? | Out of scope for this revision under D3; no domain-shift claim will be retained. |

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
- **Label construction (AIT).** An alert's evaluation phases are *all* label intervals containing its timestamp (half-open [start, end)), replacing the historical first-interval rule. Its evaluation severity s* is the maximum severity over those phases (benign 0). The rule is general, but AIT has no overlapping intervals (79 intervals; erratum 2026-09-14), so on AIT it assigns the same labels as the historical rule. The eight rows that are out of chronological order in `labels.csv` (dirb after wpscan in wheeler and wilson; privilege_escalation before the earlier service_stop row in six scenarios) do not affect labels and are listed in `wp3/label_verification.json`.
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
| Critical-step interval | A distinct (scenario, phase, interval start, interval end) with configured phase severity ≥ τ. Exact duplicate interval definitions count once; distinct repeated steps count separately. An alert covers every such interval containing its timestamp. This is temporal coverage, not confirmation that the selected alert identifies that step. |

### 4.2 Metrics

- **DCG and NDCG.** $\mathrm{DCG@}k=\sum_{j=1}^{\min(k,n)} r_{(j)}/\log_2(j+1)$ with **linear gain**, and $\mathrm{NDCG@}k=\mathrm{DCG@}k/\mathrm{IDCG@}k$. IDCG is computed from the same queue. If IDCG = 0 the value is *not applicable* and counted, not scored 0. Exponential gain $2^{r}-1$ is a labelled sensitivity analysis.
- **Recall and precision.**
  - Critical recall@k = $\sum_{j\le k} z_{(j)} / \sum_i z_i$.
  - Attack recall@k is defined analogously with $y$.
  - Precision@k = $\sum_{j\le k} y_{(j)}/\min(k,n)$.
  - FP@k = $\min(k,n) - \sum_{j\le k} y_{(j)}$.
  - A zero denominator means *not applicable*.
- **Critical-step interval coverage@k.** Number of distinct critical-step intervals containing a top-k alert divided by the number containing any alert in the same eligible queue. Each interval has equal weight regardless of its duration or alert count; overlap may allow one alert to cover multiple intervals and is reported. Zero denominator is NA. Also report coverage over all defined critical intervals, counting those without emitted alerts as uncovered. “Critical-episode coverage” in inherited sections below means this interval-based proxy, not confirmed attack discovery. No-alert intervals are described as lacking emitted alerts in this dataset, not inherently undetectable.
- **First-critical rank.** Reported with prevalence; "none" if the queue has no critical alert, and never averaged as 0.
- **Queue fraction to critical recall.** The smallest fraction of the queue reaching 50%, 80% and 90% critical recall.
- **Depths.** k ∈ {10, 25, 50, 100, 250, 500, 1000} plus queue fractions {0.1%, 1%, 5%, 10%, 25%, 50%}. A queue shorter than k is flagged.

### 4.3 Primary static endpoints

- **Primary (reported jointly):** critical-step interval coverage@100 and FP@100.
- **Key secondary, always retained:** alert-level critical recall@100, linear NDCG@100, and queue fractions to 50%, 80%, and 90% alert-level critical recall. This change in emphasis does not remove the historical critical-deferral result.
- **Always shown:** recall-versus-budget curves for critical alerts, attacks and critical episodes, and the FP-versus-critical-coverage trade-off over the full k grid.
- **No acceptability threshold.** No practical recall tolerance is prespecified. When methods trade FP burden against critical coverage, the result is reported as a Pareto trade-off, not as an acceptable loss.

### 4.4 Policy dependence

- **Severity-independent target.** Binary attack relevance ($y$) is reported alongside the policy-based target.
- **Severity-policy perturbations**, fixed now and applied to $s^*$ (evaluation) and $s$ (ranking) together:
  - (a) all phase severities +0.5 or −0.5 in rank-preserving blocks;
  - (b) swap the order of the two lowest critical phases;
  - (c) set `default_unknown` to the median mapped severity (3.0).

  Perturbation (c) also applies to the historical severity baseline, whose weakness depends on `default_unknown` (audit, Section 4.1).
- **External utility (D4).** No independent expert study is in scope. Conclusions are limited to author-policy relevance and observed interval-label/step coverage. No measured impact, true alert correctness, analyst preference, or independent severity validity is established.

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
- **Reliability target.** Shrunk frequency of the observed binary interval label y=1 (λ = 50, clip [0.05, 0.95]). On AIT this estimates P(interval-labeled positive | detector, mapped class), not a verified probability that the individual alert is malicious. “Attack precision” in inherited descriptions is shorthand for this proxy. Calibration diagnostics must test this target, with explicit label limitations.
- **Unseen (detector, class) fallback.** The pooled detector-level observed-positive fraction from permitted training alerts, clipped to the declared bounds, not an unweighted mean of class heights. An unseen detector uses the pooled permitted-training prior; no usable training labels is an explicit fitting failure. Save numerator, denominator, unclipped estimate, clipped estimate, and fallback counts. The scoring primitive itself performs no fallback or silent clipping.
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
| P. Probability risk proxy | $h\,c$, where h estimates P(observed y=1 \| detector, mapped class) | untuned; uses interval-label probability and cardinal proxy severity, not independently measured expected loss |
| C. Cost-sensitive | $h\,c - (1-h)C_{FP}$, rank-equivalent to $h(c+C_{FP})$ (disclosed) | $C_{FP}$ ∈ {0, 1, 2.5, 5, 10} (5) |
| L1. Learned probability | L2 logistic regression for $y$ on standardised (c, u, h); score $\hat p\,c$ | C ∈ {0.01, 1, 100} (3) |
| L2. Learned pointwise ranker | `HistGradientBoostingRegressor` on $r_i/10$ with features (c, u, h) | max_depth ∈ {2, 3}; learning_rate 0.1; max_iter 200; l2 1.0 (2) |
| R. Historical rule evidence | $\hat\rho(\text{key})$ and $c\,\hat\rho(\text{key})$, with key precision shrunk to detector prior, λ = 50, cross-fitted | untuned |
| S0. SGFN historical | $c + \kappa u c \ln h$ with κ = 1 | untuned reference (outside the monotone domain) |
| S1. Constrained linear-log heuristic | same form, κ strictly inside $\kappa\,u_{\max}\ln(1/h_{\min}) < 1$ with $u_{\max} = 0.5$, $h_{\min} = 0.05$ | κ ∈ {0, 0.1, …, 0.6, 0.6676} (8) |
| S2. Exponential-discount heuristic (not a Gaussian derivation) | $c\,h^{\kappa u}$ | κ ∈ {0, 0.5, 1, 2, 4, 8} (6) |

- **Learned-model training data.**
  - Label-independent uniform subsample of at most 300,000 alerts per inner training set, seed 42.
  - Sample weights equalise scenarios.
  - Features are computed with cross-fitted mappings and heights, so no training alert's own label shapes its features.
- **Training-feature isolation clarification.** For features on training scenario g, exclude g from *all* upstream mapping and height estimation, including the labels used to fit the height attached to g. Pooling all out-of-fold mapped rows and then fitting a height using g's own labels is insufficient. For outer/inner validation, fit heights on cross-fitted mapped rows from permitted training scenarios only, and fit the final mapping on those training scenarios. Log these distinct prediction roles.
- **R is compared at matching granularity.** Family R uses identifier-level evidence, so it is compared with an identifier-level SGFN variant (h from key precision) in addition to the class-level primary.
- **Compute.** Candidate counts and runtime are reported per family.

### 6.4 Selection objective

- **Primary selection rule (D1), applied to every tuned family:** maximize macro critical-step interval coverage@100; break coverage ties by lower macro FP@100, then higher macro linear NDCG@100, then the simpler candidate (fewer nonzero parameters, followed by declared grid order). This is lexicographic selection without an invented exchange rate between missed steps and false positives.
  - Coverage is averaged over the common eligible inner scenarios with at least one alert-containing critical interval. FP uses all inner scenarios; NDCG uses the common scenarios with nonzero IDCG. Publish denominator counts.
  - Equality tolerance is 1e-12 for numerical roundoff only; it is not a practical noninferiority margin. If no inner scenario has a critical interval with alerts, use lower FP, then NDCG, then simplicity and flag the fallback.
  - Prespecified **secondary** selection analysis: macro linear NDCG@100, followed by simplicity. Apply it to all tuned families using the same grids and inner predictions. It cannot replace primary results based on which method wins. This is a separate declared analysis, not a second opportunity to select the headline.

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

## 9. Archived NF-UQ-NIDS-v2 redesign (WP6 deferred under D3)

The design below is retained for provenance and possible future work. It is not an executable requirement of this revision. Do not start an iCloud stream, delete files to make room, or run NF-UQ comparisons under this protocol. Remove RQ4 and domain-shift claims from the revised manuscript; preserve WP0's all-candidate/all-domain historical audit as the explanation for withdrawal.

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
- **Primary comparison family (6 tests).** S1 selected versus A, M and P, on critical-step interval coverage@100 and FP@100.
  - Two-sided exact paired sign-flip randomisation test on the mean difference, enumerating all $2^8$ sign patterns.
  - Holm adjustment within the family.
  - With n = 8 the smallest attainable two-sided p is 2/256 = 0.0078, below the first Holm threshold of 0.0083 only when all eight folds agree. This is stated in the paper.
- **Dependence.** Training folds overlap, so tests and intervals are conditional consistency analyses over these scenarios, not deployment inference. No bootstrap is applied to fold scores in the main text.
- **Replicates.** Alerts, tie seeds, grid points and capacity settings are never counted as replicates.
- **Non-primary analyses.** Explicitly prespecified secondary analyses (including NDCG-only selection) remain secondary regardless of outcome; their additional tests, if shown, are exploratory and unadjusted. Tests are not expanded after unfavourable results.

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

## 13. D1–D4 decisions resolved in this revision turn

| ID | Decision | Rationale and limitation |
| --- | --- | --- |
| D1 | Lexicographic step-interval coverage@100, fewer FP@100, then linear NDCG@100; simpler candidate last. NDCG-only selection is a prespecified secondary analysis. | Align selection with coverage and analyst burden; identical rule for all tuned families. Window coverage remains a proxy. |
| D2 | Primary: step-interval coverage@100 jointly with FP@100. Retain alert-level recall and deep-queue effort as key secondary results. | Limits domination by long dnsteal windows without hiding delayed critical alerts or claiming verified incident discovery. |
| D3 | Drop the domain-shift claim and defer WP6. | Historical evidence does not support the claim; adequate redesign is not locally feasible. No disk deletion, cloud streaming, or new hardware assumption. |
| D4 | No independent expert study in this revision. | Limit conclusions to author policy and interval-label proxies. UWF remains crosswalk consistency only. |

Original v1 SHA-256: `2c910b81d41fb34c70f82d18988709e3618842d678e38e2657011362a5837bb8`. The original file is unchanged.

## 14. Change log

| Date | Change | Revised results seen? | Classification |
| --- | --- | --- | --- |
| 2026-09-14 | v1 frozen | No | — |
| 2026-09-14 | v1.1 resolves D1–D4; clarifies interval-label targets, strict mathematical domain, fallback semantics, and training-feature isolation | No revised comparisons; only WP0 evidence and analytic/saved-parameter diagnostics | Retrospective amendment before revised runs |
| 2026-09-14 | WP2 implementation clarifications (listed in `wp2/baseline_specification.md` §10): all-containing-interval phase counts with alphabetical ties in mapping; identifier-granularity block S0_key/S1_key/S2_key alongside R; untuned references not scored in inner folds; L1 standardization on the unweighted sample and single-class constant-rate fallback; L2 early stopping disabled; hash-ordered learned-sample draw; unseen-key detector/global prior fallback; within-detector native ordering implemented as a WP3 evaluation. Grids frozen in `wp2/grid_registry.json` (registry SHA-256 eab4ca3f…363ac). | No; synthetic fixtures and a real-data construction check (no features, scores or metrics) only | Implementation clarification before comparative runs |
| 2026-09-14 | WP3 metric-contract clarifications (`wp3/metric_contract.md`): NA rules for every zero denominator and empty queue; coverage over alert-containing and over all defined critical intervals; effort also to 50/80/100% interval coverage; exact integer ceilings for budgets and efforts; severity-level swap defined on distinct levels (three phases tie at 9.0); anchored duplicate windows and separate original/representative_own/static_cluster/chronological units; within-detector queues keep all defined intervals; all-missing native queues reported NA; near ties by 4 significant digits (`g` format). | No; hand-built, randomized and synthetic data, plus method-independent real-data label and structure checks | Specification clarification before comparative runs |
| 2026-09-14 | Erratum to §3 (also applies to frozen v1 §3): AIT `labels.csv` has 79 intervals and none overlap; the earlier dirb/wpscan overlap statement was a file-order misreading. No rule changes. | No; found by the WP2 real-data construction check (no features, scores or metrics) | Factual correction |
| 2026-09-14 | WP4 stage-1 corrections and clarifications (`wp4/fitting_specification.md`). (1) **Native-score correction** (§5, §6.3 O): the historical pooled native score mixed Suricata eve.json signature severity (inverted to 0.5–1.0) with Wazuh rule levels 6–11 assigned to Suricata fast.log lines by Wazuh IDS rules 20100–20162 (`wp4/native_score_provenance.json`). It is replaced by two single-scale references: `O_native_rule_level` (Wazuh rule.level, every Wazuh-delivered alert) and `O_native_suricata_severity` (−raw severity, eve.json alerts); other alerts are missing and ordered last. The pooled score is kept only as provenance, and within-Suricata native results are reported per raw record type. The registry grows from 156 to 157 candidates (12 untuned) and is re-frozen, with the superseded registry archived. (2) **Strict identifier hold-out** (§7.3): identifier = detector plus the first identifier field of the native key (93 identifiers, one per AIT key); group = SHA-256 of that string mod 5, unsalted. Removal from all fitting sources means removal from mapping tables, cross-fitted height rows, detector and global priors, key heights, learned training samples and inner validation queues; nested selection is rerun per hold-out fold. The outer queue keeps these alerts, which receive the declared unmapped handling (c = 5, u = 0.5, h from the (detector, unknown) cell or prior). Near-equivalent identifiers (20151/20161, 20152/20162, 2016149/2016150) are listed with their groups but not merged. (3) **Forward chaining** (§7.4): strict precedence (end < start). With exactly two fit scenarios, learned inner selection is not estimable (empty inner role-T fit sets), so §12 applies: the simplest grid point (L1 C = 0.01, L2 max_depth = 2) is fitted on the outer fit scenarios and logged. (4) **Ablations** (§7.5–7.7): global_class pools classes across detectors, and detector_only pools classes within a detector, both with the global prior; native_key uses key precision shrunk to the detector prior; none sets h = 1 (h ≤ 1 admitted only there). Uncertainty variants change mapped keys only; unmapped keys keep u = 0.5 except in constant-0.5 and zero. Historical combined is ambiguity_aware with flat context; the context ablation is asset_profile with table uncertainty. Every ablation reruns nested selection on the frozen grids. (5) **Subgroups** (§7.2): retrieval in the original mixed queue and within-subgroup ranking are reported separately (metric contract v1.1 §9a). (6) Duplicate units never change fitting populations. (7) **Open:** the §6.2 expanded vector has no declared model or grid; it is not implemented and will not be run unless specified and frozen before comparative runs. | No; synthetic fault injection, raw-data provenance, and real-data fitting chains without scoring or metrics | Correction and implementation clarification before comparative runs |
| 2026-09-14 | WP4 stage-2 run and reporting specification declared (`wp4/stage2_reporting_specification.md` v1.0): runs R1–R7 (primary and secondary LOSO, calibration, uncertainty and context ablations, 40 identifier hold-out folds, 5 forward-chaining folds); outer candidates; evaluations E1–E12 and the runs they apply to (seeded permutations for R1–R2 only); deep deferral defined as a critical alert ranked beyond ⌈n/2⌉, with five recorded causes; Brier score and 10 equal-width reliability bins against held-out y; Spearman and top-100 overlap with R1; 200 log-spaced curve ranks; per-scenario covered-interval counts with tie diagnostics beside the primary table. | No; declared before any comparative AIT result | Reporting specification before comparative runs |
| 2026-09-15 | **Amendment: expanded operational vector deferred.** The §6.2 expanded operational comparison (detector identity, native score, mapping support and alert age) was never given a model, grid or selection rule before comparative runs. Specifying it now would be informed by the WP4 stage-2 results. It is recorded as **deferred, unimplemented scope** for this revision. It is neither a completed nor a prespecified comparison, and no result for it exists or will be reported. The main WP4 findings do not depend on it. | Yes (WP4 stage-2 results seen); the decision was made because results had been seen | Scope amendment (deferral), not an analysis change |
| 2026-09-15 | WP5 chronological replay specification declared (`wp5/replay_specification.md` v1.0) before any replay outcome. It implements §8 unchanged: one analyst, non-preemptive, rates 12 (primary), 6, 30 and 60, horizon from first to last alert, no initial backlog, no draining, arrivals enqueued before selection at equal time, declared tie order, no wrappers. Clarifications: replay uses the stored WP4 R1 and R2 outer candidates without refitting (R3–R7 are not replayed); investigations are credited at start; a service in progress at T counts, with busy time truncated at T; critical episodes are critical-step intervals, covered only by an investigated alert inside them; delays are reported with right-censoring at T; critical recall within 1/4/24 h uses all critical alerts as the denominator; low-confidence critical alerts are unmapped or have R1 class height ≤ 0.2; backlog, queue age and tie-decided selection definitions are fixed; the full replay requires verified WP3/WP4/WP5 records and at least 5 GB of free disk after projected output. | No; synthetic verification and a label-free real-data precheck only | Specification before replay runs |
| 2026-09-15 | WP7 statistical reporting (`wp7/analysis_specification.md`). The §11 primary family is kept intact: the S1 selection against A, M and P on coverage@100 and FP@100, exact 2⁸ sign-flip tests, Holm. NF-UQ domain units do not occur (WP6 deferred). Twelve exploratory contrasts (S1_key vs S1, S0_key vs P, R_severity_key vs P; static and 12/h replay coverage and FP) were **specified after WP4/WP5 results were seen** and are labelled post hoc and unadjusted. Macro, pooled and median summaries are defined; delay is reported with censoring and uninvestigated counts; no equivalence margin is declared, so no equivalence claims are made. The UWF analysis follows §10 (seven tactics, frequency-weighted discrepancy, Jaccard at 7.5/8.0/8.5 with inclusive ≥, leave-one-tactic-out, duplicate-row check). | Yes (for the exploratory set) | Reporting specification; exploratory tests labelled |

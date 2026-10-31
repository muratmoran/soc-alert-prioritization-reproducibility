# WP2 baseline specification and comparison pipeline

Date: 14 September 2026. Status: **checkpoint 1 met: comparison pipeline implemented and verified on synthetic data**.

No comparative run has been made on AIT. The real-data runner refuses to start until WP3 metric verification and WP4 fitting-boundary verification records exist (Section 9). The governing protocol is [protocol_v1_1.md](../protocol_v1_1.md); grids are frozen in [grid_registry.json](grid_registry.json) (registry SHA-256 `e2f088ed…cb23a`, config SHA-256 `498290d1…7f035f`). WP4 superseded the first registry (`eab4ca3f…363ac`, archived in [superseded/](superseded/)) when it replaced the pooled native score; the 145 tuned candidates are unchanged.

## 1. Components

| File | Role |
| --- | --- |
| `configs/revision_wp2.yaml` | Declared inputs, grids, selection rule, seeds (schema: [configuration_schema.md](configuration_schema.md)) |
| `src/soc_alert_ranking/revision/config.py` | Loads the config and validates every value against protocol v1.1; rejects drift |
| `src/soc_alert_ranking/revision/labels.py` | v1.1 interval labels (y, s\*, z, r, phase and critical-interval membership); `LabelStore` with scenario locks and an access log |
| `src/soc_alert_ranking/revision/features.py` | Ranking-time frame, per-key count tables, mapping and height fitting, cross-fitting, (c, u, h) and h_key per alert |
| `src/soc_alert_ranking/revision/families.py` | 13 declared families, grids, simplicity counts, vectorized scores, domain checks, learned rankers |
| `src/soc_alert_ranking/revision/evaluation.py` | Primary order rule, exact top-k, and the three selection metrics |
| `src/soc_alert_ranking/revision/tuning.py` | Primary lexicographic rule and secondary NDCG rule |
| `src/soc_alert_ranking/revision/pipeline.py` | Nested orchestration for any outer split (LOSO, identifier hold-out, forward chaining), traces, trace verification and outputs (WP4) |
| `src/soc_alert_ranking/revision/splits.py` | Declared split machinery (WP4) |
| `src/soc_alert_ranking/revision/native_scores.py` | Raw native-score provenance and the revised alert loader (WP4) |
| `src/soc_alert_ranking/revision/synthetic.py` | Synthetic AIT-like fixtures (tests, logs, scale benchmark) |
| `scripts/revision/wp2_*.py` | Grid freeze, negative controls, synthetic checks, gated real-data runner |
| `tests/test_wp2_*.py` | 43 tests (Section 8) |

The historical modules and scripts are unchanged.

## 2. Inputs and information roles

- **Ranking-time columns** (the only alert columns that enter the pipeline): `alert_id, scenario, timestamp, detector, native_key, native_category, native_name, native_short, host, ip, detector_score`.
- **Discarded loader columns.** The loader's inferred phase, severity, uncertainty and label columns are dropped before a `RankingFrame` is built.
- **Evaluation labels.** Built from `labels.csv` under the v1.1 rule: all containing intervals, half-open, s\* = maximum interval severity, z = y·1[s\* ≥ 8], r = y·s\*.
- **Access control.** Labels are held only in `LabelStore`. Every read names a purpose and is logged, and reading a locked scenario raises `LabelAccessError`.
- **AIT has no overlapping intervals** (79 intervals; see the audit erratum), so on AIT the v1.1 rule reproduces the historical labels. The synthetic fixture includes an overlap so that the general rule is still exercised.

**Primary common vector (c, u, h)**, identical for every class-granularity family:

| Input | Definition |
| --- | --- |
| c | s·q; s = severity of the accepted mapped phase, else `default_unknown` = 5.0; primary q = 1 (flat) |
| u | primary *table*: bucket factor of the mapped phase (low 0.10, moderate 0.20, high 0.35), else 0.5 |
| h | shrunk observed-positive frequency per (detector, mapped class), λ = 50, clipped to [0.05, 0.95] |
| h_key | shrunk observed-positive frequency per (detector, native_key), λ = 50, clipped; identifier-granularity families only |
| native score | loader `detector_score` (Wazuh `rule.level`, Suricata inverted severity); **AMiner stays missing** and is ordered last, never replaced by h |

- **Secondary policy.** asset_profile q (historical token rules) plus ambiguity_aware u = clip(u_table + 0.20(1 − precision) + 0.15(1 − purity), 0, 0.5), with 0.5 for unmapped keys. It is run as a separate, labelled analysis.
- **Missing values.** Construction yields no missing c, u or h. Score functions validate c ∈ [0, 10], u ∈ [0, 0.5], h ∈ [0.05, 0.95] and finiteness, and raise `DomainError` instead of clipping or imputing.
- **Structural fact.** AIT has 93 native keys (Wazuh 24, Suricata 35, AMiner 34). All class-level inputs, and therefore all class-level scores, are constant within a key, so within-key order comes entirely from the protocol tie rule. WP3 must report the resulting tie structure.

## 3. Fitting isolation

Every fitted object is a function of a **fit set** F and is applied only to scenarios outside F:

| Object | Fitted on |
| --- | --- |
| Mapping M(F) | Summed per-key count tables of F. Thresholds: support ≥ 5, positives ≥ 3, precision ≥ 0.5, purity ≥ 0.7. Phase counts use all containing intervals; ties go to the alphabetical phase |
| Class heights H(F) | Rows of each j ∈ F mapped with M(F \ {j}), pooled (cross-fitted); detector and global priors pooled from the same rows |
| Key heights K(F) | Per-key counts of F, shrunk to the pooled detector prior |
| Fallback | Unseen (detector, class) or key → pooled detector prior (clipped) → pooled global prior (clipped) → `FitFailure`. Numerators, denominators, unclipped and clipped values and per-alert fallback codes are recorded |

Prediction roles:

| Role | Target | Fit set |
| --- | --- | --- |
| Outer validation | held-out v | S = all scenarios except v |
| Inner validation | i ∈ S | T = S \ {i} |
| Learned-ranker training features (outer) | g ∈ S | S \ {g} |
| Learned-ranker training features (inner) | g ∈ T | T \ {g} |

Consequences:
- **No self-influence.** A training scenario's labels never shape its own learned-ranker features, whether through its mapping, the mappings used to build heights, or the heights themselves. The same holds inside every inner fold. `FeatureBuilder.alert_features` raises if the target is in its fit set.
- **Manifests.** Every feature request records role, target, fit set, the mapping fit set, each height row source with the mapping that mapped it, and the key-height fit set.
- **Locking during a fold.**
  - The outer held-out scenario is locked for the whole fold.
  - Each inner validation scenario is locked while its features are built, learners are trained and candidates are scored.
  - Its labels are then read exactly once, for inner evaluation.

## 4. Comparison families (protocol v1.1 §6.3)

| Family | Score | Grid | Candidates | Granularity |
| --- | --- | --- | ---: | --- |
| O_oldest_first | −timestamp | — | 1 | none |
| O_newest_first | timestamp | — | 1 | none |
| O_native_rule_level | Wazuh rule.level (all Wazuh-delivered alerts); missing ordered last (WP4) | — | 1 | none |
| O_native_suricata_severity | −Suricata data.alert.severity (eve.json alerts); missing ordered last (WP4) | — | 1 | none |
| O_severity | c | — | 1 | class |
| O_reliability | h | — | 1 | class |
| H_weighted | 0.7c + 0.3·10h | — | 1 | class |
| W_weighted | α c/10 + (1 − α) h | α ∈ {0, 0.1, …, 1} | 11 | class |
| A_additive | a c/10 + b h − d u/0.5, a + b + d = 1 | simplex, step 0.1 | 66 | class |
| M_multiplicative | c h^a e^(−b u) | a ∈ {0, 0.25, 0.5, 1, 2, 4}; b ∈ {0, 1, 2, 4, 8} | 30 | class |
| P_probability_proxy | h c | — | 1 | class |
| C_cost_sensitive | h c − (1 − h) C_FP | C_FP ∈ {0, 1, 2.5, 5, 10} | 5 | class |
| L1_logistic | p̂(y \| standardized c, u, h) · c; L2 penalty, lbfgs, max_iter 1000 | C ∈ {0.01, 1, 100} | 3 | class |
| L2_gradient_boosting | HistGradientBoostingRegressor on r/10 with (c, u, h); learning_rate 0.1, max_iter 200, l2 1.0, no early stopping | max_depth ∈ {2, 3} | 2 | class |
| R_key_reliability | h_key | — | 1 | key |
| R_severity_key_reliability | c · h_key | — | 1 | key |
| S0_linear_log_historical | c + κ u c ln h, κ = 1 (historical heuristic, outside the monotone domain) | — | 1 | class |
| S1_linear_log_constrained | c (1 + κ u ln h); **constrained linear-log heuristic** | κ ∈ {0, 0.1, …, 0.6, 0.6676}, strictly below 0.66762 | 8 | class |
| S2_exponential_discount | c h^(κ u); **exponential-discount heuristic, not a Gaussian derivation** | κ ∈ {0, 0.5, 1, 2, 4, 8} | 6 | class |
| S0/S1/S2 `_key` variants | same formulas with h_key | same grids (S0_key untuned) | 1 / 8 / 6 | key |

The table has 20 rows because the three `_key` variants share one row.

- **Totals.** 157 candidates: 145 tuned per inner fold, plus 12 untuned references. Every untuned reference is scored on every outer fold. (Until WP4 a single pooled O_native_score made 156; see [wp4/fitting_specification.md](../wp4/fitting_specification.md) §2.)
- **Exact equivalences** (tested):
  - C with C_FP = 0 equals P.
  - C orders alerts identically to h(c + C_FP).
  - R_severity_key_reliability equals P with key-level h.
- **Matching granularity.** The identifier-level families R, S0_key, S1_key and S2_key form their own comparison block. They are never compared only with class-level SGFN.
- **Simplicity count (n_nonzero).**
  - W: nonzero weights among (α, 1 − α).
  - A: nonzero among (a, b, d).
  - M: nonzero among (a, b).
  - C, S1, S2: 1 if the parameter is nonzero.
  - L1 and L2: 0, so selection falls back to declared grid order (L1 C = 0.01 first; L2 depth 2 first).
- **Learned training data.**
  - Rows come from all training scenarios, ordered by tie hash. If there are more than 300,000, a seeded (42) uniform draw selects 300,000. No labels are involved.
  - Sample weights give each scenario equal total weight, with mean 1.
  - L1 standardization uses the unweighted sample mean and standard deviation.
  - If the training y has a single class, L1 scores p̄·c with the weighted training rate and logs `single_class_constant_probability`.
  - Convergence and coefficients are logged per fit.

## 5. Selection (protocol v1.1 §6.4)

**Primary rule**, applied identically to all 10 tuned families (`tuning.select_candidate`):
1. Highest macro critical-step interval coverage@100 over the common scenarios with at least one alert-containing critical interval.
2. Lowest macro FP@100 over all inner scenarios.
3. Highest macro linear NDCG@100 over the common scenarios with nonzero IDCG.
4. Fewest nonzero parameters.
5. Declared grid order.

**Tolerance.** Ties use an absolute tolerance of 1e-12 for roundoff only.

**Fallbacks.**
- If no inner scenario is coverage-eligible, step 1 is skipped and `coverage_fallback` is set.
- If eligibility differs across candidates, selection raises an error.
- The NDCG step is skipped, and flagged, when no inner scenario has nonzero IDCG.

**Secondary rule** (declared, cannot replace the primary): highest macro NDCG@100, then simplicity, then grid order. It uses the same inner predictions.

**Logged per selection:** macro values, denominator counts, candidates remaining after each step, and fallback flags.

## 6. Ordering and selection metrics

- **Order.**
  - Score descending, with missing scores last.
  - Then timestamp ascending.
  - Then SHA-256(`cose04000|` + alert_id), first 8 bytes, as an unsigned 64-bit integer. Uniqueness within each scenario is checked, and is satisfied on AIT.
  - `top_k_order` returns exactly the first k positions of the full order (tested under heavy ties).
- **Metrics at k = 100.**
  - Critical-step interval coverage: intervals covered by a top-k alert ÷ critical intervals containing any queue alert, NA if none. Coverage over all defined critical intervals is also logged.
  - FP@k = min(k, n) − Σ y.
  - Linear NDCG@k with IDCG from the same queue, NA if IDCG = 0.
  - Also logged: queue length, a short-queue flag, and the number of multi-interval alerts in the top k.
- **Deferred to WP3** (with hand-checked verification): recall curves, queue fractions, tie diagnostics and permutations, near-ties, within-detector native ordering, policy perturbations and final outer evaluation. `evaluate_outer_selection_metrics` exists only for synthetic checks.

## 7. Outputs and log schema

`write_fold_outputs` writes, per policy and outer fold:

| File | Content |
| --- | --- |
| `<policy>_outer_<v>_inner_metrics.csv` | One row per (inner scenario, tuned candidate): outer_held_out, policy, inner_scenario, family, candidate_id, params (JSON), grid_index, n_nonzero, coverage, coverage_all_defined, fp, ndcg, covered/eligible/defined intervals, queue_length, queue_shorter_than_k, multi_interval_alerts_in_top_k |
| `<policy>_outer_<v>_selections.csv` | One row per (family, rule): selected candidate, macro values, denominators, remaining-after-step counts, fallback flags |
| `<policy>_outer_<v>_outer_scores.npz` | `alert_ids` plus one score vector per outer candidate (untuned and every selected candidate) |
| `<policy>_outer_<v>_fit_records.json` | Outer fit set; per key: mapping support, positives, precision, purity, accepted, class, s, u_table, u_ambiguity, h and fallback, h_key and fallback, key counts, unclipped values; class-height table with numerators and denominators; priors; outer fallback and unmapped alert counts |
| `<policy>_outer_<v>_manifest.json` | Feature-request manifest (Section 3), learner diagnostics per role and candidate, runtime by family, label access log |

A complete synthetic example is in [example_logs/](example_logs/).

## 8. Verification

Run from the project root:

```sh
PY=/opt/anaconda3/envs/ids/bin/python
$PY -m unittest discover -s tests -v                        # 59 tests (43 WP2), 1 expected failure (historical NF-UQ sampling)
$PY scripts/revision/wp2_negative_controls.py                # injected faults must be detected
$PY scripts/revision/wp2_synthetic_pipeline_check.py         # all folds x both policies, synthetic
$PY scripts/revision/wp2_synthetic_pipeline_check.py --mode scale
$PY scripts/revision/wp2_freeze_grid_registry.py             # verifies the frozen registry is unchanged
$PY scripts/revision/wp2_run_comparison.py --construction-check
```

| Area | Tests (all synthetic or hand-built) |
| --- | --- |
| Config and families (`test_wp2_config_families.py`) | Protocol grid sizes; unique IDs; simplex sums; seven drift edits rejected; simplicity counts; heuristic labels; hand-calculated values for 16 score forms; exact equivalences; native missing scores kept and ordered last; domain errors without clipping; label-free and row-order-invariant training sample; equalizing weights; single-class L1 fallback |
| Labels, ordering, metrics (`test_wp2_labels_ordering_metrics.py`) | Duplicate and repeat intervals; unknown phase and zero-length rejected; all-containing half-open labels with max severity; salted SHA-256 tie keys; order rule and row-order independence; exact top-k under heavy ties (30 random trials × 6 k); coverage, FP and NDCG by hand; NA and short-queue cases |
| Fitting and isolation (`test_wp2_fitting_isolation.py`) | Mapping thresholds, purity, alphabetical ties, summing; shrinkage, priors, clipping, fallback order, `FitFailure`; key heights; fit-set objects computed with all outside scenarios locked; training features unchanged when own labels mutate; sensitivity to permitted labels; learned sample features equal isolated features and are label-independent; locked reads raise; held-out never read during a fold; inner labels read once, after fitting; held-out mutation leaves inner metrics, selections, learners and outer scores identical; inner-label mutation leaves that fold's features and learners unchanged |
| Tuning (`test_wp2_tuning.py`) | Coverage dominance; each tie-break step; macro (not pooled) averaging; tolerance boundary; common eligibility and denominators; coverage and NDCG fallbacks; inconsistent or incomplete tables rejected; secondary rule |
| Pipeline (`test_wp2_pipeline.py`) | Output structure (145 × inner folds, 2 rules × 10 families, every outer candidate); determinism; secondary policy changes c and u but not h; output files |

**Negative controls** ([negative_controls.json](negative_controls.json)). Each injected fault makes at least one test fail:

| Injected fault | Tests failing |
| --- | --- |
| Held-out labels leak into outer features (locks disabled) | 2 of 4 |
| Training scenario's own labels shape its learned-ranker heights | 1 of 1 |
| Hash tie-break dropped | 1 of 3 |
| FP tie-break direction reversed | 3 of 7 |
| Coverage denominator uses all defined intervals | 2 of 2 |

**Synthetic all-fold check** (`results/revision_cose_04000/wp2/synthetic_check`): 4 scenarios × both policies. Every fold completes with 435 inner rows and 20 selections, and zero held-out label reads during the fold.

**Scale benchmark** ([synthetic_scale_benchmark.json](synthetic_scale_benchmark.json)): 2,640,000 synthetic alerts in 8 scenarios, one outer fold. Setup took 7.4 s and the fold 37.7 s (learned fitting 21.7 s), with peak RSS 3.5 GB. The estimate is about 5 minutes per policy for all outer folds.

**Real-data construction check** ([real_data_construction_check.json](real_data_construction_check.json)). It verified the cache SHA-256 and the `labels.csv` Zenodo MD5, then built the ranking frame and interval table only:
- 2,655,821 alerts in 8 scenarios.
- 93 keys (Wazuh 24, Suricata 35, AMiner 34); tie hashes unique within scenarios.
- 79 label rows, 79 intervals after de-duplication, 32 critical at τ = 8, 0 overlapping pairs.

No feature was fitted, no candidate scored and no metric computed. This check exposed the WP0 overlap error recorded in the audit errata.

## 9. Gate to comparative runs

`scripts/revision/wp2_run_comparison.py` without `--construction-check` refuses to run unless all three hold:
1. `docs/revision/wp3/metric_verification.json` exists with `"verified": true`.
2. `docs/revision/wp4/fitting_boundary_verification.json` exists with `"verified": true`.
3. The config reproduces the frozen grid registry.

Before the final comparisons, WP3 must add and verify the full metric contract, and WP4 must verify the fitting boundaries on the real split manifests. That includes the scenario data table, unseen-key definitions and calibration diagnostics.

## 10. Implementation clarifications

These are not stated verbatim in protocol v1.1. They were decided before any revised result existed and are logged in the protocol change log.

1. **Mapping phase counts** use all containing intervals; phase ties resolve alphabetically. On AIT there are no overlaps, so each alert has at most one phase.
2. **Identifier-granularity block.** S0_key (untuned), S1_key and S2_key (same grids as S1 and S2) are the SGFN variants at identifier granularity, alongside R.
3. **Untuned references are not scored in inner folds**; only tuned families enter selection.
4. **L1** standardizes on the unweighted training sample, and falls back to a constant weighted rate for single-class training data. **L2** has early stopping disabled.
5. **The learned-sample draw** orders rows by tie hash before the seeded draw, so it does not depend on row order.
6. **Unseen keys** in the R and `_key` families use the pooled detector prior, then the global prior.
7. **Within-detector native ordering** (§5) is an evaluation on detector subsets, implemented in WP3, not a separate family.
8. **WP4 changes** (native-score correction, split machinery, ablation policies, traces): see [wp4/fitting_specification.md](../wp4/fitting_specification.md). They supersede items above where they conflict.

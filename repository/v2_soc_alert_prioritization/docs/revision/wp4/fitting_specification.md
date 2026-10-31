# WP4 fitting specification (COSE-D-26-04000)

Version 1.0, 14 September 2026. Stage 1 of WP4: fitting boundaries and input provenance. This document specifies every fitted quantity, which data may enter it, how the declared generalization splits restrict those data, and how execution is verified. It refines protocol v1.1 §2, §6 and §7 (change-log entry "WP4 stage-1 corrections and clarifications") and does not change any selection rule, grid or metric.

**No comparative result was produced.** Everything below was checked with synthetic fault injection, raw-data provenance, and real-data fitting chains that fit every component but score no candidate and compute no metric.

**Code.** `src/soc_alert_ranking/revision/{features,pipeline,splits,labels,native_scores,families}.py`. Exact hashes are in [fitting_boundary_verification.json](fitting_boundary_verification.json).

## 1. Information boundary

- **Ranking-time inputs.** Only these columns enter fitting or scoring (`features.RANKING_TIME_COLUMNS`): alert_id, scenario, timestamp, detector, native_key, native_category, native_name, native_short, host, ip, the historical detector_score (provenance only, never ranked), native_rule_level, native_suricata_severity, native_record_type. Loader labels, inferred phases and any other evaluation column are dropped before the ranking frame is built.
- **Labels.** Interval labels (y, s\*, z, r, phase and critical-interval membership; metric contract §2–3) are reachable only through `LabelStore.get(scenario, purpose)`.
  - Every read is logged with its purpose.
  - A locked scenario raises `LabelAccessError`.
  - Label arrays are read-only; a change must go through `LabelStore.replace`, which increments the scenario's label version.
- **Fit specification.** Every fitted quantity is a function of:
  - a fit set F of scenarios;
  - an excluded-identifier set E;
  - the fitting settings (thresholds, λ, clip bounds, uncertainty weights);
  - the severity table;
  - the reliability variant.

  A fitted quantity is applied only to scenarios outside F.
- **Caches.** Mappings and key features are cached under (F, label version of every scenario in F, E, settings digest, severity digest, number of keys), with the reliability variant added for key features. Key tables are cached under (scenario, label version). Changing any of these recomputes the fit. Context and uncertainty variants are applied after the cached fit and never alter it.

## 2. Native-score provenance

The historical `detector_score` pooled two score types inside the loader's Suricata group ([native_score_provenance.json](native_score_provenance.json); full table in metric contract §9):

| Record type | Keys | Alerts | Raw score | Historical value |
| --- | ---: | ---: | --- | --- |
| Wazuh rule alert | 24 | 1,986,905 | rule.level 3–10 | rule.level |
| Suricata eve.json signature alert (Wazuh rule 86601) | 29 | 306,635 | data.alert.severity 1–3; wrapper rule.level always 3 | (5 − severity)/4 = 0.5–1.0 |
| Suricata fast.log line (Wazuh IDS rules 20100–20162) | 6 | 306,723 | rule.level 6–11; no data.alert | rule.level |
| AMiner | 34 | 55,558 | none | missing |

**Evidence.**
- Raw files were re-read in loader order; the alignment of alert_id, scenario, detector, native_key and timestamp is exact for every alert.
- The pooled value is re-derived exactly from the separated fields.
- The two Suricata ranges are distinct score types from distinct log sources, not a parse error.

**Resolution** (applied to every method and report):
- `O_native_rule_level` ranks by Wazuh rule.level, one scale, for all Wazuh-delivered alerts.
- `O_native_suricata_severity` ranks by −severity on eve.json alerts.
- Missing values are ordered last. No label-dependent transform is used, and the pooled score is not ranked.
- The registry was re-frozen at 157 candidates; the 145 tuned candidates are unchanged.
- The WP3 contract (v1.1) and its verification record were regenerated.

`native_scores.load_revised_alerts` checks both cache identities, the provenance cache's parent hash and row alignment, and derives the record type from raw location and severity presence. It refuses any disagreement.

## 3. Fitted components

Let T(s) be the key table of scenario s: for each native key k, the alert count n, the observed positives Σy, and the per-phase positives (all containing intervals). Keys in E are zeroed in every table before any use.

### 3.1 Native-key mapping M(F)

Over the tables of F, for each key:
- support = Σn;
- positives = Σy;
- precision = positives / support;
- top phase = the largest phase count, ties alphabetical;
- purity = top count / positives.

A key is mapped to its top phase if support ≥ 5, positives ≥ 3, precision ≥ 0.5 and purity ≥ 0.7. Otherwise it is `unknown`. M(∅) maps nothing.

### 3.2 Class reliability heights H(F), cross-fitted

- **Rows.** For each j ∈ F, the rows of T(j) are classed with **M(F − {j})**. A row's own labels therefore never choose its class, and nothing outside F enters any mapping used for these heights.
- **Cells.** Pooled over j, a cell (group, class) has numerator Σy and denominator Σn.
  - `detector_class` (primary) groups by (detector, class).
  - `global_class` groups by class across detectors.
  - `detector_only` groups by detector.
- **Priors.**
  - The detector prior is the pooled Σy/Σn over all permitted rows of that detector in F.
  - The global prior pools all permitted rows.
  - `detector_class` uses the detector prior; the other two groupings use the global prior.
- **Estimate.** With w = n/(n + 50), the unclipped estimate is w·(Σy/n) + (1 − w)·prior, and the height is clipped to [0.05, 0.95]. Numerators, denominators, priors, unclipped and clipped values are all saved.
- **Application.** A key's height comes from the cell of its class under **M(F)**. When that cell was not observed, the fallback is:
  - code 1: the detector prior, clipped (`detector_class` only);
  - code 2: the global prior, clipped.
  
  With no permitted labels at all, `FitFailure` is raised.
- **Interpretation.** h estimates P(interval-labeled positive | detector, mapped class) on the training scenarios. It is not a probability that an individual alert is malicious. Its calibration quality can be assessed only against held-out y in stage 2, and is reported separately from mapping coverage (the label-free share of held-out alerts mapped to a class).

### 3.3 Key reliability K(F)

- **Estimate.** Per key over the tables of F, w·(Σy/n) + (1 − w)·detector prior with w = n/(n + 50), clipped.
- **Fallback.** A key with n = 0 in F takes the clipped detector prior (code 1), else the clipped global prior (code 2).
- **Use.** This is the h_key of the R and `_key` families, and the `native_key` calibration variant.

### 3.4 Severity, uncertainty and context

- **Severity.** s = configured phase severity of the mapped class, or 5.0 for `unknown`. c = s·q, with q = 1 (flat) or the asset-profile factor (a label-free token rule).
- **Uncertainty variants.** Values below are for mapped keys. Unmapped keys have u = 0.5 except under constant 0.5 and zero.

  | Variant | u for mapped keys |
  | --- | --- |
  | table (primary) | configured phase uncertainty factor |
  | ambiguity_aware ("historical combined") | clip(table + 0.20(1 − precision) + 0.15(1 − purity), 0, 0.5) |
  | constant_0.5 | 0.5 for every key |
  | purity_only | 0.35(1 − purity) |
  | precision_only | 0.35(1 − precision) |
  | zero | 0 for every key |

- **Reliability `none`.** h = 1; this is the only variant whose domain admits h = 1.
- **Scaling.** c/10 and u/0.5 use declared ranges and are not fitted. L1 standardization is fitted on the learned training sample only; its scope is logged. L2 is unscaled.

## 4. Prediction roles

For an outer split with held-out scenario v, training scenarios S and excluded identifiers E:

| Role (trace label) | Target | Fit set F | Labels read |
| --- | --- | --- | --- |
| `<split>:outer_validation` | v | S | none of v (locked for the whole fold) |
| `<split>:training_features` (outer learned models) | g ∈ S | S − {g} | g's y and r as targets, after its features are built |
| `<split>\|inner=i:validation` | i ∈ S | S − {i} | i is locked while features, learners and scores are produced, then read once for inner evaluation |
| `<split>\|inner=i:training_features` | g ∈ S − {i} | S − {i, g} | g's y and r as targets |

- **Learned training samples.**
  - Rows come from the fit scenarios, excluding every alert of an excluded identifier.
  - A hash-ordered, seeded (42) draw of at most 300,000 rows is taken, with scenario-equalizing weights.
  - The sampled scenarios, row counts, excluded-row count (must be 0) and standardization scope are logged.
- **Inner validation queues** omit alerts of excluded identifiers before scoring and evaluation, so those alerts' labels cannot influence selection.
- **Selection.** It is unchanged: primary and secondary rules on the frozen grids.
- **Expected fit sets of a split.** {S} ∪ {S − {g}} ∪ {S − {i}} ∪ {S − {i, g}}, the last only when learned inner selection is estimable. The real-data check requires the fit sets observed in the trace to equal this set exactly.

## 5. Declared experiments and their exclusion sets

| Experiment | Outer splits | E | Notes |
| --- | --- | --- | --- |
| Primary and secondary comparisons | LOSO, 8 folds | ∅ | frozen primary (flat + table) and secondary (asset_profile + ambiguity_aware) policies |
| Calibration ablation | LOSO | ∅ | detector_class, global_class, detector_only, native_key, none; full nested selection per variant |
| Uncertainty ablation | LOSO | ∅ | table, constant_0.5, purity_only, precision_only, historical combined, zero; all methods receive the same u |
| Context ablation | LOSO | ∅ | flat versus asset_profile (table uncertainty) |
| Seen versus unseen identifiers | LOSO | ∅ | unseen = (detector, native_key) absent from S; reported within the subgroup and as subgroup retrieval in the mixed queue (metric contract §9a) |
| Strict identifier hold-out | LOSO × 5 groups (40 folds) | all keys of group g | identifier = detector plus first identifier field of the native key; group = SHA-256(identifier) mod 5 |
| Forward chaining | eligible test scenarios | ∅ | fit only on scenarios whose alert-timestamp extent ends strictly before the test extent starts; eligible with ≥ 2 |
| Duplicates | as the base experiment | ∅ | evaluation units only (metric contract §10); fitting always uses raw alerts |

**Strict identifier hold-out.**
- Group g's alerts are removed from mapping tables, cross-fitted height rows, detector and global priors, key heights, learned training samples and inner validation queues. Nested selection is rerun with the exclusion.
- The outer queue keeps these alerts, which receive the declared unmapped handling:
  - c = 5 (times q);
  - u = 0.5 (variant rules apply);
  - h from the (detector, unknown) cell, or a prior;
  - h_key from the detector or global prior.
- **Group sizes are very unequal** ([split_manifests.json](split_manifests.json)):

  | Group | Keys | Alerts (all scenarios) |
  | ---: | ---: | ---: |
  | 0 | 15 | 496,247 |
  | 1 | 16 | 1,702,148 |
  | 2 | 20 | 21,326 |
  | 3 | 17 | 152,208 |
  | 4 | 25 | 283,892 |

  Removing group 1 withholds most of the stream from fitting.
- **Near-equivalent identifiers are not merged**, because the protocol groups by identifier. They fall into different groups, so related content can remain in fitting:

  | Pair | Groups |
  | --- | --- |
  | Wazuh correlation rules 20151/20161 | 4 / 2 |
  | Wazuh correlation rules 20152/20162 | 1 / 4 |
  | STUN request/response signatures 2016149/2016150 | 4 / 2 |

  This limits the hold-out to a new-identifier stress test, not a new-content or new-SOC test.

**Forward chaining** (extents from alert timestamps, label-free):

| Test scenario | Extent (UTC) | Fit scenarios | Eligible | Learned inner selection |
| --- | --- | --- | --- | --- |
| santos | 01-14 00:00 – 01-17 23:51 | — | no | — |
| fox | 01-15 00:00 – 01-19 23:55 | — | no | — |
| wardbeck | 01-19 00:00 – 01-23 23:59 | santos | no | — |
| russellmitchell | 01-21 00:00 – 01-24 23:39 | fox, santos | yes | not estimable: simplest grid point (L1 C = 0.01, L2 max_depth = 2) fitted on the two fit scenarios, logged (protocol §12) |
| shaw | 01-25 00:00 – 01-30 23:31 | fox, russellmitchell, santos, wardbeck | yes | yes |
| wheeler | 01-26 00:00 – 01-30 23:54 | fox, russellmitchell, santos, wardbeck | yes | yes |
| wilson | 02-03 00:00 – 02-08 23:50 | fox, russellmitchell, santos, shaw, wardbeck, wheeler | yes | yes |
| harrison | 02-04 00:00 – 02-08 23:59 | fox, russellmitchell, santos, shaw, wardbeck, wheeler | yes | yes |

This tests "no future scenario content in fitting". It is not a deployment chronology: scenario clocks are never concatenated.

**Seen versus unseen under LOSO is nearly empty on AIT.**

| Held-out scenario | Unseen identifiers | Unseen alerts |
| --- | --- | ---: |
| santos | 4 Suricata identifiers | 99 |
| wardbeck | 2 | 6 |
| wilson | 2 | 6 |
| shaw | 1 | 2 |
| fox, harrison, russellmitchell, wheeler | none | 0 |

Unseen-subgroup metrics are therefore mostly NA or based on a handful of alerts, and generalization to new identifiers rests on the strict hold-out.

## 6. Execution traces and their verification

- **Trace events** (`FeatureBuilder.trace`):
  - `fold_start`;
  - `table_read`: scenario, purpose, label version, excluded-key count, feature fit set, component, and for height rows the mapping set;
  - `fit`: mapping, class_heights with row sources, key_heights;
  - `learned_sample`: fit scenarios, rows per scenario, excluded rows in sample, standardization scope;
  - `inner_queue`: alerts and excluded alerts removed.
- **Feature-request manifest.** Each request records role, target, fit set, policy, reliability, excluded keys, mapping fit set, height row sources, key-height fit set and whether it was served from cache.
- **`pipeline.verify_fold_trace`** checks each executed fold against its split:
  - no target in its own fit set; the held-out scenario in no fit set, table read or label read;
  - mapping and key-height fit sets equal the request's fit set;
  - every height row source j is mapped with exactly F − {j}, and never with the target or the held-out scenario;
  - excluded identifiers equal the split's set in every request and every table read;
  - every table read lies inside its feature fit set;
  - role-specific fit sets for inner validation, training features and outer validation;
  - learned samples contain no excluded rows and no scenario outside the expected fit scenarios, including the standardization scope;
  - inner queues removed exactly the excluded identifiers' alerts;
  - an inner scenario's labels are never read for fitting inside its own validation fold;
  - completeness: every fit has its logged table reads, every uncached request has its fits, and every learned fit has its logged sample.
- **What a trace cannot show.** It records what the code says it did. Defects that keep the trace truthful-looking (a wrong mapping inside a height fit, exclusion applied to the log but not to the data, stale caches) are caught only by behavioural tests. Section 7 lists them; 16 of the 19 negative controls inject defects that trace verification alone would not reveal.

## 7. Verification evidence

| Check | Where | Result |
| --- | --- | --- |
| Adversarial changes to excluded data (synthetic): mutate labels, delete rows, add rows including a new identifier; identifier-level and class-level exclusion; class-level and key-level reliability; whole nested folds compared on inner metrics, selections, learned fits and outer scores | `tests/test_wp4_fitting_boundaries.py` (ExcludedIdentifierData, ExcludedIdentifierPipeline) | unchanged; the same changes do alter fits when not excluded |
| Cache invalidation: fit population, label version, exclusion set, reliability, settings, severity table; read-only labels | CacheInvalidation | pass |
| Reliability arithmetic versus an independent per-alert reference (numerators, denominators, priors, shrinkage, clipping, fallback codes), three groupings and key heights; unseen class; unseen detector; empty, fully excluded and single-class training; uncertainty variants; heights ignore non-label columns | `tests/wp4_reference_fitting.py`; ReliabilityArithmetic | pass |
| Splits: strict forward precedence, protocol hash groups, hold-out partition, unseen mask, simplest-grid-point learned fallback | SplitMachinery | pass |
| Executed traces pass for LOSO, hold-out and every ablation policy; 11 kinds of forged trace rejected | TraceVerification | pass |
| Negative controls: 19 injected defects | [negative_controls.json](negative_controls.json) | all detected |
| Real data: fitting chains for every declared split and policy; expected fit sets; independent pandas recomputation of every mapping and height used by LOSO, each hold-out exclusion and forward chaining; adversarial and cache checks; label-free coverage | [real_data_fitting_check.json](real_data_fitting_check.json); [split_manifests.json](split_manifests.json); per-chain traces in `results/revision_cose_04000/wp4/fitting_chain_traces/` | see the verification record |
| Native-score provenance | [native_score_provenance.json](native_score_provenance.json) | exact alignment and re-derivation |

Reproduce from the V2 project root:

```sh
PY=/opt/anaconda3/envs/ids/bin/python
$PY scripts/revision/wp4_native_score_provenance.py
$PY -m unittest discover -s tests -v
$PY scripts/revision/wp4_negative_controls.py
$PY scripts/revision/wp4_fitting_boundary_check.py --workers 4
$PY scripts/revision/wp3_write_verification_record.py
$PY scripts/revision/wp4_write_verification_record.py
```

## 8. Limits

- **Proxy target.** Interval labels remain temporal proxies, so reliability heights inherit them.
- **LOSO unseen subgroups.** They are nearly empty on AIT (Section 5).
- **Hold-out groups.** They are hash-assigned and very unequal in size, and near-equivalent identifiers can straddle groups.
- **Forward chaining.** It has one two-scenario fit (russellmitchell); its learned families use a fallback rather than selection.
- **Deferred scope.** The expanded operational vector of protocol §6.2 is deferred, unimplemented scope for this revision (protocol amendment of 2026-09-15). It was never specified, run or reported.

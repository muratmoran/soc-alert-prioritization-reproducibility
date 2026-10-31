# WP4 stage 2 results: prespecified AIT comparisons (COSE-D-26-04000)

15 September 2026.

> **Corrections (15 September 2026, WP9 submission-readiness check).** The statements below overstated the evidence. The original text is kept unchanged further down (pre-correction copy: `../wp9/superseded/2026-09-15_pre_wp9_wp4_stage2_results.md`). No output, table or selection changed; each correction is read from the existing stage-2 tables.
> 1. **Learned rankers (Two groups of methods; Findings).** L1 and L2 do **not** cover the same one interval per scenario. At k = 100 in R1 they cover 5 and 7 of 32 ([r1_t1_primary_long.csv](stage2_tables/r1_t1_primary_long.csv)). The 8-of-32 group is the class-level *formula* scores P, H, W, A, C, M, S0, S1 and S2. The learned scoring forms therefore do change class-level coverage.
> 2. **Ties (Section 2.2).** The class-level top 100 does **not** lie inside one score block, and the cutoff block is not the highest cell. At least 99% of top-100 positions lie in tied blocks for every class-level formula score. The tied block crossing position 100 (up to 430,178 alerts) supplies 85–97 positions for P (median 96.5) and as few as 37 for the selected A and M candidates. The rest come from higher-scoring tied blocks (`order_share` and `members_selected_by_tie_rule` in [r1_t2_ties.csv](stage2_tables/r1_t2_ties.csv)). "Inside one tied block" should read "inside the tied block that crosses position 100". The expected FP of about 0.6 means nearly all declared false positives come from that block.
> 3. **Deferral (T5).** The 9,047 / 98.3% figures are tabulated for P, H, W, A, S0, S1 and S2 (and O_severity). M, C, L1 and L2 are not in T5.
> 4. **Strict identifier hold-out (R6).** Besides P, C also drops to 2 of 32 when group 1 is held out. L1 (5–7 per group) and L2 (1–7 per group) do not keep one interval per scenario ([r6_t1_primary_long.csv](stage2_tables/r6_t1_primary_long.csv)).

**How these results were produced.**
- Everything reported was produced under [stage2_reporting_specification.md](stage2_reporting_specification.md) (SHA-256 `b50ab1b3…`), declared before any comparative result.
- The comparison gate was opened by [metric_verification.json](../wp3/metric_verification.json) and [fitting_boundary_verification.json](fitting_boundary_verification.json).
- Protocol v1.1 and the frozen 157-candidate registry (`e2f088ed…cb23a`) were used unchanged. No grid, rule, run or diagnostic was changed after results were seen.
- Generated tables (CSV and [stage2_tables.md](stage2_tables/stage2_tables.md)) are in [stage2_tables/](stage2_tables/). Output provenance is in [stage2_output_manifest.json](stage2_output_manifest.json).

**Language.**
- **Coverage.** A covered critical-step interval means that an alert ranked in the top 100 lies inside that interval's time window. It does not mean the attack step was identified.
- **Heights.** h is a shrunk frequency of interval labels, not a probability of maliciousness.
- **Units.** Scenarios are the units of analysis. With four critical intervals per AIT scenario, per-scenario coverage moves in 25-point steps, so covered counts are shown.
- **Inference.** No significance test is reported; paired tests are WP7.

## 1. Execution

- **Folds.**
  - 141 of 141 declared folds completed with no errors: R1 8, R2 8, R3 32, R4 40, R5 8, R6 40, R7 5.
  - Every executed fold's trace was verified against its split before evaluation.
- **Failures and fallbacks** ([t4_failures.csv](stage2_tables/t4_failures.csv)):
  - no learned-model fit failures and no empty queues;
  - no NA primary metrics (every scenario has 4 critical intervals, all containing alerts);
  - no coverage or NDCG selection fallbacks.
- **Declared fallbacks that occurred:**
  - R7 russellmitchell has two fit scenarios, so L1 and L2 used their simplest grid points (4 selection records);
  - the 113 alerts of the 9 LOSO-unseen identifiers took the detector-prior key height;
  - R7 had 2 class-height detector-prior alerts;
  - in R6 every held-out-group alert (2.66 M across the 40 folds) took fallback inputs by design.
- **Storage.** Outputs were written under `results/` and then copied with integrity checks to `~/soc_revision_data/wp4_stage2`, because iCloud had evicted the originals to placeholders. The copy's SHA256SUMS hash is recorded in the output manifest.

## 2. Primary comparison (R1: flat + table, primary selection rule)

### 2.1 Covered critical intervals and FP@100 per scenario (T1)

| Method | fox | harrison | russellmitchell | santos | shaw | wardbeck | wheeler | wilson | Intervals covered (of 32) | Median FP@100 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: |
| S1_key (primary rule) | 3 · 77 | 3 · 50 | 3 · 81 | 3 · 73 | 1 · 90 | 2 · 79 | 3 · 70 | 3 · 77 | 21 | 77 |
| S2_key (primary rule) | 3 · 77 | 3 · 50 | 3 · 81 | 3 · 73 | 1 · 90 | 2 · 79 | 3 · 70 | 3 · 77 | 21 | 77 |
| S0_key (κ = 1) | 3 · 77 | 3 · 61 | 3 · 85 | 3 · 76 | 1 · 90 | 2 · 79 | 3 · 76 | 3 · 77 | 21 | 77 |
| R_severity_key (c·ĥ_key) | 3 · 77 | 1 · 72 | 2 · 53 | 3 · 86 | 1 · 90 | 2 · 86 | 3 · 70 | 3 · 78 | 18 | 77.5 |
| P = h·c | 1 · 19 | 1 · 17 | 1 · 8 | 1 · 8 | 1 · 40 | 1 · 95 | 1 · 10 | 1 · 41 | 8 | 18 |
| H (0.7c + 3h), S0, S1, S2, C, M (primary rule) | as P (M, C: FP within ±2) | | | | | | | | 8 | 18 |
| W (primary rule) | 1 · 19 | 1 · 17 | 1 · 8 | 1 · 8 | 1 · 40 | 1 · 97 | 1 · 10 | 1 · 35 | 8 | 18 |
| A (primary rule) | 1 · 17 | 1 · 17 | 1 · 8 | 1 · 8 | 1 · 40 | 1 · 97 | 1 · 10 | 1 · 35 | 8 | 17 |
| L2 (primary rule) | 1 · 19 | 1 · 17 | 1 · 8 | 1 · 8 | 0 · 40 | 1 · 97 | 1 · 10 | 1 · 41 | 7 | 18 |
| L1 (primary rule) | 1 · 19 | 1 · 17 | 1 · 8 | 1 · 8 | 0 · 40 | 0 · 100 | 0 · 10 | 1 · 41 | 5 | 18 |
| O_severity (c) | 1 · 96 | 1 · 96 | 1 · 97 | 1 · 97 | 1 · 97 | 1 · 95 | 1 · 97 | 1 · 96 | 8 | 96.5 |
| O_reliability (h) | 0 · 14 | 0 · 17 | 0 · 8 | 0 · 8 | 0 · 40 | 0 · 100 | 0 · 10 | 0 · 30 | 0 | 15.5 |
| R_key_reliability (ĥ_key) | 0 · 73 | 0 · 61 | 0 · 41 | 0 · 90 | 0 · 74 | 0 · 100 | 0 · 44 | 0 · 61 | 0 | 67 |
| O_native_suricata_severity | 1 · 75 | 0 · 88 | 0 · 73 | 0 · 85 | 0 · 100 | 0 · 91 | 0 · 76 | 0 · 73 | 1 | 80.5 |
| O_native_rule_level | 0 · 100 | 0 · 100 | 0 · 100 | 0 · 100 | 0 · 100 | 0 · 99 | 0 · 100 | 0 · 100 | 0 | 100 |
| O_oldest_first, O_newest_first | 0 · 100 everywhere | | | | | | | | 0 | 100 |

Cells show intervals covered (of 4) · FP@100. Full rows with candidate ids are in [r1_t1_primary.csv](stage2_tables/r1_t1_primary.csv).

**Two groups of methods.**
- **Class-level methods** cover the same one interval per scenario.
  - This includes P, H, W, A, C, M, S0, S1, S2 and the learned rankers, and all use class reliability h.
  - Selection chose κ = 0.3–0.4 for S1 and κ = 0.5 for S2. Inner coverage tied across most candidates (all 8 S1 values, 8–9 of 11 W values, 34–37 of 66 A values), so FP decided.
- **Identifier-level variants** cover 3 of 4 in six scenarios and 21 of 32 overall.
  - This includes S0_key, S1_key and S2_key, which use key reliability ĥ_key.
  - They carry about four times the median FP@100 (77 against 18).
  - Neither group dominates the other on the declared pair (coverage, FP).

### 2.2 Ties beside the primary table (T2, k = 100)

| Method | Top-100 positions inside tied blocks | Block crossing k = 100 | Median cutoff block | Covered over 100 seeds (sum over scenarios, min–max) | Declared FP (median) | Exact expected FP under random tie order (median) | Near-tie (4 s.f.) covered |
| --- | --- | --- | --- | --- | ---: | ---: | --- |
| P, H, S0, S1, S2, W, C | 100% in every scenario | 8 of 8 | 213,202 alerts | 8–8 | 18 | 0.60 | 8 |
| A, M | 100% | 8 of 8 | 213,202 | 8–8 | 17–18 | 0.59 | 8 |
| S1_key, S2_key | 97% | 6 of 8 | 24 | 21–22 | 77 | 77 | 21 |
| S0_key | 97% | 6 of 8 | 5,549 | 21–21 | 77 | 68 | 21 |
| O_severity | 100% | 8 of 8 | 102,064 | 8–20 | 96.5 | 94.4 | 8 |
| O_native_rule_level | 100% | 8 of 8 | 680 | 0–4 | 100 | 87.2 | 0 |

**What the tie diagnostics show.**
- **Class-level top 100s are decided by the tie rule.** For class-level methods the entire top 100 lies inside one score block of up to 430,178 alerts: the highest class-height × severity cell.
  - Which 100 alerts are shown is decided by the declared chronological rule (oldest first, then hash).
  - Their coverage is the same under all 100 within-block permutations.
  - Their FP@100 is not. Under random order within the block, expected FP@100 is about 0.6 (median; 0–11 by scenario), because that block is 99.9% interval-labeled positive. Under the declared oldest-first order, the block's earliest alerts are disproportionately interval-labeled negatives.
  - Declared-order FP for class-level methods therefore largely reflects chronology inside one tied block, not score discrimination.
- **Identifier-level variants are much less tie-dependent.** Small cutoff blocks give expected FP equal to declared FP, and coverage varies by at most one interval.
- **O_severity coverage is highly tie-dependent.** It ranges from 8 to 20 covered intervals across seeds.

### 2.3 Deep queue and critical-alert deferral (T3, T5)

**Deep-queue effort** (median over scenarios):

| Method | Critical recall at k = 100 | Queue fraction to 50% critical recall | Queue fraction to 90% |
| --- | ---: | ---: | ---: |
| P, H, S0, S1, S2, W, A, M, C | 0.005 | 0.879 | 0.897 |
| S1_key | 0.023 | 0.325 | 0.458 |
| S2_key, S0_key, R_severity_key | 0.014–0.023 | 0.879 | 0.898 |
| O_severity | 0.005 | 0.407 | 0.468 |
| O_oldest_first | 0 | 0.615 | 0.822 |

**Deferral** (T5):
- Class-level methods rank **9,047 of 9,204 critical alerts (98.3%) beyond half the queue**. O_severity defers 1,907 (20.7%).
- **Causes** among the 9,047 deferred alerts:
  - 8,999 belong to identifiers the fold's mapping rejected: 8,996 fail precision < 0.5, 8,856 fail purity < 0.7, and 12 have fewer than 3 positives;
  - none are mapped-but-low-height;
  - 1,759 sit in a tied block crossing the half-queue cutoff.
- **Severity reversal.** It explains the deferral for S0 only, where γ = 1 + u·ln h ≤ 0 for 9,072 of 9,204 critical alerts (98.6%). It is 0 for every selected S1 and S2 candidate. The constrained heuristics remove reversal without changing which alerts are deferred.
- **Unmapped subgroup** (E7, retrieval in the mixed queue).
  - 9,072 of the 9,204 critical alerts are unmapped.
  - P places no unmapped alert in any top 100.
  - S1_key places 751 unmapped alerts across the eight top 100s and covers 20 of 32 unmapped-eligible intervals.
- **Calibration context** (E9). Unmapped alerts receive h = 0.05; 908,544 held-out alerts are in that bin, with a 2.1% interval-positive share.
- **Reading.** On AIT the critical dnsteal and related alerts come from high-volume identifiers whose training-scenario interval precision is low. Class reliability therefore places them at the floor. This is the historical-rule-precision mechanism, not the SGFN interaction.

## 3. What drives the result

| Run | Change | Class-level coverage (of 32) and median FP | Identifier-level coverage and FP |
| --- | --- | --- | --- |
| R1 | primary | 8 · 18 | S*_key 21 · 77 |
| R3 native_key | class methods use key precision ĥ as h | P 18 · 77.5; H, W, S0, S1, S2 21 · 77 | unchanged |
| R3 global_class, detector_only, none | coarser or no reliability | 8 · 96.5 for P, H, W, S0, S1, S2 (A 8 · 18–66; L2 6–7 · 29.5–97) | unchanged |
| R4 constant_0.5 | u = 0.5 everywhere | 8 · 17–18 | 21 · 77 |
| R4 purity_only | u variant | 8 · 8.5–10 for S0/S1/S2 and A; 18 for P, H, W | 21 · 68–77 |
| R4 historical combined | u variant | 8 · 4–8 for S0/S1/S2 and A; 18 for P, H, W | 21 · 72–77 |
| R4 precision_only | u variant | 8 · 0 for S0/S1/S2 and A; 18 for P, H, W | 21 · 64–77 |
| R4 zero | u = 0 | 8 · 96.5 for S0/S1/S2 (they reduce to c); 17–18 for P, H, W, A | 8 · 96.5 (S*_key reduce to c) |
| R5 asset_profile context | q from token rules | 8 · 17–21 (L2 6) | 21 · 76–80.5 |
| R2 secondary policy (asset_profile + ambiguity_aware) | historical selected policy | 8 · 4.5–21 | 21 · 51–79.5 |

**Findings.**
- **Coverage follows the reliability granularity.**
  - Any method given identifier-level precision covers 18–21 of 32 intervals; any method given class-level reliability covers 8.
  - Uncertainty and context variants never change coverage.
  - Across grids, the scoring form (additive, multiplicative, probability, cost, linear-log, exponential, learned) does not change class-level coverage.
- **Detector-class reliability mainly lowers FP@100.** Its FP of 18 against 96.5 for global, detector-only or no reliability comes largely inside the tied top block (Section 2.2).
- **Uncertainty can lower FP for u-using formulas.** Precision-only u drives FP@100 to 0 for S0, S1, S2 and A, at unchanged coverage. With u = 0 the identifier-level S variants reduce to severity ordering and lose their coverage. The identifier-level coverage of S*_key therefore needs the u·ln ĥ_key discount, whereas R_severity_key (c·ĥ_key) reaches 18 without u.
- **Ranking agreement with R1** (E10; median over scenarios):
  - Class methods under native_key share 3.5–46.5% of R1's top 100.
  - Under uncertainty variants they share 3.5–100% (3.5% for the S family at u = 0).
  - Under asset context they share 98–100%, except the key variants (52–58%).
- **Asset context mostly reflects signature content, not assets** (E11). q ≠ 1 for 2,558,589 of 2,655,821 alerts:
  - native key or category tokens alone supply the factor for 1,740,391 (almost all in the 0.9 tier of web/apache-type tokens);
  - host or IP alone for 530,701;
  - both for 287,497.
- **Secondary selection rule.** In R1, NDCG-only selection gives the same coverage as the primary rule for every family (class-level 8, identifier-level S1_key and S2_key 21). In R2 its S2_key selection covers only 8.

## 4. Generalization

- **Seen versus unseen identifiers under LOSO.**
  - 113 held-out alerts in total come from identifiers absent from training: 99 in santos, 6 in wardbeck, 6 in wilson, 2 in shaw. None is critical.
  - Within-subgroup metrics are therefore NA or based on a handful of alerts. The LOSO results say nothing about new identifiers.
- **Strict identifier hold-out** (R6; 40 folds; each fold's held-out identifier group is excluded from all fitting).

  | Method | Group 0 | Group 1 | Group 2 | Group 3 | Group 4 | All (of 160) |
  | --- | --- | --- | --- | --- | --- | --- |
  | S1_key covered (median FP) | 9 (84.5) | 20 (87.5) | 8 (79) | 8 (96) | 8 (96.5) | 53 |
  | P covered (median FP) | 8 (18) | 2 (9) | 8 (16.5) | 8 (64) | 8 (18) | 34 |
  | S1 covered (median FP) | 8 (18) | 8 (10) | 8 (16.5) | 8 (64) | 8 (18) | 40 |

  - When any group other than group 1 is held out, the identifier-level advantage disappears: 8–9 of 32 against 21 in R1.
  - The held-out identifiers receive the detector-prior key height and occupy 3,298 of the 4,000 top-100 positions of S0_key and R_severity_key (E7). Yet those alerts cover only 5 of 110 eligible held-out-group intervals.
  - Class-level methods keep their single interval per scenario in every group, except P when group 1 is held out (2 of 32; S1 keeps 8).
  - **The identifier-level coverage gain does not transfer to identifiers absent from training.**
- **Forward chaining** (R7; fit only on scenarios that end before the test scenario starts).

  | Method | russellmitchell | shaw | wheeler | wilson | harrison |
  | --- | --- | --- | --- | --- | --- |
  | S1_key | 3 · 81 | 1 · 94 | 3 · 74 | 3 · 77 | 3 · 50 |
  | P | 1 · 98 | 1 · 98 | 1 · 98 | 1 · 35 | 1 · 17 |

  - With 2–6 earlier fit scenarios, FP@100 of P and S1 rises to 98 in three scenarios (russellmitchell, shaw, wheeler), against 8–40 under LOSO. The low class-level FP depends on the training scenarios available.
  - The identifier-level variants keep 13 of 20 intervals.
  - russellmitchell used the simplest-grid-point fallback for L1 and L2.

## 5. Native references, detectors, duplicates and calibration quality

- **Native references** (E5).
  - Wazuh rule.level covers no interval in any scenario, whole-stream or within Wazuh; within Wazuh its FP@100 is 0–27.
  - Suricata signature severity covers one interval (fox) within Suricata eve.json alerts.
  - Rule level is constant (3) within eve.json alerts, so that ordering is an all-tie ordering.
  - Severity is undefined outside eve.json alerts: reported NA, not FIFO.
- **Duplicates** (E6).
  - Under representative-only and static-cluster units at 60, 300 and 900 s, P covers 8–9 of 32 intervals and S1_key covers 24 of 32.
  - FP@100 for P rises to a median of 50–75 once repeated alerts collapse into representatives. The low alert-level FP of class methods partly comes from repeats of the same attack alerts.
  - Mixed-label clusters remain rare (contract §10).
- **Calibration of h against held-out y** (E9, R1 and R3).

  | Reliability | Mean Brier | Range |
  | --- | ---: | --- |
  | detector_class | 0.0133 | 0.0054–0.0242 |
  | global_class | 0.0134 | — |
  | native_key | 0.0135 | — |
  | detector_only | 0.175 | — |
  | none | 0.556 | — |

  - The reliability diagram is bimodal: 908,544 alerts at h = 0.05 (y share 0.021) and 1,747,036 at h ≈ 0.95 (y share 0.999). Low Brier scores mostly reflect this separation between the unknown class and the mapped attack classes.
  - It does not show calibration at intermediate probabilities, which are nearly empty except under native_key.
  - Mapping coverage (share of held-out alerts mapped, mean over scenarios) is 43.6% for every variant and is reported separately.

## 6. Conclusion and consequences for the revision's claims

> On AIT, the tested SGFN interactions provide no demonstrated advantage over simpler scores. Identifier-level historical precision increases critical-interval coverage at the cost of more false-positive investigations, and that coverage advantage does not persist reliably under identifier hold-out.

1. **No demonstrated SGFN advantage.**
   - Class-level SGFN variants (S0, S1, S2) are indistinguishable from P, H, W, A, C and M at the primary endpoint in every scenario.
   - Uncertainty and context variants never change coverage.
2. **A tradeoff, not a winner.**
   - Identifier-level precision (ĥ_key) raises coverage at k = 100 from 8 to 21 of 32 intervals, but median FP@100 rises from 18 to 77.
   - Neither method group dominates on the declared (coverage, FP) pair, so identifier-level precision is not the overall winner.
   - Class-level FP differences are largely a chronological tie effect inside one tied block. The low FP expected under static tie permutations is a diagnostic, not an operational improvement.
3. **Deferral cause.**
   - Class reliability defers 98% of critical alerts to the back half of the queue, because critical identifiers have low training interval precision.
   - Constraining κ removes severity reversal without changing this deferral.
4. **Generalization.**
   - The identifier-level coverage advantage does not persist reliably under strict identifier hold-out: 8–9 of 32 in four of five groups.
   - LOSO contains only 113 unseen-identifier alerts, none critical. That is essentially no evidence about retrieving critical alerts from new identifiers, and generalization to new identifiers must not be claimed.
5. **Earlier claims not supported.**
   - "Asset context" is mainly signature tokens.
   - The "fuzzy representation" changes FP but not coverage.
6. **Deferred scope.** The protocol §6.2 expanded operational vector is deferred, unimplemented scope (amendment of 2026-09-15). It is not a completed or prespecified comparison.

These are descriptive, per-scenario static findings under interval-label proxies (protocol D4). Whether the tradeoff survives arrival order and limited investigation capacity is WP5. Paired inference across scenarios is WP7.

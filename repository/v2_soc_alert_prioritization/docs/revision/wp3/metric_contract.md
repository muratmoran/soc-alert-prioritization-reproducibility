# WP3 metric contract (COSE-D-26-04000)

Version 1.1, 14 September 2026. Governs every static queue metric, tie analysis, native-score comparison, subgroup analysis and duplicate analysis in the revision. It refines protocol v1.1 §4–§5 and §7.2 without changing any protocol decision.

**Changes from 1.0 (made in WP4 stage 1, before any comparative result):**
- §9 replaces the pooled native score with two single-scale native references traced to raw fields ([wp4/native_score_provenance.json](../wp4/native_score_provenance.json)); within-Suricata reporting is by raw record type.
- §9a adds subgroup retrieval in the original mixed queue, kept separate from within-subgroup ranking.

**Code.** `src/soc_alert_ranking/revision/{labels,metrics,evaluation,ties,duplicates,severity_variants,native_scores}.py`. Exact file hashes are in [metric_verification.json](metric_verification.json).

**No comparative result is produced or needed.** The AIT facts quoted here come from two method-independent checks, [label_verification.json](label_verification.json) and [structural_audit.json](structural_audit.json). Neither scores any method.

## 1. Terminology

| Term | Meaning | Must not be read as |
| --- | --- | --- |
| Interval-labeled positive (y = 1) | An alert whose timestamp lies in at least one attack interval of its scenario | A verified malicious alert, or an alert that identifies the attack step |
| Interval-labeled negative (y = 0) | An alert outside every attack interval; counted by FP@k | A verified benign alert |
| Critical alert (z = 1) | An interval-labeled positive with s\* ≥ τ | A confirmed high-impact event |
| Critical-step interval | A distinct critical interval (scenario, phase, start, end) | A confirmed attack discovery when "covered" |
| Queue | The ordered alerts of one scenario, or of one declared subset (Section 9: one detector or record type; Section 9a: one subgroup ranked alone; Section 10: representatives) | — |
| Budget k | Number of leading queue positions evaluated | — |
| NA | Not applicable: the metric's denominator is zero. Reported and counted, never replaced by 0 or 1 | — |

## 2. Label intervals

1. **Source.** `labels.csv` (Zenodo record 8263181; MD5 verified). Columns: scenario, attack (phase), start, end, in epoch seconds.
2. **De-duplication.** Rows identical in (scenario, phase, start, end) count once. Distinct rows of the same phase are separate intervals.
3. **Half-open intervals.** An interval covers timestamp t iff start ≤ t < end. A shared boundary (end of interval i equals start of interval j) belongs to j only.
4. **Every containing interval counts.** An alert's phases are all intervals containing its timestamp.
5. **File order has no effect.** Labels depend on interval content, not row order, and are verified invariant to reversed and shuffled row orders.
6. **Severity.** Phase severities come from `configs/severity_mapping.yaml` (`ait_attack_phase_severity`). An unknown phase is an error.

**AIT facts** ([label_verification.json](label_verification.json)):
- **Intervals.** 79 rows and 79 distinct intervals. No two intervals overlap, and 62 pairs are adjacent (end of one = start of the next).
- **File order.** Eight rows are out of chronological order: dirb after wpscan in wheeler and wilson, and privilege_escalation before the earlier service_stop row in six scenarios. This does not affect labels.
- **Criticality by τ.** 40 critical intervals at τ = 7, 32 at τ = 8, 24 at τ = 9.
- **Scenario composition.** Every scenario has 4 critical intervals at τ = 8 (webshell, reverse_shell, privilege_escalation, dnsteal), and all 32 contain at least one alert.
- **Unequal windows.**
  - dnsteal windows last 3,312–7,200 s (median 3,600) and hold 23–3,239 alerts each (8,630 in total).
  - webshell, reverse_shell and privilege_escalation windows last 12–88 s and hold 1–94 alerts each.
- **Boundary alerts.** 1,028 alerts lie exactly on an interval start and 1,022 exactly on an end; all are assigned by the half-open rule with zero violations. The convention changes interpretation for two groups:
  - **6 alerts** at a webshell end that is also a cracking start are non-critical. A closed-end convention would make them critical.
  - **19 alerts** at a reverse_shell end that is also a privilege_escalation start cover the privilege_escalation interval, not reverse_shell.
- **Agreement with history.** The v1.1 rule reproduces the historical loader labels (y, s\*, z at τ = 8) exactly, in all 2,655,821 rows.

## 3. Per-alert evaluation quantities

| Symbol | Definition |
| --- | --- |
| y_i | 1 if any interval contains t_i, else 0 |
| s\*_i | maximum configured severity over intervals containing t_i; 0 if none |
| τ | criticality threshold; primary 8.0; sensitivity 7.0 and 9.0 |
| z_i | y_i · 1[s\*_i ≥ τ] |
| r_i | y_i · s\*_i (linear relevance) |
| g_i | 2^(r_i) − 1 (exponential gain; sensitivity only) |
| C | distinct critical intervals of the scenario (severity ≥ τ), whether or not they contain alerts |
| E(Q) | intervals in C containing at least one alert of queue Q |
| M_i | intervals in C containing t_i (possibly several if intervals overlapped; empty on AIT outside critical windows) |

## 4. Order and budgets

- **Declared order.** Score descending, missing scores last; then timestamp ascending; then the unsigned 64-bit integer formed by the first 8 bytes of SHA-256(`cose04000|` + alert_id). Hash uniqueness within each scenario is checked.
  - The order does not depend on row order.
  - Rank positions are 1-based: π(1) is the first alert.
- **Budgets.** k ∈ {10, 25, 50, 100, 250, 500, 1000}. For a queue of n alerts, k_eff = min(k, n).
  - `short_queue` is true when n < k; the queue is never padded.
  - `empty_queue` is true when n = 0.
- **Queue-fraction budgets.** f ∈ {1/1000, 1/100, 1/20, 1/10, 1/4, 1/2} gives k_f = max(1, ⌈f·n⌉) in exact integer arithmetic, NA for an empty queue. For example, n = 10 gives k = 1, 1, 1, 1, 3, 5.
- **Exact arithmetic.** All ceilings use integer arithmetic on fractions. For the declared fractions and every count up to 2,000,000, floating-point ceilings give identical values; this is tested.

## 5. Budgeted metrics

T_k denotes the first k_eff positions; P = Σ_Q y, Z = Σ_Q z, D(j) = 1/log₂(j + 1).

| Metric | Numerator | Denominator | Empty queue | Zero-positive case | Short queue |
| --- | --- | --- | --- | --- | --- |
| positives_in_top@k | Σ_{T_k} y | — | 0 | 0 | counts existing alerts |
| **FP@k** (negatives_in_top) | k_eff − Σ_{T_k} y | — | 0 | k_eff | counts existing alerts only |
| precision@k | Σ_{T_k} y | k_eff | NA | 0 when n > 0 | divides by k_eff, not k |
| attack recall@k (interval-labeled positive recall) | Σ_{T_k} y | P | NA | NA (P = 0) | ≤ 1; equals 1 if all positives fit |
| **alert-level critical recall@k** | Σ_{T_k} z | Z | NA | NA (Z = 0) | as above |
| **interval coverage@k (eligible)** | \|∪_{T_k} M_i\| | \|E(Q)\| | NA | NA (\|E\| = 0) | as above |
| **interval coverage@k (all defined)** | \|∪_{T_k} M_i\| | \|C\| | 0 if \|C\| > 0; NA if \|C\| = 0 | 0 if \|C\| > 0 | as above |
| **linear NDCG@k** | DCG = Σ_{j ≤ k_eff} r_π(j) D(j) | IDCG = Σ_{j ≤ k_eff} r_(j) D(j), with r sorted descending over Q | NA | NA (IDCG = 0) | both sums stop at k_eff |
| exponential NDCG@k (sensitivity) | same with g | same with g | NA | NA | as above |
| multi-interval alerts in top k | #{i ∈ T_k: \|M_i\| > 1} | — | 0 | 0 | — |

Every interval counts once in coverage, however long it is and however many alerts it holds. Two consequences:
- **Not discovery.** Covering an interval means some top-k alert lies inside it. It is a temporal coverage proxy, not confirmed attack discovery.
- **Denominators coincide on AIT.** Every critical interval contains alerts at τ = 8, so the two coverage denominators coincide there (\|E\| = \|C\| = 4 per scenario). Both are still reported; they can differ under subsets (Section 9) and other thresholds.

## 6. Queue-level metrics

- **First-critical rank.** min{j: z_π(j) = 1}, reported with prevalence Z/n.
  - With Z = 0 the rank is *none* (NA), prevalence is 0 when n > 0 and NA when n = 0.
  - An NA rank is never averaged as 0.
- **Effort to critical recall.** For each target ρ ∈ {1/2, 4/5, 9/10}, required = ⌈ρ·Z⌉ and position = min{j: Σ_{i ≤ j} z_π(i) ≥ required}.
  - Reported as the position and the queue fraction position/n.
  - NA when Z = 0.
- **Effort to interval coverage.** For each target ρ ∈ {1/2, 4/5, 1}, required = ⌈ρ·\|E\|⌉ and position = the smallest j at which ∪_{i ≤ j} M_π(i) contains `required` intervals.
  - NA when \|E\| = 0.
- **Complete report** (`metrics.queue_report`):
  - every k in the grid and every queue fraction, all Section 5 metrics;
  - first-critical rank;
  - all six efforts.

**Reporting hierarchy** (protocol v1.1 D2):
- **Primary:** interval coverage@100 (eligible) jointly with FP@100.
- **Always alongside:** coverage@100 over all defined intervals.
- **Key secondary, always retained:**
  - alert-level critical recall@100;
  - linear NDCG@100;
  - queue fractions to 50%, 80% and 90% critical recall.
- **Budget curves** over the full k grid and queue fractions for critical recall, attack recall, both coverages and FP.

## 7. Ties and ordering interpretations

### 7.1 Score blocks and diagnostics

A **score block** is a maximal set of alerts with identical scores. Missing scores form one block, placed last. Under the declared order, blocks occupy contiguous ranks. Per queue and method (`ties.tie_diagnostics`):

- **Block counts:**
  - distinct finite scores, missing scores, blocks, tied blocks (size > 1);
  - alerts in tied blocks and their share;
  - maximum and median block size.
- **Per budget k:**
  - `cutoff_block_size`: size of the block containing rank k_eff.
  - `crosses_cutoff`: that block has members at ranks ≤ k_eff and > k_eff.
  - `positions_in_tied_blocks` and `order_share`: top-k positions whose occupant comes from a block of size > 1, so its identity at that position is decided by timestamp and hash rather than by score; share = count / k_eff.
  - `members_selected_by_tie_rule` and `membership_share`: members of a cutoff-crossing block that fall inside the top k, i.e. alerts admitted to the budget by the secondary order; share = count / k_eff.

### 7.2 Within-key score constancy (checked per family and per policy)

Each family depends only on the per-alert inputs listed below:

| Family | Inputs |
| --- | --- |
| O_oldest_first, O_newest_first | timestamp |
| O_native_rule_level | Wazuh rule.level |
| O_native_suricata_severity | Suricata signature severity |
| O_severity | c |
| O_reliability | h |
| H, W, P, C | c, h |
| A, M, L1, L2, S0, S1, S2 | c, u, h |
| R_key_reliability | h_key |
| R_severity_key_reliability | c, h_key |
| S0_key, S1_key, S2_key | c, u, h_key |

Zero-weight terms are removed per candidate (e.g. W with α = 0 uses only h; S1/S2 with κ = 0 use only c).

A candidate's score is **guaranteed constant within a (scenario, native key) group** when none of its inputs varies within any such group. Class and key inputs h, h_key and u are key-level by construction, and c = s·q with s key-level and positive. Therefore c varies within a key exactly when q does.

**AIT, label-free** ([structural_audit.json](structural_audit.json)):

| Policy | Inputs varying within keys | Guaranteed key-constant candidates | May vary |
| --- | --- | --- | --- |
| Primary flat + table | timestamp only | 155 of 157 | O_oldest_first, O_newest_first |
| Secondary asset_profile + ambiguity_aware | timestamp, c | 16 of 157: O_native_rule_level, O_native_suricata_severity, O_reliability, R_key_reliability, W with α = 0, and the 11 A candidates with a = 0 | 141: every candidate that uses c (including S1, S2 and key variants at κ = 0, which reduce to c), plus O_oldest_first and O_newest_first |

- **q varies within 28 of 628 (scenario, key) groups**, containing 1,876 alerts (0.07%): 27 Wazuh groups and 1 AMiner group. The asset-context result must therefore be audited per group, not assumed from the primary policy.
- **Both native scales are constant within every key** (0 of 628 groups vary for rule.level and for Suricata severity), and every key has one raw record type.
- **Empirical check.** Tests fit every candidate on synthetic data under both policies. Every guaranteed-constant candidate is observed constant, and candidates that use c do vary under asset_profile.

Consequences under the primary policy on AIT:
- **Block size.** Every class- or key-level score block is a union of whole native keys. The largest key holds 31.7–80.3% of its scenario's alerts (80.3% in fox; 62.3–64.7% in harrison, wheeler and wilson).
- **Order within a block.** It is entirely chronological (oldest first), except where alerts share a timestamp. 44.7–96.7% of alerts share both key and timestamp with another alert (largest group 514), so the hash then decides.
- **Tie diagnostics are mandatory.** They are reported for every method, fold and policy, together with the permutation analyses of Section 7.3.

### 7.3 Three ordering interpretations (never interchangeable)

1. **Declared order** (Section 4). The operational policy and the only order for primary results.
2. **Expected tie-averaged metrics** (`ties.expected_under_random_ties`). Exact expectations when every score block is uniformly shuffled, for linear metrics: positives, FP, precision, attack recall, critical recall, linear and exponential NDCG.
   - A block at ranks [a, b] contributes its mean value times \|[a, b] ∩ [1, k_eff]\| to counts, and its mean value times Σ_{j ∈ [a, min(b, k_eff)]} D(j) to DCG. IDCG is unchanged.
   - Coverage and first-critical rank are not linear and have no closed form here.
3. **Seeded within-score-block permutations** (`ties.permuted_order`, seeds 0–99). Each block is shuffled uniformly by a seeded generator, ignoring timestamp and hash.
   - Reported per budget: median, 2.5th and 97.5th percentiles (linear interpolation), minimum and maximum of FP, critical recall, attack recall, both coverages, linear NDCG and first-critical rank.
   - Seeds whose metric is NA are excluded and counted.

Interpretations 2 and 3 **remove the chronological order inside every block**. They diagnose how much a result depends on the tie rule; they do not reproduce the operational policy. Seeds are not independent experimental replicates and never enter statistical tests.

**Near-tie sensitivity.** Scores are rounded to 4 significant digits by Python's `g` format (correctly rounded; 0, ±inf and missing unchanged), then placed in the declared order.

## 8. Severity-policy and criticality variants

Each variant changes both ranking inputs and evaluation labels, except where stated (`severity_variants.VARIANTS`):

| Variant | Definition | τ | Effect on labels (AIT) |
| --- | --- | --- | --- |
| primary | configured table | 8.0 | 32 critical intervals |
| severity_plus_0.5 | every phase severity + 0.5, clipped to [0, 10]; order preserved | 8.0 | service_stop (8.0) becomes critical |
| severity_minus_0.5 | every phase severity − 0.5, clipped; order preserved | 8.0 | webshell (8.0) stays critical |
| swap_lowest_critical_levels | swap the two lowest *distinct* critical severity levels: 8.5 (webshell) ↔ 9.0 (reverse_shell, dnsteal, data_exfiltration) | 8.0 | criticality unchanged; relevance values change |
| default_unknown_3.0 | severity of unmapped alerts 5.0 → 3.0 | 8.0 | none (ranking input only) |
| tau_7 | configured table | 7.0 | 40 critical intervals (adds service_stop) |
| tau_9 | configured table | 9.0 | 24 critical intervals (drops webshell) |

Protocol v1.1 wrote "swap the order of the two lowest critical phases". Three phases tie at 9.0, so the swap is defined on levels (implementation clarification recorded before any result).

## 9. Native scores: provenance, availability and within-detector queues

**Provenance.** The historical loader wrote one `detector_score` column that pooled two score types. WP4 re-read all 16 raw JSON files in loader order (alignment with the canonical cache is exact for all 2,655,821 alerts, and the pooled column is re-derived exactly). The result is in [wp4/native_score_provenance.json](../wp4/native_score_provenance.json).

| Detector group | Raw record type | Keys | Alerts | Raw fields present | Historical pooled value |
| --- | --- | ---: | ---: | --- | --- |
| Wazuh | Wazuh rule alert | 24 | 1,986,905 | `rule.level` ∈ {3: 286,087; 4: 13; 5: 1,576,278; 6: 2,650; 8: 3; 10: 121,874} | rule.level |
| Suricata | `suricata_eve_alert`: eve.json signature alert delivered by Wazuh rule 86601 | 29 | 306,635 | `data.alert.severity` ∈ {1: 150; 2: 92,514; 3: 213,971}; wrapping `rule.level` = 3 for every alert | (5 − severity)/4 ∈ {0.5, 0.75, 1.0} |
| Suricata | `suricata_fast_log_ids_rule`: fast.log line matched by Wazuh IDS rules 20100–20162 | 6 | 306,723 | `rule.level` ∈ {6: 295,032; 8: 626; 10: 9,398; 11: 1,667}; no `data.alert` | rule.level (loader fallback) |
| AMiner | AMiner anomaly | 34 | 55,558 | none | missing |

The 0.5–1.0 and 6–11 values are therefore **different score types**, not a parsing error. One is a Suricata signature severity; the other is a Wazuh correlation or aggregation rule level assigned to Suricata fast.log lines. Every key has exactly one record type.

**Native references** (no pooling, no label-dependent transform):

| Reference | Score | Defined on | Missing (ordered last) |
| --- | --- | --- | --- |
| `O_native_rule_level` | Wazuh `rule.level` | every alert delivered through Wazuh: Wazuh alerts and both Suricata record types (one Wazuh scale, 0–15) | AMiner |
| `O_native_suricata_severity` | −`data.alert.severity` (1 = most severe; negation is a label-independent monotone transform) | Suricata eve.json signature alerts | Wazuh, AMiner and Suricata fast.log alerts |

The historical pooled `detector_score` is kept only as provenance and is never ranked.

**Missing-score accounting** (`metrics.score_availability`): n, missing count and rate, and `ordering_defined` (false if every score is missing).

**What each whole-stream native reference confounds:**
- source exclusion: AMiner is always last, and for the severity reference so are all non-eve alerts;
- for the rule-level reference, Wazuh's own level assignment to Suricata records: every eve.json alert sits at level 3, below fast.log alerts at 6–11.

**Within-detector queues** (`metrics.restrict_queue`) isolate these effects:
- The queue is the subset's alerts only.
- n, P, Z, IDCG and E are computed on that subset.
- C keeps all defined critical intervals of the scenario, so all-defined coverage counts intervals without that subset's alerts as uncovered.

**Reporting.**
- Every method and both native references are reported within Wazuh and within Suricata.
- Within Suricata, native results are also reported within each raw record type: the rule level within fast.log alerts, and the signature severity within eve.json alerts. (The rule level is constant within eve.json alerts and is therefore reported as an all-tie ordering there.)
- For AMiner, `ordering_defined` is false: native metrics are NA, not a timestamp (FIFO) ordering.

## 9a. Subgroups: retrieval in the mixed queue versus ranking within the subgroup

Subgroups are defined from ranking-time fields or split membership. Examples: identifiers unseen in the outer training scenarios, mapped versus unmapped alerts, one detector, one record type, a held-out identifier group. Two different questions are answered and always labelled separately:

1. **Subgroup retrieval in the original mixed queue** (`metrics.subgroup_in_mixed_queue`). The order and k_eff come from the full scenario queue, and nothing is reranked.
   - Counts use subgroup alerts among the first k_eff positions: `subgroup_in_top`, `subgroup_share_of_top` = in_top / k_eff, subgroup positives and negatives in the top.
   - Recalls divide by subgroup totals: `subgroup_attack_recall`, `subgroup_critical_recall`.
   - `subgroup_eligible_intervals` are critical intervals containing at least one subgroup alert.
   - `subgroup_covered_intervals` are those covered by a subgroup alert in the top k_eff; `subgroup_coverage` = covered / eligible.
   - The NA rules of Section 5 apply to every zero denominator.
2. **Within-subgroup ranking** (`restrict_queue` then Sections 5–6). The subgroup's alerts form their own queue, and budgets apply to that queue.

The first measures whether a method surfaces subgroup alerts at the operator's actual budget. The second measures how well the method orders the subgroup when it is isolated. Reference example A (`expected_subgroup_in_mixed_queue`) shows the two diverging: at k = 3 the subgroup has no covered interval in the mixed queue but full eligible coverage when ranked alone.

## 10. Duplicates

**Clusters** (`duplicates.assign_clusters`), from ranking-time fields only:
- Grouping key: (scenario, detector, native_key, host), with alerts taken in arrival order (timestamp, tie hash).
- The first unassigned alert is a **representative**; alerts with timestamp < representative timestamp + W join its cluster.
- The window is anchored at the representative and never extended by members.
- W ∈ {60, 300, 900} s. Labels never form or suppress clusters.

**Evaluation units:**

| Unit | Queue | Labels of each queue item | Score | Use |
| --- | --- | --- | --- | --- |
| original | all alerts | own | own | **primary static metrics** |
| representative_own | representatives | representative's own labels only | representative's own | conservative de-duplicated static metrics |
| static_cluster | representatives | y = any member y; s\* = max member s\*; M = union of member intervals | representative's own | explicitly static cluster-level analysis; never used for time-based metrics |
| chronological (WP5) | investigated alerts in time | an interval is detected only by an investigated alert whose **own** timestamp lies in it, at that alert's investigation start; investigating before arrival is an error; suppressed members confer nothing | — | time-to-coverage |

A future member therefore never gives its representative an earlier detection time, nor any detection at all in chronological analyses. Static cluster credit exists only in the static_cluster unit, where there is no time.

**AIT cluster descriptors** (method-independent; [label_verification.json](label_verification.json), [structural_audit.json](structural_audit.json)):

| Window | Clusters | Share of alerts | Max size | Mixed-label clusters | Representative negative, member positive | Members in more than one critical interval |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 60 s | 101,605 | 3.83% | 25,020 | 25 | 11 | 8 |
| 300 s | 43,439 | 1.64% | 121,456 | 74 | 40 | 9 |
| 900 s | 24,197 | 0.91% | 340,956 | 119 | 65 | 10 |

## 11. Verification

| Check | Location | Result |
| --- | --- | --- |
| Hand-calculated reference examples: exact half-open boundaries, shuffled and duplicated label rows, unequal windows, repeated alerts in one window, a no-alert critical interval, cutoff-crossing ties, a missing score, an empty queue, zero relevant alerts, short queue, integer ceilings, duplicate windows with member-only positives and chronological credit, near-tie rounding, subgroup retrieval in the mixed queue versus within-subgroup ranking | [reference_examples.json](reference_examples.json) (formulas in `scripts/revision/wp3_build_reference_examples.py`); `tests/test_wp3_reference_examples.py` | production and independent reference both equal the hand values |
| Independent reference implementation (plain loops, sets, fractions; no shared code) | `tests/wp3_reference_metrics.py` | agrees with production on 60 random queues × 3 τ × 6 budgets, all fractions and efforts; brute-force enumeration of every within-block order matches the closed-form tie expectations |
| Label construction on random intervals (overlapping and not) | `tests/test_wp3_properties.py` | invariant to file order; boundary timestamps included |
| Within-key constancy per family and policy | `tests/test_wp3_constancy_variants.py` | guaranteed-constant candidates observed constant on actual fitted scores under both policies |
| Severity variants, within-detector denominators, score availability | same, and `test_wp3_properties.py` | pass |
| Real AIT label construction | `scripts/revision/wp3_label_verification.py` | 79 / 79 / no overlap; 0 boundary violations; 0 mismatches with historical labels; file-order invariant |
| Real AIT structure (label-free) | `scripts/revision/wp3_structural_audit.py` | Sections 7.2, 9, 10 |
| Negative controls: wrong denominators (coverage, recall, precision, NDCG), NA handling, closed end, open start, missing de-duplication, effort floor and off-by-one, fraction floor, untruncated tie expectation, member-conferred chronological credit | [negative_controls.json](negative_controls.json) | all 14 detected (each makes WP3 tests fail) |
| Negative control: subgroup retrieval computed from a reranked subgroup | [wp4/negative_controls.json](../wp4/negative_controls.json) | detected by the reference-example test |
| Native-score provenance (raw fields, parser branches, record types) | `scripts/revision/wp4_native_score_provenance.py`; `native_scores.load_revised_alerts` (identity and alignment checks) | exact alignment and re-derivation for all alerts |

Reproduce from the V2 project root:

```sh
PY=/opt/anaconda3/envs/ids/bin/python
$PY scripts/revision/wp3_build_reference_examples.py
$PY -m unittest discover -s tests -v
$PY scripts/revision/wp3_negative_controls.py
$PY scripts/revision/wp3_label_verification.py
$PY scripts/revision/wp3_structural_audit.py
$PY scripts/revision/wp3_write_verification_record.py
```

## 12. Limits the metrics cannot remove

- **Temporal proxies.** Interval labels, criticality and coverage are temporal proxies. No metric here establishes that a top-ranked alert identifies an attack step, that an interval-labeled negative is benign, or that severity values measure impact (protocol v1.1 D4).
- **dnsteal dominance.** dnsteal windows hold 94% of critical alerts. Alert-level critical recall is dominated by them, which is why interval coverage is primary. Alert-level recall remains reported because it exposes deep-queue deferral.
- **Tie dependence.** Class-level scores on AIT form very large blocks, so declared-order results depend heavily on the chronological tie rule. Section 7 diagnostics must accompany every result.

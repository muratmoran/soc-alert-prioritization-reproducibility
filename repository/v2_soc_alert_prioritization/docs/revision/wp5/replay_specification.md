# WP5 chronological replay specification (COSE-D-26-04000)

Version 1.0, 15 September 2026. **Declared before any replay outcome exists.**

- **Purpose.** Determine whether the static coverage/false-positive tradeoff reported in WP4 survives actual arrival order and limited investigation capacity.
- **Relation to the protocol.** It implements protocol v1.1 §8 unchanged. It fixes only the event-handling, metric and reporting details that §8 leaves open.
- **No search.** Nothing here is tuned against replay outcomes, and replay is not used to look for a setting that restores a superiority claim.

## 1. What is replayed

| Replay set | Rankers | Folds | Rates (alerts per analyst-hour) |
| --- | --- | --- | --- |
| P1 (primary) | R1 outer candidates: 12 untuned references, the primary-rule selection and the secondary-rule selection of each tuned family | 8 LOSO held-out scenarios | **12 (primary)**; sensitivity 6, 30, 60 |
| P2 (secondary input policy) | R2 outer candidates, same roles | 8 LOSO | 12, 6, 30, 60 |

- **Scores.** Scores are the stored WP4 stage-2 outer scores. They come from `~/soc_revision_data/wp4_stage2/{R1,R2}/loso_*/outer_scores.npz`, whose SHA256SUMS hash is pinned in [stage2_output_manifest.json](../wp4/stage2_output_manifest.json).
  - Mappings, heights, learned models and selections are exactly those fitted on the outer training scenarios.
  - Nothing is refitted, retuned or reselected, and replay outcomes never feed back into any score.
- **Not replayed.** Ablations R3–R5, identifier hold-out R6 and forward chaining R7 remain static WP4 analyses. Their scores were not retained, and refitting them for replay is outside WP5 v1.
- **No duplicate suppression.** Every original alert arrives, and duplicate units remain static WP4 analyses.
- **No wrappers.** There is no aging, exploration or feedback wrapper (protocol §8). Calibration is frozen throughout replay.

## 2. Event semantics

For one held-out scenario and one ranker:

- **Arrival.** Alert i arrives at its AIT timestamp a_i (seconds).
- **Horizon.** [t0, T], with t0 = min a_i (first alert) and T = max a_i (last alert). Staffing is 24 hours a day with one analyst, and there is no initial backlog.
- **Service.** Non-preemptive, with equal duration s = 3600 / rate seconds for every alert.
- **Priority.** The declared order of metric contract §4: score descending, missing scores after all scored alerts, then timestamp ascending, then the SHA-256 tie hash ascending. It is a fixed total order, so each alert has a unique priority rank that does not depend on time.
  - FIFO is `O_oldest_first`, the oldest arrival.
  - `O_newest_first` selects the newest alert in the backlog.
- **Decision epochs.** The analyst is free at t0.
  - Whenever the analyst becomes free at time f: if any alert with a_i ≤ f is uninvestigated, a selection is made at t = f. Otherwise the analyst waits and selects at the next arrival time t = min{a_i : a_i > f}.
  - **Simultaneous events.** All alerts with a_i ≤ t, including a_i = t, are in the backlog before the selection at t. In particular, an arrival at the exact instant a service completes is selectable at that instant.
  - **Selection.** The backlog alert with the best priority rank. A future alert (a_i > t) is never selectable.
  - The selected alert's service starts at t, and the analyst becomes free at t + s.
- **No draining.** No selection is made at a time t > T. A service that starts at t ≤ T counts as an investigation even if it would end after T; its busy time is truncated at T for accounting.
- **Crediting.**
  - An investigation is credited at its start time, as in the chronological unit of metric contract §10.
  - A critical interval is covered only by an investigated alert whose own timestamp lies in that half-open interval.
  - No cluster member, future alert or interval end confers coverage.
- **Label boundary.** Selection uses only scores, timestamps and tie hashes. Labels are read only after the trace is complete, to compute metrics.

**Integrity checks, run on every replay and recorded:**
1. Every selected alert had arrived: a_i ≤ start.
2. Starts are separated by at least s, so no more than one alert is ever in service.
3. Every start is ≤ T.
4. Busy time plus idle time equals T − t0.
5. The analyst is work-conserving: idle only when the backlog is empty.
6. The number of investigations is at most ⌊(T − t0)/s⌋ + 1.
7. On a declared sample of selections (the first 50 and 50 seeded at random, seed 42), the selected alert is the best-ranked arrived and uninvestigated alert. This is checked by an independent full-backlog scan.
8. Arrival sequences are identical across rankers within a fold.
9. Mutating held-out labels leaves the trace unchanged.

## 3. Metrics per replay

The scenario is the unit. With H_d denoting a delay of d ∈ {1, 4, 24} hours, coverage and delay are always reported together.

| ID | Metric | Definition |
| --- | --- | --- |
| C1 | Critical-interval coverage by horizon | Covered intervals out of defined and out of eligible (intervals containing at least one alert; all 4 per AIT scenario) |
| C2 | Uninvestigated critical intervals | Defined minus covered, listed per interval |
| C3 | Interval detection delay | Per interval: first alert time f_c (earliest alert in the interval), detection time D_c (earliest investigation start among investigated alerts inside it), and delay D_c − f_c. An undetected interval is right-censored at T − f_c |
| C3a | Delay summary | Always paired with the number censored: detected and censored counts; median delay among detected; intervals covered within H_d of their first alert; restricted mean delay with censored delays set to their censoring time, labelled a lower bound |
| R1 | Alert-level critical recall by horizon | Critical alerts investigated / all critical alerts |
| R2 | Critical recall within H_d | Critical alerts with start − arrival ≤ H_d, over all critical alerts. Reported alongside the number of critical alerts arriving after T − H_d, which cannot meet H_d |
| F1 | Investigations | Total; interval-labeled positives; **false-positive investigations** (interval-labeled negatives) and their share; critical investigations |
| S1 | Starvation | Critical alerts never investigated by T, with count and share. Also reported separately for low-confidence critical alerts (unmapped, or class height ≤ 0.2 in the fold's R1 outer features, label-free and common to all rankers) and for the remaining critical alerts |
| B1 | Backlog | Peak backlog (largest backlog size at any selection, before removal, or at T); backlog at T; time-average backlog = Σ_i (e_i − a_i)/(T − t0), where e_i is the start time if investigated, else T |
| Q1 | Queue age | Waiting time (start − arrival) of investigated alerts: median, 90th percentile, maximum. Age at T of uninvestigated alerts: median and maximum |
| T1 | Tie-decided selections | Selections where the next-best backlog alert had the same score (both missing counts as equal), so timestamp or hash decided; count and share |
| U1 | Capacity use | Investigations, busy and idle seconds, and utilization |

**Ties.** Replay uses the declared order only. The within-block permutation diagnostics of WP3/WP4 are static diagnostics. Their low expected FP does not imply an operational improvement, because future alerts are not available at selection time. Replay does not permute ties.

**Language.**
- Investigating an alert inside a critical window counts as temporal coverage, not confirmed detection of the attack step.
- The rates are simulation assumptions, not measured SOC capacity.
- Interval labels are proxies (protocol D4).

## 4. Reporting

1. **Primary replay table** (P1, rate 12). Rows are the untuned references and primary-rule selections; columns are the 8 scenarios. Each cell shows covered intervals (of 4), FP investigations, critical recall by horizon, and starved critical alerts. Summary columns give intervals covered (of 32), median FP investigations, median starvation share, and median delay with censored count.
2. **Capacity-response table.** The same summaries at rates 6, 12, 30 and 60, for P1 and P2.
3. **Delay table.** Per interval: first alert time offset, detection delay or censoring, and the investigating alert's identifier-level role. Summarized per ranker with detected and censored counts always shown.
4. **Backlog and queue-age table.** Peak, final and time-average backlog; waiting and age summaries.
5. **Static versus replay comparison.** For each ranker, WP4 static coverage@100 and FP@100 shown beside replay coverage and FP investigations at each rate. Labelled descriptive: the static top-100 and the replay's investigated set are different quantities.
6. **Tie-decided selection shares.**
7. **Trace samples** (P1, rate 12, fold fox): the first 50 selections of P, S1_key (primary rule) and O_oldest_first, with arrival, start, score, backlog size and tie flag.
8. **Integrity results** for every replay, and a limitations paragraph on the service assumptions.

No statistical test is reported; paired inference is WP7.

## 5. Verification before full replay

- **Independent reference simulator.** `tests/wp5_reference_replay.py` uses plain loops and shares no code with production. On randomized instances with simultaneous arrivals, arrivals at service completion, tied and missing scores and short horizons, its traces and metrics must equal production.
- **Hand-calculated examples.** Arrival boundaries, simultaneous events, non-preemption, service accounting, horizon censoring, half-open interval crediting, delay censoring, recall-within-delay equality, and time-average backlog.
- **Label-mutation invariance and identical arrivals across rankers.**
- **Negative controls.** Injected defects (lookahead, select-before-enqueue, draining, preemption, reversed tie hash, crediting at arrival, recall over investigated alerts only, censoring dropped, backlog average over investigated alerts only, label-aware selection, a weakened trace checker) must each make a test fail.
- **Real-data precheck.** On real data, integrity checks, runtime and output size only; no outcome metric is computed.
- **Verification record.** `docs/revision/wp5/replay_verification.json` pins this specification, the replay code, tests, controls, the precheck and the stage-2 score identities.
- **Gate and output capacity.** The full-replay runner refuses to start unless the WP3, WP4 and WP5 records are verified and not stale, and the stage-2 copy matches its pinned hash. It writes only to `~/soc_revision_data/wp5_replay` (outside iCloud) and refuses to start if free disk space minus the projected output size (from the precheck) is below 5 GB.

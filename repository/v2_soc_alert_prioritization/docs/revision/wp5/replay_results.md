# WP5 chronological replay results (COSE-D-26-04000)

15 September 2026.

> **Corrections (15 September 2026, WP9 submission-readiness check).** The statements below overstated the evidence. The original text is kept unchanged further down (pre-correction copy: `../wp9/superseded/2026-09-15_pre_wp9_wp5_replay_results.md`). Values are read from the existing replay summaries; no replay was rerun.
> 1. **"13 for every class-level ranker"** and **"Class-level rankers leave 19 of 32 critical intervals uninvestigated"** hold for the class-level *formula* rankers (P, H, W, A, C, M, S0, S1, S2). At 12/h the learned L1 and L2 cover 10 and 12 intervals.
> 2. **Capacity response.** "Class-level coverage stays at 9–13" holds for the formula rankers. L1 covers 6–10 and L2 8–12 from 6 to 60 alerts/hour. The identifier-level range 23–30 refers to S0_key, S1_key, S2_key and R_severity_key; R_key covers 3–5.
> 3. **"Indistinguishable … in critical recall and starvation."** S0, S1 and S2 are identical to P, H and C in coverage, FP investigations, critical recall and starvation. W, A and M share the coverage and FP investigations but investigate 51 rather than 53 critical alerts at 12/h (eight-scenario totals).
> 4. **Tie-decided shares** (96%; 76–84%) are the 12/h values from [tie_decided.csv](tables/tie_decided.csv).

**How these results were produced.**
- Everything reported was produced under [replay_specification.md](replay_specification.md), declared before any replay outcome and logged in the protocol change log.
- The replay gate was opened by the verified WP3, WP4 and [WP5](replay_verification.json) records.
- The replayed rankers are the stored WP4 outer-fold candidates, with no refitting, retuning or reselection.
- Tables are in [tables/](tables/) ([tables.md](tables/tables.md)); output provenance is in [replay_output_manifest.json](replay_output_manifest.json).

**Language.**
- **Coverage.** A covered critical-step interval means that an investigated alert's own timestamp lies inside the interval, credited at investigation start. It is temporal coverage, not confirmed detection of the attack step.
- **Rates.** The analyst rates (6, 12, 30, 60 alerts per hour; 12 is primary) are simulation assumptions, not measured SOC capacity.
- **Units.** Scenarios are the units of analysis.
- **Inference.** No significance test is reported (WP7).

## 1. Execution and integrity

- **Scale.**
  - 1,616 replays: P1 (R1 outer candidates) and P2 (R2 outer candidates) × 8 held-out scenarios × 4 rates.
  - Horizons run from each scenario's first to its last alert: 95.7–143.8 hours, 958.7 hours in total.
- **Integrity.**
  - Every replay passed every declared check: no selection before arrival, no overlapping service, no selection after the horizon, service accounting, work conservation, and the capacity bound.
  - The sampled priority check against a full backlog scan passed on 160,792 selections.
  - Arrivals were identical across rankers.
- **Before the full run**, the implementation matched an independent reference simulator on 150 randomized instances, and 11 injected defects were all detected. A label-free real-data precheck confirmed alignment and label-mutation invariance.
- **Saturation.** At 6, 12 and 30 alerts/hour the analyst was essentially never idle (at 12/hour, 11,508 investigations across the 8 scenarios, the capacity maximum). At 60/hour about 1% of the horizon was idle, when the backlog briefly emptied (56,941 investigations). The analyst only idles when nothing is waiting, so investigation counts and backlog sizes are identical across rankers at every rate.
  - Backlog is therefore ranker-independent: peak backlog 44,399–632,519 alerts by scenario (median 300,649), median time-average 109,899, median age of uninvestigated alerts at the horizon 36 hours.
  - The rankers differ only in which alerts they investigate.

## 2. Primary replay (P1, 12 alerts/hour)

| Ranker | Intervals covered (of 32) | Censored (never investigated) | FP investigations (of 11,508) | Interval-positive investigations | Critical investigations | Critical recall by horizon (median) | Starved critical alerts (of 9,204) | Median delay to first investigation, detected intervals (h) | Selections decided by tie rule (median) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| S1_key (primary rule) | 30 | 2 | 11,013 | 495 | 258 | 0.047 | 8,946 | 0.29 | 76% |
| S2_key (primary rule) | 29 | 3 | 9,997 | 1,511 | 252 | 0.046 | — | — | 78% |
| S0_key (κ = 1) | 28 | 4 | 9,345 | 2,163 | 177 | 0.029 | 9,027 | 0.29 | 84% |
| R_severity_key (c·ĥ_key) | 25 | 7 | 9,308 | 2,200 | 108 | 0.021 | 9,096 | 0.29 | 84% |
| P, H, S0, S1, S2, C (class level) | 13 | 19 | 9,285 | 2,223 | 53 | 0.009 | 9,151 | 0.06 | 96% |
| W, A, M (primary rule) | 13 | 19 | 9,285 | 2,223 | 51 | 0.009 | — | — | 96% |
| L2 (primary rule) | 12 | 20 | 9,285 | 2,223 | 48 | 0.004 | — | — | 96% |
| L1 (primary rule) | 10 | 22 | 9,285 | 2,223 | 42 | 0.004 | — | — | 96% |
| O_newest_first (LIFO) | 11 | 21 | 11,284 | 224 | 133 | 0.022 | 9,071 | 0.04 | 74% |
| O_severity | 8 | 24 | 11,479 | 29 | 29 | 0.005 | 9,175 | 0.03 | 100% |
| R_key_reliability | 5 | 27 | 9,271 | 2,237 | 36 | 0.005 | — | — | 85% |
| O_reliability | 5 | 27 | 9,285 | 2,223 | 24 | 0.001 | — | — | 96% |
| O_native_rule_level | 4 | 28 | 10,287 | 1,221 | 45 | 0 | — | — | 86% |
| O_native_suricata_severity | 1 | 31 | 11,369 | 139 | 1 | 0 | — | — | 99% |
| O_oldest_first (FIFO) | 0 | 32 | 11,508 | 0 | 0 | 0 | 9,204 | — | 66% |

Per-scenario cells (covered/4 · FP investigations · critical recall · starved) are in [primary_replay_cells.csv](tables/primary_replay_cells.csv). Dashes mark values not tabulated here; they are in [starvation.csv](tables/starvation.csv) and [delay_summary.csv](tables/delay_summary.csv).

**Coverage, delay and failures together.**
- **Coverage.** Class-level rankers leave 19 of 32 critical intervals uninvestigated by the horizon; identifier-level variants leave 2–7. FIFO investigates nothing inside any critical interval, because under saturation its oldest-first queue never reaches the attack windows.
- **Delay.** Intervals that are covered are covered quickly: median 0.06 hours for class-level rankers and 0.29 hours for identifier-level variants. Delay among detected intervals would hide the main difference, which is the number of intervals never investigated.
- **Starvation.** At least 95% of critical alerts are never investigated by any ranker at 12 alerts/hour. 9,072 of the 9,204 critical alerts are low-confidence (unmapped, or class height ≤ 0.2). Among them, 8,843 (S1_key) to 9,072 (FIFO, O_severity) are starved.
- **Critical recall within 1, 4 or 24 hours** has a median of at most 0.047 for every ranker ([capacity_response.csv](tables/capacity_response.csv)).

## 3. Does the static tradeoff survive?

**Static top-100 versus replay** (P1, totals over the 8 scenarios; descriptive, because the two quantities differ):

| Ranker | Static coverage@100 (of 32) | Static FP@100 (of 800) | Replay coverage, 12/h | Replay FP investigations, 12/h (of 11,508) | Replay coverage, 60/h | Replay FP investigations, 60/h (of 56,941) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| P, S1 (class level) | 8 | 238 | 13 | 9,285 | 13 | 45,964 |
| S0_key | 21 | 621 | 28 | 9,345 | 28 | 45,992 |
| R_severity_key | 18 | 612 | 25 | 9,308 | 25 | 45,962 |
| S1_key (primary rule) | 21 | 597 | 30 | 11,013 | 30 | 56,435 |
| O_severity | 8 | 771 | 8 | 11,479 | 8 | 56,912 |
| O_oldest_first | 0 | 800 | 0 | 11,508 | 0 | 56,941 |

1. **Coverage survives arrival order and limited capacity.**
   - Rankers using identifier-level historical precision investigate alerts inside 25–30 of 32 critical intervals, against 13 for every class-level ranker.
   - The ordering matches the static result (and widens), and it holds at every declared rate.
2. **The FP side does not survive as a clear penalty, because the queue is saturated.**
   - Every ranker makes the same number of investigations, so FP investigations equal that count minus interval-positive investigations. The static FP@100 gap (18 against 77 per scenario) is not the operational quantity here.
   - In replay, S0_key and R_severity_key make essentially the same number of FP investigations as the class-level rankers (9,345 and 9,308 against 9,285) while covering more intervals.
   - The selected S1_key and S2_key make more FP investigations: 11,013 and 9,997.
   - Class-level rankers' interval-positive investigations (2,223) concentrate on alerts from few intervals: 13 covered, 53 critical.
   - **The replay tradeoff therefore depends on the selected discount.** It is not a general property of identifier-level precision, and it is not an SGFN advantage.
3. **Capacity response is flat for score-based rankers.**
   - From 6 to 60 alerts/hour, class-level coverage stays at 9–13, and identifier-level coverage at 23–30.
   - Only LIFO rises (9 → 24), consistent with it sampling more fresh arrivals during attack windows.
   - Even at 60 alerts/hour the analyst investigates 2.1% of all arrivals (1.2–12.3% by scenario), and peak backlogs remain 44,000–633,000 alerts by scenario. The declared rates cannot test regimes in which capacity approaches alert volume.
4. **Ties remain decisive in replay.**
   - 96% of class-level selections and 76–84% of identifier-level selections were decided by the chronological/hash rule among equal scores.
   - The low FP expectation under static tie permutations (WP4) does not translate into an operational improvement. In replay, the tie rule operates on the current backlog only, and class-level rankers still make 9,285 FP investigations.
5. **SGFN interactions provide no replay advantage.**
   - Class-level S0, S1 and S2 are indistinguishable from P, H, W, A, C and M in coverage, FP investigations, critical recall and starvation, in every scenario.
   - The only differences among identifier-level variants come from the u·ln ĥ_key discount (S1_key, S2_key) against the plain c·ĥ_key product (R_severity_key): higher coverage at the cost of more FP investigations for the selected discounts.

## 4. Secondary input policy (P2, asset_profile + ambiguity_aware)

P2 reproduces the P1 pattern at 12 alerts/hour ([capacity_response.csv](tables/capacity_response.csv)):

| Rankers | Intervals covered (of 32) | FP investigations |
| --- | ---: | ---: |
| Class-level P, H, W, A, C, M, L1, S1, S2 | 13 | 9,292–9,294 |
| S0 | 9 | 9,302 |
| L2 | 9 | 9,294 |
| S0_key | 28 | 9,321 |
| R_severity_key | 25 | 9,309 |
| S1_key | 28 | 9,672 |
| S2_key | 29 | 9,847 |
| O_severity | 17 (the asset factor changes its ordering) | 11,282 |

## 5. Limitations

- **Service assumptions.**
  - One analyst working 24 hours a day, with equal non-preemptive service time and no aging, exploration or feedback, is a stylised model.
  - Real triage times vary by alert type, analysts batch or suppress repeated alerts, and SOCs escalate.
  - The declared rates are assumptions, and all are overloaded on AIT. The results describe which alerts a fixed ordering surfaces under overload, not SOC performance.
- **No draining and no deduplication.**
  - Alerts after the horizon are censored.
  - Duplicate suppression was not replayed; repeated alerts consume capacity, which is part of why so few intervals are reached.
- **Temporal-proxy labels.** Coverage and critical recall rest on interval labels and the author's severity policy (protocol D4). Investigating an alert inside a critical window is not confirmed attack detection.
- **Scope of rankers.** The replayed rankers are the WP4 R1/R2 outer candidates. Ablations, identifier hold-out and forward chaining were not replayed. The identifier-level coverage advantage seen here is therefore subject to the WP4 finding that it does not persist reliably under identifier hold-out.
- **Inference.** Eight scenarios; per-scenario results only, no inference (WP7).

## 6. Consequence for the revision

Under arrival order and saturated capacity:
- **Coverage.** Identifier-level historical precision still reaches more critical intervals than class-level scores (25–30 against 13 of 32).
- **False positives.** Its false-positive cost depends on the selected form: similar FP investigations for S0_key and R_severity_key, more for S1_key and S2_key.
- **Class-level SGFN variants** show no advantage over simpler class-level scores.
- **Starvation.** Every ranker starves at least 95% of critical alerts, which are almost all low-confidence.

The paper's time-related statements must come from this replay, and they must be read together with the WP4 result that the identifier-level advantage does not persist reliably under identifier hold-out.

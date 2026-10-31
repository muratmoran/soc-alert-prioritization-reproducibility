# Methods and reproduction supplement

Revision: 26 October 2026. This supplement accompanies the revised JNSM manuscript and dated exploratory amendments. Original primary testing remains a six-contrast family on eight scenarios. The additional analyses reuse the previously examined corpus and are descriptive.

## Estimation and selection sequence

For each outer test scenario t, define fitting scenarios F using the declared split. LOSO uses all other scenarios; forward fitting uses only scenarios whose last alert precedes t's first alert and requires at least two fitting scenarios. Identifier hold-out also removes every occurrence of the excluded identifiers from all fitting and inner-validation stages.

1. Lock test labels. For every inner validation scenario v in F, use F minus v as its fitting boundary. No mapping, reliability estimate, preprocessing statistic, learned model or candidate choice can use t or v labels at this stage.
2. Fit each native key's phase mapping on the permitted records: support >=5, positives >=3, positive fraction >=0.5 and largest phase-positive count / union-positive count >=0.7. Rejected keys map to unknown. Phase ties follow the frozen phase order. Severity and uncertainty come from `configs/severity_mapping.yaml`, reproduced in the manuscript.
3. For class reliability, classify the rows of each fitting scenario j using a mapping fitted without j. Pool these cross-fitted class assignments to estimate (detector, class) positive frequencies, shrinking toward the detector prior with lambda=50 and clipping to [0.05,0.95]. Estimate native-key reliability on permitted fitting records using the same shrinkage. Missing cells/keys use the detector prior, then global prior; neither prior available is an error. All counts exclude withheld identifiers where applicable.
4. Score each validation scenario with all candidates in the frozen registry. Learned methods use scenario-excluded features for their fitting rows. Select each tuned family by macro coverage@100, then lower macro interval-negatives@100, then higher macro linear-gain NDCG@100, then fewer nonzero parameters and grid order (tolerance 1e-12). If no inner learner fit is possible in a small forward split, the frozen pipeline uses its declared simplest-candidate fallback. Inspect the recorded per-fold selections rather than assuming a common parameter across folds.
5. Refit the selected candidate on F with the same isolation rules, freeze test scores, unlock test labels for evaluation, and evaluate all test records. The additional forward replay requires exact reproduction of the saved selections and static coverage/negative counts before service simulation.

The original implementations and their verification records remain unchanged. The portable entry point rebinds their data paths for an unpacked archive. This changes file location only, not fitting logic.

## Endpoint definitions

All labels are timestamp-in-interval proxies, with half-open bounds. Coverage counts a critical interval when at least one selected alert has an event timestamp in it. It does not establish that the alert concerns the attack. FP denotes interval-labelled negatives, not independently verified false alarms.

The analyst starts one non-preemptive equal-duration investigation at a time. Arrivals at a start time enter before selection; an empty backlog causes idling. Scores, ascending timestamps and stable hashes determine selection. The scenario runs from its first to last alert without a drain. Credit occurs at service start, even when service would complete beyond the horizon.

For interval j let a_j be its first alert time, d_j its first credited investigation start and T the scenario's last alert time. Covered delay is d_j-a_j. For an uncovered interval the lower-bound delay is T-a_j. Average these four values within each scenario, then take the median of eight scenario means for the reported lower-bound summary. The separate covered-delay statistic is the median across scenario-specific medians of covered delays. These are different aggregations; no common follow-up horizon is imposed.

The added end-of-interval check compares d_j with the exclusive interval end e_j: d_j<e_j is before end; d_j>=e_j is late. One-hour coverage is d_j-a_j<=3600 and can include late investigation of a short interval. Critical-record non-investigation means no service start by T, not indefinite non-investigation or a count of missed independent attacks.

Identifier subgroup outcomes retain the original mixed-queue top-100 budget. Only retrieved records from the excluded group can cover that group's eligible intervals; the denominator is intervals containing at least one such record. Whole-queue coverage has a separate denominator of 32. Never rerank only the excluded subset to derive these values.

## Inputs, outputs and commands

Use the versions in the archive's `environment/` records. The existing `ids` environment ran the checks here. Python requires NumPy, pandas, scikit-learn, PyYAML, SciPy, Matplotlib and the remaining packages listed in `requirements.txt`. PDF compilation requires TeX Live/latexmk and Ghostscript.

From an unpacked archive, set only the task-specific data and plotting paths. Do not change the account home directory:

```sh
export SOC_REVISION_DATA="$(pwd)/external_data/soc_revision_data"
export MPLCONFIGDIR="/tmp/jnsm-matplotlib"
export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1
cd repository/v2_soc_alert_prioritization
python -m unittest discover -s tests -p test_jnsm_revision.py -v
python scripts/revision/jnsm_reproduce.py --assets --compile
```

To regenerate the additional numerical analyses first:

```sh
python scripts/revision/jnsm_reproduce.py --analysis --assets --compile
```

The analysis entry point regenerates all five nested forward fits, verifies their saved selections and outcomes, runs 45 forward replays, and then runs the eight declared rate-score folds and replays. On this machine the forward fits/replays took about 7–51 seconds per fold after data loading. It checks at least 6 GiB free disk space. This is not a full raw-JSON reconstruction of the earlier research history.

Current inputs are the included canonical/provenance caches and labels, original per-fold and replay outputs, and original gate manifests. Derived summaries and selected-candidate tables are under `docs/revision/jnsm_20261026/`. Detailed scores, traces, selections and fit records are under `results/jnsm_20261026/`. Original result folders and the 157-candidate registry are retained separately.

`jnsm_revision_analysis.py`, `jnsm_ait_rate.py`, `jnsm_build_assets.py` and `jnsm_compile.py` implement the added work. `analysis_manifest.json` and `ait_rate_manifest.json` identify the numerical inputs/outputs; `revision_assets_manifest.json` governs the October assets; `manuscript_manifest.json` governs the article PDF and flattened source comparison; and `supplementary_manifest.json` governs the electronic supplementary-material PDF. Earlier WP8/manuscript manifests are historical and describe their own version.

## Review access and remaining scope

The local archive `jnsm-revision-2026-10-27-v3.tar.gz` is prepared for reviewer access and includes checksums, editable article and supplementary sources, code, configurations, supplied data caches, original outputs and added outputs. It has not been deposited publicly or submitted to the journal. The author can supply it through the chosen reviewer-access route. This v3 package supersedes the 26 October v1 and 27 October v2 packages; v2 added editorial corrections and v3 rewords four summary sentences on the class-level formula comparison. The numerical analyses are unchanged.

No new dataset, expert alert adjudication, mapping-threshold grid, randomized online scheduler, oracle bound, capacity-near-arrival regime, or replay of identifier exclusions/duplicate handling is claimed. The rate-score comparison is an explicitly specified native-key adaptation, not a reproduction of the original abbreviation-level filtering analysis.

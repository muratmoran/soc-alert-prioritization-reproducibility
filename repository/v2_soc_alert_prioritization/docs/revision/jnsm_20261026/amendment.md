# Exploratory JNSM revision amendment

Recorded 26 October 2026, before the additional numerical analyses below. This extends the completed September evaluation on the same previously examined AIT corpus. It is not independent confirmation. The original candidate registry, six primary tests, split definitions and recorded outputs remain unchanged.

1. Summarize all five identifier partitions from the existing R6 mixed-queue subgroup outputs at k=100. Report support once per scenario/group, and primary selected methods separately. Zero-support recall remains undefined. Do not rerank only the excluded subset.
2. Reclassify first credited LOSO investigations at 12 alerts/hour as before the interval end or at/after that end, using saved per-interval starts and half-open intervals. Report existing one-hour coverage beside this diagnostic. No ranker fitting is changed.
3. Reconstruct all five existing R7 forward folds with the original configuration and pipeline. Require agreement with saved primary/secondary candidate selections and static primary outcomes before replay. Replay P, S1, S0key, S1key, S2key, Rsev,key, severity-only, FIFO and LIFO at 12 alerts/hour, retaining arrivals, ties, service-start credit and no draining. Every trace must pass the existing replay integrity checks. Save the scores, traces, fitting/selection provenance and per-interval results in a new directory.
4. Compare forward replay with LOSO replay restricted to the same five scenarios. Report interval coverage, record retrieval, interval-negative burden, one-hour coverage, late coverage and backlog. These are descriptive exploratory comparisons; no additional confirmatory p-value family is introduced.
5. Assess the original AIT detector-score implementation and write a separate specification before any added baseline is run. An unresolved adaptation is documented as an omission; no performance result determines inclusion.

Conditional extensions in the revision plan (mapping sensitivity, oracle/random policies, adjudication and new datasets) are excluded from this pass. Claims will remain policy-conditioned and proxy-based.

Verification: retain original verification gates; hash-check inputs actually consumed; hand-check new timing and aggregation functions; reproduce saved R7 metrics; check all new replay traces; regenerate manuscript assets from recorded outputs. New outputs go under `results/jnsm_20261026/`; small reviewable summaries and provenance are copied here. No output is written over the external historical data or run directories.

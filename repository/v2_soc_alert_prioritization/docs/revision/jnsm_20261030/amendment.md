# Review-response amendment — 30 October 2026

Exploratory extension specified after the original results and the mock review,
before computing the new outcomes. The original 157-candidate protocol, six
primary tests, saved fits, and October 27 package remain historical records.

1. Extract all primary-selected static rankers' exact expected FP and 100-seed
   coverage means/ranges, with per-scenario and aggregate-seed ranges distinguished.
   Compute scenario-paired exploratory contrasts on averaged values. Report distinct
   scores and deep-queue deferral for all nine class-level formulas.
2. Repeat the original nested fitting/selection for the formula families and
   operational references (the two learned families are outside this mechanism
   sensitivity): precision 0.3/0.4/0.5/0.6/0.7; purity 0.5/0.7/0.9; joint corner
   settings (0.3,0.5), (0.3,0.9), (0.7,0.5), (0.7,0.9); support/positive minima
   (1,1), (5,3), (10,5); shrinkage 0/10/50/200 applied to class and key estimates.
   The unchanged configuration is reproduced against saved primary selections.
   No new best policy will be selected using outer outcomes.
3. Severity shifts -1/+1 with original evaluation labels fixed; separately repeat
   shifts with revised evaluation labels at tau=8, and original severity at tau=7/9.
   Report critical denominators for every endpoint-changing variant.
4. Critical-target reliability ablation: change the positive counts used for
   class/key reliability and detector/global priors to critical-interval membership;
   leave phase mapping, its thresholds, and evaluation labels unchanged. Keep all
   fitting exclusions and cross-fitting. Use a separate traced provider.
5. Randomized-tie replay: fixed original selected scores, one analyst at 12/h,
   100 seeds (0–99), common deterministic pseudorandom per-alert priorities across
   methods; ties ordered by that priority, then timestamp/hash. Only arrived alerts
   can be selected. Include P, S1, S0key, S1key, S2key, Rsev,key, and severity-only.
   Scenarios, not seeds, are inferential units. No primary-test replacement.
6. Grouped replay: existing causal anchored grouping by detector/native key/host
   with windows 60/300/900 seconds. A group is released at anchor+window, its score
   is the maximum of arrived members' scores, and a fixed service investigates
   that closed group. Groups closing after the original raw-alert horizon remain
   uninvestigated. No future member can confer earlier coverage. Use the same seven
   rankers at 12 groups/h; report group retrieval, contained critical records,
   coverage, before-end timing, FP groups, and utilization. Equal per-group service
   is an explicit assumption, not measured analyst productivity. Keep the original
   raw-alert horizon. Labels are used only after queue simulation.
7. Correct wording, explain statistical discreteness and target mismatch, add the
   relevant tie/capacity/aggregation/forward references, update Kim–Dán, name
   chronological splits, add S2key rate outcomes, and define the L2 target.
8. Prepare a versioned public-release package with attribution, checksums,
   environment, tests, complete derived outputs and reproduction commands; record
   actual publication status truthfully. User requested public GitHub/Zenodo deposit.

Verification: independent backlog-scan reference tests; raw deterministic replay
agreement with the historical engine; no-lookahead, closed-window, endpoint and
no-drain tests; fitting-trace checks plus excluded-label mutation tests; saved
baseline selection/outcome agreement; full relevant test suite; regenerated PDF
text, references, source-bundle and visual checks. Every new run records input,
amendment, code and output hashes. Failed/incomplete folds cannot be aggregated.

# WP2 configuration schema (`configs/revision_wp2.yaml`)

`soc_alert_ranking.revision.config.load_comparison_config` validates the file against the protocol v1.1 values restated in `PROTOCOL_V1_1`. Any missing key, unexpected key (other than `protocol`), type mismatch, or value different from protocol v1.1 raises `ConfigError`. Numeric values must be real numbers; booleans are rejected. After loading, the expanded tuned grid sizes must equal `EXPECTED_TUNED_SIZES`. Changing a value therefore requires a protocol change-log entry and a matching edit of `config.py`, and it produces a new registry hash that `wp2_freeze_grid_registry.py` refuses to accept silently.

| Key | Type | Required value (protocol v1.1) | Used by |
| --- | --- | --- | --- |
| `schema_version` | int | 1 | loader |
| `protocol` | str | `docs/revision/protocol_v1_1.md` | provenance |
| `policies.primary` | {context, uncertainty} | {flat, table} | `InputPolicy` |
| `policies.secondary` | {context, uncertainty} | {asset_profile, ambiguity_aware} | `InputPolicy` |
| `mapping_thresholds.min_support` / `min_positive` | int | 5 / 3 | `fit_mapping` |
| `mapping_thresholds.min_precision` / `min_phase_purity` | float | 0.5 / 0.7 | `fit_mapping` |
| `reliability.target` | str | `observed_interval_label` | documentation of h semantics |
| `reliability.class_lambda` / `key_lambda` | number | 50 / 50 | `fit_class_heights`, `fit_key_heights` |
| `reliability.height_min` / `height_max` | float | 0.05 / 0.95 | clipping at fit time; score domain check |
| `uncertainty.unmapped` / `maximum` | float | 0.5 / 0.5 | u construction; S1 domain |
| `uncertainty.ambiguity_precision_weight` / `ambiguity_purity_weight` | float | 0.20 / 0.15 | secondary policy only |
| `evaluation.tau` | float | 8.0 | label construction (criticality) |
| `evaluation.selection_k` | int | 100 | selection metrics |
| `evaluation.tie_salt` | str | `cose04000\|` | tie hash |
| `selection.primary` | list[str] | [max_macro_coverage, min_macro_fp, max_macro_ndcg, min_nonzero_params, grid_order] | `select_candidate(PRIMARY)` |
| `selection.secondary` | list[str] | [max_macro_ndcg, min_nonzero_params, grid_order] | `select_candidate(SECONDARY)` |
| `selection.tolerance` | float | 1e-12 | tie tolerance (roundoff only) |
| `learned.max_training_alerts` | int | 300000 | `draw_training_rows` |
| `learned.seed` | int | 42 | sample draw, model `random_state` |
| `learned.weights` | str | `equalize_scenarios` | `equalizing_weights` |
| `grids.W.alpha` | list[float] | 0.0–1.0 step 0.1 (11) | W_weighted |
| `grids.A.simplex_step` | float | 0.1 (66 points) | A_additive |
| `grids.M.a` / `grids.M.b` | list[float] | {0, 0.25, 0.5, 1, 2, 4} / {0, 1, 2, 4, 8} (30) | M_multiplicative |
| `grids.C.c_fp` | list[float] | {0, 1, 2.5, 5, 10} (5) | C_cost_sensitive |
| `grids.L1.C` | list[float] | {0.01, 1, 100} (3) | L1_logistic |
| `grids.L2.max_depth` | list[int] | {2, 3} (2) | L2_gradient_boosting |
| `grids.L2.learning_rate` / `max_iter` / `l2_regularization` | number | 0.1 / 200 / 1.0 | L2_gradient_boosting (fixed) |
| `grids.S0.kappa` | float | 1.0 | S0 and S0_key |
| `grids.S1.kappa` | list[float] | {0, 0.1, …, 0.6, 0.6676} (8); maximum must be < 0.6676164 | S1 and S1_key |
| `grids.S2.kappa` | list[float] | {0, 0.5, 1, 2, 4, 8} (6) | S2 and S2_key |

## Frozen registry

`docs/revision/wp2/grid_registry.json` lists all 157 candidates in declared grid order, each with family, candidate_id, parameters, grid_index, n_nonzero, tuned/learned flags, granularity, heuristic label and description. It also records:

- `config_sha256`: 498290d10990740e488df7f2e42f633719bb8163672646e4157f234634f7035f
- `registry_sha256`: e2f088ed3b8c70f762600069ffd0676cde79a2311403f801526518e9b59cb23a (supersedes eab4ca3f86ace522f26f740afee70b31ad7e9099c578b7f2c82ee3e884e363ac, archived in `superseded/`, after the WP4 native-score correction; `supersedes` records the reason)
- `revised_results_seen`: false, and the freeze timestamp.

`wp2_run_comparison.py` refuses to run if the loaded config does not reproduce `registry_sha256`.

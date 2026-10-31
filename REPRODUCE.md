# Reproduction

Download `soc-alert-prioritization-v2026.10.30.tar.gz` from the
[versioned release](https://github.com/muratmoran/soc-alert-prioritization-reproducibility/releases/tag/v2026.10.30) and verify it against `SHA256SUMS`.
Extract it into a new directory. The commands below run from the extracted
archive root, which contains `repository/`, `external_data/`, and `environment/`.
The GitHub checkout alone is sufficient to read the code and compile the supplied
manuscript, but the complete archive is needed for asset/analysis reproduction.

## Environment

Use Python 3.10 and install `environment/review-requirements.txt` in an isolated
environment. The recorded analysis used Python 3.10.18, NumPy 2.0.1, pandas 2.3.1,
and scikit-learn 1.7.1. The supplied NumPy 2.x caches are not compatible with
NumPy 1.x. PDF compilation requires TeX Live, `latexmk`, and Ghostscript.

```sh
python -m pip install -r environment/review-requirements.txt
export SOC_REVISION_DATA="$PWD/external_data/soc_revision_data"
export MPLCONFIGDIR="/tmp/soc-review-matplotlib"
export XDG_CACHE_HOME="/tmp/soc-review-cache"
export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1
export MKL_NUM_THREADS=1
cd repository/v2_soc_alert_prioritization
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/revision/review_reproduce.py --assets --compile
```

The asset command verifies and summarizes saved completed outputs. It does not
recompute all model fits. To recompute the exploratory extension in a new
directory without replacing the supplied results:

```sh
python scripts/revision/review_reproduce.py   --rerun-dir results/fresh_reproduction --assets --compile
```

The destination must not already exist. Full fitting is substantially slower
than rebuilding assets. The extension comprises 23 policy configurations and
184 outer fits, 5,600 randomized-tie replays, and 168 grouped replays. The two
learned families are outside the mechanism-sensitivity extension.

To compile only, run `python scripts/revision/review_reproduce.py --compile`.
The modular article and flattened `main_submission.tex` must have identical
text and rendered pages. The supplement compiles as `supplementary.pdf`; the
release copy of that file is named `ESM_1.pdf` for journal submission.

## Scientific records

- `docs/revision/protocol_v1_1.md`: primary comparison protocol.
- `docs/revision/wp2` through `wp5`: frozen configurations, metric/fitting gates,
  original selected candidates and replay specifications.
- `docs/revision/wp7`: primary statistical results and UWF crosswalk consistency.
- `docs/revision/jnsm_20261026`: forward evaluation, support diagnostics, and
  separately specified rate adaptation.
- `docs/revision/jnsm_20261030/amendment.md`: exploratory extension specification.
- `docs/revision/jnsm_20261030/*.csv`: current per-scenario results and summaries.
- `results/jnsm_20261030`: full extension outputs and fitting traces (full archive).

Paths above are relative to `repository/v2_soc_alert_prioritization/`.
Earlier manifests describe their dated experiments and are retained as provenance.
They are not current release inventories. `MANIFEST.sha256` covers every supplied
file; `PUBLICATION_CHECKS.json` reports independent package verification.

All 131 tests complete with one known expected failure documenting the withdrawn
NF-UQ category-sampling diagnostic. NF-UQ is not supporting evidence for this
manuscript and its result datasets are not included. The original source and
boundary test are retained so the documented failure remains visible.

Labels denote membership in attack intervals. They do not establish individual
alert maliciousness or confirmed incident detection. Equal service time per raw
record or closed group is an assumption; no analyst productivity claim is made.
See `DATA_SOURCES.md` and `LICENSES.md` for source versions, transformations, and
component-specific reuse terms.

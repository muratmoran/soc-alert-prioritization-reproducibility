# Security alert prioritization under limited capacity

Reproducibility materials for **Evaluating Security Alert Prioritization under
Limited Capacity: Rule Granularity, Score Ties, and Coverage Tradeoffs**, by
Murat Moran, Giresun University. This is a research manuscript; journal acceptance
is not claimed.

- [Read the article](repository/computers_security_revision/main.pdf)
- [Online Resource 1](repository/computers_security_revision/ESM_1.pdf)
- [Download the versioned reproduction archive](https://github.com/muratmoran/soc-alert-prioritization-reproducibility/releases/tag/v2026.10.30)
- [Reproduction instructions](REPRODUCE.md)
- [Dataset attribution](DATA_SOURCES.md) and [licenses](LICENSES.md)
- [Study history and scope](STUDY_HISTORY.md)

The comparison uses eight AIT scenarios and 2,655,821 alerts. It distinguishes
interval coverage, false-positive burden, critical-alert retrieval, and timing.
The primary comparison is frozen; separately specified exploratory analyses
examine policy sensitivity, randomized ties, and grouped service.

Class-level formula scores cover the same eight critical intervals under the
declared static policy. Identifier-level coverage gains depend on mapping
policy: purity 0.9 removes that gain. In raw-alert replay, high coverage can
coexist with late first investigations and extensive critical-alert deferral.
Grouped service changes the investigation unit and its interpretation.
Interval membership is a temporal proxy, not confirmed attack detection.

The repository contains the current manuscript, code, tests, configurations,
scientific protocols, verification records, and compact result tables. The
release archive additionally supplies attributed data caches and detailed
saved outputs required for reproduction. GitHub's automatic source ZIP alone
does not contain those data. Editorial correspondence, working drafts, and
private repository history are excluded.

Version: `v2026.10.30`. Original code is MIT; original documentation/results are
CC BY 4.0. Manuscript and third-party rights are separate. No Zenodo DOI has
been assigned. Consult the release checksums when downloading files.

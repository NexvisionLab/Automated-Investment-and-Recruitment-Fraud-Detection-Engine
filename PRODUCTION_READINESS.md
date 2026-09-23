# Production readiness policy

This repository can produce a technically verified synthetic research release. It is not production-approved merely because generation, validation and tests pass.

Production approval requires all gates in `quality/PRODUCTION_READINESS_REPORT.md` to pass with human-owned evidence. The build system must never generate or infer those approvals.

## Required evidence

1. Native-speaker review of every supported non-English language and relevant regional register.
2. Independent real-world evaluation separated by campaign, actor, source, platform and time.
3. Calibration, false-positive, abstention and out-of-distribution performance by language, subtype and channel.
4. Legal, privacy, licence and data-governance approval for every real-data source and deployment jurisdiction.
5. Security threat assessment and release approval.
6. Protected Git branch, mandatory review, CI, immutable release tag and retained build evidence.
7. Written NexVision Lab production-owner authorization.

Run `python scripts/production_readiness.py` to refresh the evidence report. Run with `--strict` only as a production promotion gate; a non-zero result is expected until every independent approval is recorded.

The dataset remains unsuitable as the sole basis for automated adverse decisions or allegations about a person, organisation, country or language group.

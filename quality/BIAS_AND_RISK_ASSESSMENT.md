# Bias and risk assessment

This release is balanced by design, not by observed prevalence. Country, language, channel and currency fields are scenario controls and must not be interpreted as demographic or geographic risk estimates.

Primary risks are template artefacts, false confidence from synthetic performance, uneven naturalness across languages, over-triggering on finance/job vocabulary, and under-detection of novel campaigns. Mitigations include explicit provenance, hard negatives, awareness/negation examples, OOD abstention cases, group-isolated splits, native-review flags and a prohibition on standalone production claims.

Before deployment, evaluate independently collected and lawfully held data by language, country, scam subtype, channel and harm type. Report false-positive and abstention rates, calibration error and performance intervals. Human review must remain available for consequential decisions.

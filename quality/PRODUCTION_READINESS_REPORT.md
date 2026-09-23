# Production readiness report

**Overall status: NOT_READY_FOR_PRODUCTION**

Technical release status: **PASS**
Blocked gates: **7**

Technical PASS means the synthetic research release is reproducible and internally consistent. It does not authorize operational or commercial deployment.

| Gate | Requirement | Status | Evidence | Owner |
|---|---|---|---|---|
| T01 | Dataset validation | **PASS** | quality/validation_report.json | Engineering |
| T02 | Complete release manifest | **PASS** | metadata/release_manifest.json | Engineering |
| T03 | Synthetic provenance and safe indicators | **PASS** | validation checks: safe_provenance_flags, reserved_urls_only | Data governance |
| T04 | External records excluded | **PASS** | metadata/external_sources_manifest.csv | Data governance |
| G01 | Native-language review | **BLOCKED** | quality/native_review_matrix.csv | Language review lead |
| G02 | Independent real-world validation | **BLOCKED** | campaign- and time-separated evaluation report | Validation lead |
| G03 | Bias, calibration and abstention review | **BLOCKED** | per-language/subtype/channel metrics | ML governance |
| G04 | Legal and privacy review | **BLOCKED** | approved lawful-basis, privacy and data-use record | Legal/privacy |
| G05 | Security release review | **BLOCKED** | signed security review and threat assessment | Security |
| G06 | Git repository governance | **BLOCKED** | protected branch, review and immutable release evidence | Repository owner |
| G07 | Production owner approval | **BLOCKED** | written NexVision Lab approval | Product owner |

## Decision

Do not use this synthetic dataset as the sole basis for a production scam decision system while any governance gate is blocked.
Populate `metadata/production_attestations.json` only after the named reviewer has approved linked evidence. Self-attestation by the generator or build process is not sufficient.

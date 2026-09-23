# Dataset QA report

**Status: PASS**

Records: 64,000

## Checks

- PASS — record count
- PASS — unique ids
- PASS — unique content
- PASS — language count
- PASS — taxonomy leaf count
- PASS — domain balance
- PASS — label counts
- PASS — record type counts
- PASS — leaf balance
- PASS — campaign split isolation
- PASS — variant family split isolation
- PASS — reserved urls only
- PASS — content hashes valid
- PASS — safe provenance flags
- PASS — no transient release files
- PASS — language balance
- PASS — multilingual english cue removed
- PASS — ood abstention metadata
- PASS — robustness variants present
- PASS — curated eval integrity
- PASS — all required fields

## Important limitations

- All included records are synthetic and require external validation before performance claims.
- Non-English leaf labels require native-speaker review.
- External source records are not redistributed in this package.
- Campaign isolation prevents generator-family leakage only; it is not a substitute for independent real-world testing.

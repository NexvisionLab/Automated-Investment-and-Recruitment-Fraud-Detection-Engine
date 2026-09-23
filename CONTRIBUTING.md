# Contributing

Contributions should improve correctness, coverage, documentation or safety without weakening provenance controls.

## Development workflow

1. Use Python 3.10 or later.
2. Do not add real personal data, credentials, live scam infrastructure, wallet addresses or active malicious links.
3. Generate the canonical corpus with `python scripts/generate_dataset.py`.
4. Run `python scripts/validate_dataset.py`.
5. Run `python -W error::ResourceWarning -m unittest discover -s tests -v`.
6. Refresh `python scripts/release_manifest.py` and `python scripts/production_readiness.py`.

Changes to templates, taxonomy, labels or language content require updated tests and documentation. Non-English changes require native-speaker review before any validation claim. Preserve campaign and variant-family isolation across dataset splits.

By contributing, you agree that your contribution is distributed under the repository's PolyForm Noncommercial 1.0.0 terms. Commercial rights are not granted.

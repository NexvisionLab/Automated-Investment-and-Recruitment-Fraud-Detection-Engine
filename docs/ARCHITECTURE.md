# Architecture and data flow

## Purpose

NexVision ScamIntel Dataset is an offline, deterministic research-data pipeline. It generates synthetic job- and investment-scam examples, hard negatives, awareness messages and abstention cases without calling an external service.

## Data flow

1. `scripts/language_seed.py` supplies auditable multilingual phrase families.
2. `scripts/generate_dataset.py` combines taxonomy, language, channel, country-context and robustness variants using a fixed seed.
3. The generator writes the canonical JSONL corpus, indexes, samples, taxonomy and statistics.
4. `scripts/validate_dataset.py` enforces record counts, schema expectations, leakage controls, provenance and reserved-domain safety.
5. `scripts/release_manifest.py` creates a complete SHA-256 inventory.
6. `scripts/production_readiness.py` separates automated technical gates from human-owned governance approval.
7. `scripts/build_release.py` creates and verifies a deterministic release archive.

## Trust boundaries

- No network client, credential store, database or subprocess is used by the dataset pipeline.
- Generated URLs are restricted to reserved `.invalid` and `.example` domains after obfuscation normalization.
- External datasets listed in the research manifest are references only and are not redistributed.
- The build process cannot approve linguistic, legal, security or operational governance gates.

## Generated versus maintained files

The public source repository omits `data/records.jsonl` because it is a reproducible 64,000-record generated artifact larger than GitHub's ordinary file limit. Run the generator before validation or testing. Curated samples remain committed for inspection.

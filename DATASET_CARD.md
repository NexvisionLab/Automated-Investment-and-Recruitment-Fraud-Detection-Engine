# Dataset card

## Intended uses

- Defensive scam-classification research.
- Rule, machine-learning and hybrid-system regression testing.
- Multilingual detection prototyping and error analysis.
- Conversation-escalation and scam-lifecycle experiments.
- Explainability, abstention and out-of-distribution safeguard development.

## Out-of-scope uses

- Generating real scam campaigns or impersonating real organisations.
- Measuring real-world accuracy without independent validation.
- Treating synthetic labels as proof of fraud or criminal intent.
- Country, ethnicity or language profiling.
- Automated adverse decisions about individuals.

## Construction

Every record was generated offline using deterministic templates derived from an evidence-based taxonomy. Names are explicitly fictional, links use the reserved `.invalid` domain, authentication values are never populated, and wallet or account details are represented only by safe placeholders.

The package does not copy or redistribute records from the external sources listed in `metadata/external_sources_manifest.csv`. That manifest records possible future ingestion sources, their published counts, access state and licence review requirements.

## Labels

| Field | Values |
|---|---|
| `label` | `scam`, `legitimate`, `awareness`, `ambiguous_ood` |
| `domain` | `job`, `investment` |
| `record_type` | `single_message`, `conversation` |
| `split` | `train`, `validation`, `test` |
| `synthetic` | Always `true` in version 1.2.0 |
| `review_status` | `internal_template_review` for English; `native_speaker_review_required` otherwise |
| `variant_type` | Six clean/obfuscated robustness forms |
| `severity` | `none`, `medium`, `high` |

## Splitting policy

Splits are assigned by a SHA-256 hash of `campaign_group_id`, producing an approximately 80/10/10 distribution. Every campaign and `variant_family_id` is confined to one split. This reduces leakage between variants produced from the same template family.

`ambiguous_ood` records are designed for abstention or human-review experiments. They are deliberately under-specified and carry confidence `0.5`; they should not be silently merged into the legitimate class.

## Known limitations

- Synthetic language is less varied than naturally occurring scam communication.
- Non-English grammar, dialect, register and code-switching require native-speaker review.
- Taxonomy coverage does not establish prevalence.
- The dataset cannot model newly emerging campaigns without maintenance.
- Safe placeholder URLs and identifiers differ from live infrastructure distributions.
- The generator can introduce template artefacts; independent real-world testing is mandatory.

## Maintenance

New versions should append source and annotation provenance, preserve earlier immutable releases, and publish migration notes. Real samples must be stored in separate licence/provenance partitions and subjected to privacy review, deduplication and campaign-level splitting.

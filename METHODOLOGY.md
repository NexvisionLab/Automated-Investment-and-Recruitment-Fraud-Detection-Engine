# Methodology and governance

## Taxonomy design

The taxonomy separates the claimed opportunity from the mechanism of harm. For example, a job offer can lead to an advance-fee loss, credential theft, malware installation, money laundering, reshipping or trafficking. An investment pitch can lead to a fake platform, market manipulation, pyramid recruitment, clone-firm impersonation or recovery fraud.

Each leaf records:

- a stable taxonomy identifier;
- a plain-language definition;
- the principal deception mechanism;
- observable signals;
- likely scam-lifecycle stages.

## Record construction

Records combine an auditable language phrase pack with fictional entities, country and currency context, delivery channel, lifecycle stage, payment method, safe amount, reserved URL and campaign identifier. Legitimate examples deliberately contain scam-adjacent terms while explicitly denying fees, transfers, passwords and OTP requests. Awareness examples contain risky phrases in warning or negated contexts. OOD examples are intentionally insufficient for a fraud conclusion and are labelled for abstention.

Non-English `text` contains target-language template content rather than an injected English leaf description. The English analytical paraphrase is stored separately in `text_en`, and exact leaf-level rationale in `scenario_cue_en`. Non-English leaf specificity is marked `mechanism_level` until native reviewers author or approve leaf-specific language.

Conversation records preserve speaker roles and also include a flattened `text` representation. Scam conversations model contact, recipient verification, pressure, refusal and escalation. Legitimate conversations model verification through official channels and explicit confirmation that no payment or secret is required.

## Leakage controls

- Campaign groups are assigned to one split only.
- Variant families are assigned to one split only.
- Stable record IDs and SHA-256 content hashes support deduplication.
- The validator rejects exact content duplicates.
- External-source imports must deduplicate across both normalized text and campaign identifiers before joining any release.

## Safety controls

- Only reserved `.invalid` or `.example` links are allowed.
- No live telephone numbers, wallet addresses, credentials or account numbers are generated.
- Every record is marked synthetic and safe-placeholder-only.
- External records are referenced in a manifest but not redistributed.

## Release gates

The following remain open before production-performance claims:

1. Native-speaker review for every non-English language.
2. Independent real benign and scam corpus with documented consent or lawful basis.
3. Campaign-, actor-, platform- and time-separated external evaluation.
4. Country and language calibration with uncertainty intervals.
5. External out-of-distribution and abstention testing beyond the included designed cases.
6. Human-factors testing of risk explanations and false-positive consequences.

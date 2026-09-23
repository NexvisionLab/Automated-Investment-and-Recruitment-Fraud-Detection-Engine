# Annotation guidelines

## Decision order

1. Identify whether the message makes or advances a job or investment proposition.
2. Identify the requested action: payment, transfer, credential disclosure, software installation, reshipping, recruitment or travel/document surrender.
3. Check whether risky language is quoted, negated, educational or part of an official no-payment notice.
4. Use `scam` only where the synthetic ground truth contains a deceptive mechanism and harmful action.
5. Use `legitimate` for a complete benign context, and `awareness` for warnings or educational descriptions.
6. Use `ambiguous_ood` where evidence is insufficient or the content is adjacent but non-transactional; route these cases to abstention/human review.

## Severity

- `high`: identity theft, malware, money-mule activity, reshipping, trafficking or document surrender.
- `medium`: other scam-labelled financial or social-engineering actions.
- `none`: legitimate, awareness and ambiguous/OOD records.

## Multilingual review

Review meaning, grammar, register, locale fit, script correctness and whether the requested action remains clear. Do not infer a sender's location from `country`. Record disagreements in `inter_annotator_template.csv`; do not overwrite generator provenance.

## Prohibited assumptions

Brand names, urgency, cryptocurrency, remote work or high returns are signals, not proof in isolation. Negated and quoted terms must be interpreted in context. Synthetic labels must not be used as evidence against a person or organisation.

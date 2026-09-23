# Methodology and research basis

## Threat model

The checker targets social-engineering evidence in job and investment approaches: advance fees, task deposits, reshipping, money movement, fake cheques, credential theft, guaranteed returns, fake investment dashboards, withdrawal blocks, pressure, impersonation and off-store apps.

Patterns were derived from public advisories and standards, with particular attention to Singapore Police Force and ScamShield task/job/investment warnings, FTC employment and investment guidance, regulator verification practice, Unicode Technical Standard #39 and the Mozilla Public Suffix List.

Primary references:

- Singapore Police Force newsroom: https://www.police.gov.sg/Media-Room/News
- ScamShield scam types and checking guidance: https://www.scamshield.gov.sg/
- MAS Investor Alert List: https://www.mas.gov.sg/investor-alert-list
- MAS Financial Institutions Directory: https://eservices.mas.gov.sg/fid
- FTC job scams: https://consumer.ftc.gov/articles/job-scams
- FTC investment scams: https://consumer.ftc.gov/articles/investment-scams
- SEC Investor.gov fraud red flags: https://www.investor.gov/protect-your-investments/fraud/types-fraud
- Unicode UTS #39: https://unicode.org/reports/tr39/
- Public Suffix List: https://publicsuffix.org/
- ICANN registration data and RDAP: https://www.icann.org/rdap

The sources define behaviors and verification principles. They do not validate this software's accuracy.

## Evidence pipeline

1. Preserve the original evidence and compute its SHA-256 digest.
2. Create a loss-aware normalized copy: NFKC, invisible/control removal, defanging restoration, homoglyph skeleton, spaced-letter collapse and limited leetspeak handling.
3. Apply explainable patterns with local negation and educational-warning suppression.
4. Parse message turns and score ordered escalation stages.
5. Extract URLs, email addresses, phone numbers, handles and cryptocurrency wallets.
6. Resolve registrable domains with the bundled PSL and inspect structural/brand/email mismatches.
7. Run the local multilingual character n-gram classifier, or abstain.
8. Fuse bounded components and produce an evidence-backed band.

## Fusion

Rules use severity weights, then pass through a diminishing-return curve capped at 68 points. Conversation escalation is capped at 30; URL at 28; identity at 25; Unicode at 7; and the local model at 28. The total is capped at 100. A decisive critical rule can still produce a high band when the model abstains.

Bands: 75-100 Critical; 50-74 High; 25-49 Elevated; 0-24 Low. "Needs review" is used for model abstention without a decisive rule. These are operational triage bands, not externally calibrated fraud probabilities.

## Local classifier

The model is a smoothed Multinomial Naive Bayes classifier over character 3-5-grams plus word anchors. It trains deterministically from a small bundled seed corpus at runtime. A temperature of 2.4 softens raw log-odds. This scaling was chosen on internal development examples only and must not be interpreted as population calibration.

Supported profiles are English, Singlish, Chinese, Malay/Indonesian and Tamil. The system abstains for unsupported scripts, very short evidence or sparse near-boundary cases. Rules may still make a decisive finding during model abstention.

## Domain and web safety

The bundled PSL determines the public suffix and registrable domain; naive last-two-label parsing is not used. Brand findings compare a domain label with a small transparent allowlist and edit-distance heuristic. This can produce false positives and is never proof of impersonation.

Optional network actions use only direct DNS/TLS or direct retrieval of the user-supplied webpage. The HTML fetcher allows HTTP/HTTPS on ports 80/443, requires every resolved address to be public, pins the connection to a vetted address, limits one redirect and 600 KB, applies timeouts and does not execute scripts.

DNS record presence, TLS validity and a registered company are not proof that an offer is legitimate.

## OCR and reports

OCR invokes the local Tesseract executable in a temporary directory, validates PNG/JPEG magic bytes, enforces an 8 MB input limit and deletes the temporary file automatically. It never calls cloud OCR.

Reports are built locally. HTML escapes displayed evidence and embeds the full JSON in a non-executing JSON script block. PDF creation uses local ReportLab. Reports should be stored together with original evidence; the embedded hash covers the analyzed text, not external attachments.

## Validation design

The regression suite contains 25 risky semantic bases and 20 safe/educational bases, each exercised across six context-preserving variants: 270 curated cases total. These cases are deterministic regression fixtures, not a prevalence-weighted field dataset. Training seeds and regression fixtures are separate files.

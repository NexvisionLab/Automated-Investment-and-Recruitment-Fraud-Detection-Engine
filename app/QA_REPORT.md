# QA report - v2.0.0

Validation date: 2026-09-23 UTC

## Automated results

- Python unit/integration tests: 28/28 passed.
- Curated regression cases executed inside the suite: 270.
  - Risky: 150/150 matched their intended rule.
  - Safe/educational: 120/120 avoided High/Critical classification.
- Python compilation and browser JavaScript syntax checks: passed.
- Local API health/security headers, URL-only and malformed-request behavior: passed.
- HTML and PDF report generation: passed.
- PSL cases for `co.uk` and `com.sg`: passed.
- Brand-like domains and recruiter/company email mismatch: passed.
- English/Singlish, Chinese, Malay/Indonesian and Tamil signals: passed.
- Out-of-distribution abstention: passed.
- Static HTML inspection: passed; scripts counted but never executed.
- Unicode/invisible/homoglyph/spaced-letter normalization: passed.

## Manual and visual checks

- Example staged conversation produced the expected escalation timeline.
- Sample PDF rendered with Poppler and was visually inspected for clipping, overflow and legibility.
- Local Tesseract OCR was exercised against a generated PNG screenshot.
- UI has unique element IDs, valid label targets and local-only script/style assets.

## Security checks

- Server defaults to loopback.
- Non-loopback binding and untrusted Host headers are rejected.
- Content Security Policy, frame denial, no-sniff, no-referrer and no-store headers are set.
- Request body and text lengths are bounded.
- OCR accepts only base64 PNG/JPEG, caps input at 8 MB and uses a temporary directory.
- Optional HTML retrieval blocks private/reserved IP destinations, nonstandard ports, oversized responses and multi-hop redirects.
- Report endpoints accept only a recognizable analysis result.
- HTML/PDF reports include the submitted message and source link, escape active markup and use band-specific color indicators.
- No professional API, cloud model, analytics SDK, remote JavaScript or API key is present.

## Known limitations

- The regression set measures stability on curated fixtures, not real-world precision/recall.
- The language model is intentionally small and may miss nuanced or code-switched persuasion.
- OCR quality depends on image quality and locally installed Tesseract language packs.
- DNS TXT/MX parsing is intentionally minimal; truncated UDP replies may be incomplete.
- Brand and domain heuristics can create false positives.
- Safe HTML inspection cannot establish ownership or legitimacy.
- Manual regulator and company verification remains required.

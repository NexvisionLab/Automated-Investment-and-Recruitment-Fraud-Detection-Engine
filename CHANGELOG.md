# Changelog

## Unreleased

- Malay, Indonesian and Tamil coverage, and a fee wording the English rule missed. Found by running 23 job and investment
  scams in 16 languages through the checker. The engine claims Malay/Indonesian and Tamil but had one rule for each, so a
  Malay guaranteed-profit pitch ("Untung pasti 20% setiap minggu tanpa risiko") scored Low 13 and a Tamil "pay a fee first to
  confirm the job" scored Low 4. New rules: `ms_guarantee`, `ms_unrealistic_return`, `ms_fee_job`, `ms_easy_income`,
  `ms_regulator_claim`, `ms_pressure`, `ta_fee_job`, `ta_easy_income`, `ta_guarantee`. They need the return or job context, so
  "Diskon hingga 30% setiap hari", "tiada yuran pendaftaran" and "prestasi lalu bukan jaminan" stay Low. In English,
  `job_upfront_fee` now also matches a named fee ("To process your work permit and uniform please pay a refundable fee"),
  which was only Elevated 32; it no longer matches across a full stop, it stands down on "no registration fee", "we never
  charge any fee" and "the company will pay for your visa" when that is said in the same sentence as the fee (a "no interview
  fee" in one sentence does not hide a registration-fee demand in the next), and it requires the text to be about a job, so a
  course registration fee no longer scores Critical. `app/tests/test_multilingual_rules.py` covers the scams and 12 genuine
  messages. Not added: Spanish, French, Portuguese, German, Vietnamese, Tagalog, Hindi, Arabic and Thai still have no rules (the
  last three abstain); the DarkNyx checker now says so.

- Word boundaries on three rules that started with a short word. `pressure` matched "act" inside "action" ("No action is
  needed today" scored Elevated), "pay" inside "payment" ("Your payment is due today") and "join" inside "joined" ("She
  joined the company now"); `no_risk` matched "no" inside "know" ("I know the risks of this project" scored Elevated 49);
  `fake_regulation` matched "sec" inside "second" and "section" and "mas" inside "mass" ("The second draft was approved and
  licensed"). All three now need whole words. Real wordings ("Act now, offer ends today", "Invest today", "zero risk",
  "MAS approved", "SEC regulated") are tested to still match, and `tests/test_word_boundaries.py` fails without the fix.

- Rule fixes found by testing job and investment wording. False alarms: an ordinary employee-referral bonus ("refer a
  friend who joins our team ... after 3 months") was scored Elevated as a pyramid indicator, and a warehouse job advert
  ("Uniform provided free. Walk in with your NRIC.") was scored High because `sensitive_data` matched "provide ... nric"
  across a full stop. Misses: "Deposit $200 to activate your account", "turned $1,000 into $50,000 in one month" and
  "re-label them and post to our overseas address" matched no rule. `sensitive_data` now needs whole words and the
  object in the same sentence, `referral_income` skips employment referrals unless profit, tiers, deposits or similar
  appear with it, and `account_upgrade`, `unrealistic_return` and `reshipping` gained the missing wordings.

- Scoring: with no rule matched, the classifier can now add at most 10 points, so it cannot lift a message out of Low
  by itself. It was trained on a few dozen sentences and rated a plain delivery notice and an invoice reminder as
  near-certain scams (0.997 and 0.999), which put both at Elevated. The blanket "no rule matched, cap at 20" is removed,
  because it also threw away real link evidence: a "verify now" text pointing at a brand look-alike domain was rated Low
  and is now Elevated. Messages with rule matches score exactly as before.

- README: added "How the checker decides" (pipeline diagram, the seven steps, the score components and their caps, a worked
  example and the limits of the scoring) and "How the dataset is built" (generator and release-gate diagram). Corrected the
  CI description to Linux, Windows and macOS. Documentation only; no behaviour change.

Cross-platform and security fixes found by auditing the release on Windows. Generated data is unchanged.

- Every generated CSV, Markdown and JSON file is now written with LF line endings on every operating system
  (the `csv` module defaults to CRLF, and Windows text mode translated the rest). Previously the on-disk bytes,
  and therefore the SHA-256 manifest, depended on the platform, contradicting the deterministic-bytes guarantee.
  `.gitattributes` now forces LF for all text files (CRLF for `.bat`).
- Dataset validation and the hygiene test no longer fail because of a virtual environment or other hidden directory
  inside the repository; a stray dotfile in a normal directory is still flagged.
- Checker API: `POST` requests must now use `Content-Type: application/json` and, if an `Origin` header is sent,
  it must match the server. Previously a web page on another site could send a cross-origin `text/plain` request to
  `127.0.0.1` with no CORS preflight and drive the local checker.
- Checker: the HTML inspector no longer crashes on a valueless attribute such as `<input type>`.
- Checker: text in an unsupported writing system (for example Russian, Greek or Arabic) now abstains with
  "Needs review". The script check used the look-alike-normalized text, in which Cyrillic letters had become Latin,
  so unsupported text was treated as supported and a clear scam was banded "Low".
- Checker: optional DNS checks use the machine's configured resolver, read from `/etc/resolv.conf` or the Windows
  registry, and can be overridden with `NEXVISION_DNS_RESOLVER`. On Windows the app previously ignored the
  configured resolver and queried 1.1.1.1. DNS transaction IDs are now random and replies must come from the
  resolver.
- Checker: the OCR language argument is validated before it is passed to `tesseract`.
- CI now runs on Linux, Windows and macOS; the README badge and `CITATION.cff` point at this repository.

## 1.2.0 — 2026-09-23

- Added full-file SHA-256 release manifests with packaged-archive verification.
- Added explicit technical and independently attested governance gates for production readiness.
- Added CI, dependency update configuration, security reporting guidance and production-control tests.
- Adopted the public project name NexVision ScamIntel Dataset and sanitized GitHub-ready documentation.
- Pinned GitHub Actions to verified immutable commit SHAs.
- Production status fails closed until all human-owned evidence gates are approved.

## 1.1.2 — 2026-09-23

- Enforced reserved `.invalid` and `.example` indicators by parsed hostname rather than substring.
- Added URL path/suffix-confusion regression tests.
- Excluded filesystem symlinks from deterministic release assembly.

## 1.1.1 — 2026-09-23

- Removed stale hidden partial datasets from the maintained source and release.
- Extended integrity hashes to decision-critical content fields.
- Added normalized safety checks for defanged, full-width and zero-width URL forms.
- Made split-file materialization atomic with cleanup on failure.
- Added deterministic release assembly, hygiene tests and an independent code-audit report.

## 1.1.0 — 2026-09-23

- Added 4,000 ambiguous/OOD abstention examples; total is now 64,000.
- Removed English scenario-cue injection from non-English message text.
- Added English audit text, action, harm, severity, confidence, review and robustness metadata.
- Added six obfuscation variants and variant-family split-isolation validation.
- Expanded documentation and human-review templates.

## 1.0.0 — 2026-09-23

- Initial 60,000-record offline research release.
- Balanced job and investment domains.
- Added 32 leaf scam types with 1,000 scam records each.
- Added 19-language phrase-template coverage.
- Added 12,000 multi-turn conversations.
- Added legitimate hard negatives and awareness/negation cases.
- Added campaign-grouped train, validation and test splits.
- Added provenance, external-source, licensing, checksum and QA documentation.

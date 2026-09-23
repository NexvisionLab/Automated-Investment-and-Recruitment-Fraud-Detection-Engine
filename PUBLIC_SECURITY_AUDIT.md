# Public security and privacy audit

**Project:** NexVision ScamIntel checker and dataset
**Audit date:** 2026-09-23  
**Release:** 1.2.0

## Result

The audited public source tree passed its current technical publication checks. It is suitable for public source publication under the included non-commercial licence. This result does not constitute production approval for a deployed scam-detection service.

## Checks performed

| Area | Result | Evidence |
|---|---|---|
| Credentials and secret-shaped values | Pass | No API keys, access tokens, private keys, passwords or credential files found |
| Personal information | Pass | No personal names, personal email addresses, telephone numbers or street addresses found |
| Network and external API use | Pass with documented boundary | No professional API, cloud AI or analytics integration; checker DNS/TLS and guarded target-page retrieval are opt-in and off by default |
| Unsafe execution | Pass with documented boundary | No shell execution, dynamic evaluation, pickle or unsafe YAML; optional local OCR invokes a fixed Tesseract executable without a shell |
| Synthetic-data safety | Pass | Records use synthetic placeholders and reserved `.invalid`/`.example` indicators |
| Dependency exposure | Pass | PDF dependency pinned to `reportlab==4.4.9`; GitHub Actions pinned to immutable commit SHAs; Dependabot configured |
| Generated-file hygiene | Pass | Caches, local environments, secrets and build archives are excluded from source control |
| Licence and provenance | Pass | NexVision Lab copyright, PolyForm Noncommercial 1.0.0, SPDX notice and external-source boundaries retained |

## Verification summary

- Deterministic generation: pass
- Dataset validation: 21/21 checks passed
- Regression suite: 20/20 tests passed
- Checker suite: 28/28 tests passed, including 270 curated cases
- Browser JavaScript syntax and Python compilation: pass
- Host-header/DNS-rebinding regression: pass
- HTML/PDF evidence retention, escaping and color-band regression: pass
- Manifest and archive verification: pass
- Extracted-release end-to-end verification: pass
- Production strict gate: expected fail-closed result while seven independent governance approvals remain absent

## Remaining governance requirements

Native-language review, independent real-world validation, bias and calibration evaluation, legal/privacy approval, security approval, protected repository governance and NexVision Lab production-owner authorization remain required before operational deployment.

The local classifier is trained on a small development seed and must not be represented as independently calibrated. The vendored Public Suffix List retains its MPL-2.0 notice, but its upstream commit/retrieval date still requires a provenance record at the next refresh.

## Authorship statement

No visible generation artifacts were found in the audited maintained scope after remediation. This does not prove that code or content was not AI-generated; authorship cannot be established from style alone.

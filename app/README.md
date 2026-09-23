# NexVision OSINT Job & Investment Scam Checker v2.0.0

A local, explainable triage application for job, paid-task, reshipping, money-mule and investment scams. It combines deterministic rules, a small multilingual character model, conversation sequencing and OSINT-oriented identity checks.

This is a research release. The bundled classifier is an experimental model trained on a small development seed and has not been independently validated on a representative real-world population. Its output is not a fraud probability or a substitute for human investigation.

## Privacy and network boundary

- Core message, conversation, screenshot OCR, HTML parsing and report creation run locally.
- No paid/professional reputation API, cloud AI API, API key or analytics service is used.
- Live checks are **off by default**. If enabled, the program performs direct DNS/TLS queries and, separately, a guarded fetch of the exact webpage the investigator supplied.
- Message content is not sent to DNS, TLS or any third-party analysis service.
- The web server binds to `127.0.0.1` by default.

## Start

Requires Python 3.10 or later.

```bash
python3 app/server.py
```

Open `http://127.0.0.1:8787`. On Windows, double-click `start.bat`.

PDF export needs the local `reportlab` package. Screenshot OCR uses a locally installed `tesseract` executable. Everything else uses the Python standard library and bundled data.

```bash
python3 -m pip install -r app/requirements.txt
```

## What is new

### v1.1 detection expansion

- 34 explainable patterns, including task deposits, negative balances, task mistakes, paid upgrades, fake shops, physical cash collection, small trust payouts, group testimonials, celebrity endorsements and sideloaded apps.
- NFKC normalization, control/invisible stripping, practical Greek/Cyrillic homoglyph skeletons, defanged link/email restoration, spaced-letter collapse and common leetspeak decoding.
- Speaker-prefixed or structured multi-message analysis with an escalation timeline.
- Context-aware suppression for legitimate warnings and investment risk disclosures.
- A 270-case curated regression matrix, plus unit, server, security and report tests.

### v1.2 OSINT intelligence

- Registrable domains using a vendored Mozilla Public Suffix List, including wildcard and exception rules.
- Punycode, homoglyph/brand-like domain and recruiter/company email mismatch findings.
- Optional direct DNS, SPF/DMARC presence and TLS inspection. These are clues, never proof.
- Investigator workflow for company, regulator, licence and independently sourced contact verification.
- Static HTML inspection that never executes JavaScript. Optional retrieval blocks private/reserved addresses, nonstandard ports, oversized bodies and redirect abuse.
- Local screenshot OCR for PNG/JPEG evidence.

### v2.0 local hybrid intelligence

- Local English, Singlish, Chinese, Malay/Indonesian and Tamil character n-gram model.
- Bounded fusion of rule, conversation, URL, identity, Unicode and model components.
- Conservative risk bands with diminishing returns.
- Abstention for unsupported writing systems, very short input and sparse uncertain evidence.
- Downloadable JSON, self-contained HTML and PDF investigation reports.

## Programmatic use

```python
from analyzer import analyze

result = analyze(
    "Recruiter: Like products for commission.\nRecruiter: Top up USDT to unlock withdrawal.",
    source_url="https://example.invalid/offer",
    online_checks=False,
    claimed_company="Example Pte Ltd",
    claimed_domain="example.com",
    recruiter_email="agent@example-careers.xyz",
)
print(result["risk_band"], result["risk_score"])
```

The v1 `verdict`, `recommendations` and `warnings` aliases remain in the JSON response for compatibility.

## Test

```bash
cd app
python3 -m unittest discover -s tests -v
node --check static/app.js
python3 -m py_compile *.py
```

## Important limits

This is triage software, not a clearance service. A low score is not proof that an offer is genuine. Its calibrated model score is internal to the bundled development examples and is not a population probability of fraud. Verify the exact entity, representative, beneficiary and licence through independent official sources.

See `METHODOLOGY.md` for the evidence model and research basis, and `QA_REPORT.md` for the validation record.

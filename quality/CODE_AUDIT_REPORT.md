# Independent code audit report — NexVision ScamIntel

**Project:** NexVision ScamIntel checker and dataset
**Audit date:** 2026-09-23  
**Audited scope:** checker source/UI, tests, scripts, documentation, vendored Public Suffix List, schema, generated metadata/samples, canonical dataset and release archive
**Purpose mapped:** local job/investment scam triage plus deterministic generation and validation of a synthetic multilingual research corpus

## Executive conclusion

Across the dataset audit and checker-integration audit, confirmed defects and release-control weaknesses were found and remediated. The most significant dataset issue was two stale hidden partial datasets—one containing obsolete 1.0.0 records—inside the 1.1.0 release archive. The checker audit additionally found a localhost DNS-rebinding boundary weakness, incomplete investigation reports, a silent parser failure and a response-resource leak. Version 1.2.0 adds a complete content manifest, automated readiness gates, continuous integration and a fail-closed production decision.

No committed credentials, unsafe deserialisation, prompt fragments, chat transcripts, placeholder citations, “as an AI” wording or documented-but-stubbed workflows were found in the maintained source scope. The checker has documented, opt-in direct DNS/TLS and guarded webpage retrieval. Optional OCR invokes the local Tesseract binary without a shell. Matches for terms such as “AI” and “hacked” were legitimate scam-taxonomy, model documentation or synthetic-message content.

This finding means **no visible generation artifacts were found in the audited maintained scope**. It does not prove, and must not be represented as proving, that no code or content was AI-generated.

## Findings

| ID | Severity | Classification | File and line/evidence | Evidence and impact | Action |
|---|---|---|---|---|---|
| F-01 | High | Confirmed defect / visible artifact | Removed `data/.train.jsonl.OFMbbZ` and `data/.train.jsonl.SJCFiM`; both appeared in the 1.1.0 ZIP | Hidden partial datasets added about 121 MB uncompressed and exposed obsolete 1.0.0 content inconsistent with the release. | Removed. Added transient-file validation and regression coverage at `scripts/validate_dataset.py:86-89` and `tests/test_release_hygiene.py:21-27`. |
| F-02 | Medium | Confirmed defect | `scripts/generate_dataset.py:266-285`; `scripts/validate_dataset.py:30-50` | The 1.1.0 content hash covered label, primary text and turns but not English audit text or semantic annotations. Changes to decision-relevant fields could go undetected. | Hash payload now covers domain, taxonomy, language, both texts, turns, signals, action, harm, severity, confidence, label basis, OOD reason and variant. Mutation regression test added. |
| F-03 | Medium | Confirmed defect | `scripts/validate_dataset.py:20-27,66-69` | Reserved-domain enforcement examined ordinary `http(s)` text only. Defanged, full-width-colon and zero-width variants were not canonicalised before checking. | Added safe normalization before scanning primary text, audit text and conversation turns; regression test at `tests/test_release_hygiene.py:34-35`. |
| F-04 | Medium | Confirmed defect | `scripts/materialize_splits.py:16-52` | Direct split writes could leave incomplete outputs after interruption; prior working copies contained partial files. | Split output now uses same-directory temporary files, flush/fsync, atomic replacement, invalid-split rejection and failure cleanup. End-to-end temporary-directory test added. |
| F-05 | Medium | Confirmed defect | `scripts/build_release.py:19-70` | The earlier release was built with a broad recursive ZIP command, allowing hidden partial files into the deliverable. | Added sorted deterministic assembly, explicit exclusions, required-entry checks, duplicate detection and CRC verification. Full split JSONL files remain reproducible from the canonical file and are not duplicated in the archive. |
| F-06 | Medium | Confirmed defect | `schema/record.schema.json:6-70` | The schema did not require or constrain several fields relied upon by downstream auditing and modelling. | Expanded required fields and constraints for provenance, language/review state, actions, severity, lifecycle, source, campaign and safety fields. Added all-record required-field regression coverage. |
| F-07 | Low | Confirmed defect | Former generation assertions; replacements at `scripts/generate_dataset.py:510-511,552-553` | Critical count/slice invariants used `assert`, which Python can disable with optimization. | Replaced with explicit runtime exceptions and descriptive messages. |
| F-08 | Low | Confirmed defect | Headers in `scripts/*.py` and `tests/*.py` | Code files lacked the project’s requested source-level copyright/SPDX notice even though root licensing was correct. | Added `Copyright © 2026 NexVision Lab` and `SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`; preserved the full root licence. |
| F-09 | Low | Needs verification | Repository root | No `.git` metadata was supplied with the archive, so commit history, author attribution, branch policy and historical provenance could not be audited. | No history was invented or rewritten. Audit the GitHub repository separately after upload. |
| F-10 | High | Needs verification | `README.md:17-21`; `quality/native_review_matrix.csv` | All non-English material is template-generated and explicitly not human validated. Automated checks cannot establish naturalness, dialect fitness or translation quality. | Native-speaker review remains a release/production blocker and is accurately disclosed. |
| F-11 | Medium | Needs verification | `metadata/external_sources_manifest.csv`; `RESEARCH_SOURCES.md` | External source counts, access and licence notes are research leads. They were not independently refreshed during this code audit, and no external records are redistributed. | Preserve the manifest; re-verify source terms immediately before any ingestion. |
| F-12 | Informational | Style observation | `scripts/language_seed.py:18-298` | The shared language seed contains detection helpers and scam phrase families not invoked by this dataset generator. They are not reachable from production generation but may support planned expansion. | Preserved to avoid silently removing a potential interface. Review for extraction into a shared package if the repository becomes installable. |
| F-13 | High | Confirmed defect | `scripts/validate_dataset.py:30-38,75-77` | The earlier reserved-domain check used a substring. A live URL such as `https://attacker.example.org/.invalid/payload` could satisfy that check. | Added parsed scheme/hostname enforcement with exact reserved TLD matching and path/suffix-confusion tests. |
| F-14 | Medium | Confirmed defect | `scripts/build_release.py:19-29` | Recursive release discovery followed symlinks, allowing a repository symlink to include bytes from outside the project root. | Symlinks are now rejected before packaging; a regression test verifies exclusion. |
| F-15 | High | Confirmed defect | Former release process; replacement at `scripts/release_manifest.py` | There was no complete, machine-verifiable inventory of distributed files. Integrity checking covered only selected dataset content, so documentation, code or metadata tampering could be missed. | Added a deterministic SHA-256 manifest covering every distributed file and archive-time verification against that manifest. |
| F-16 | High | Confirmed defect | Former release process; replacements at `scripts/production_readiness.py`, `metadata/production_attestations.json` and `PRODUCTION_READINESS.md` | Passing technical tests could be mistaken for production approval despite absent linguistic, empirical, legal, security and governance evidence. | Added fail-closed technical/governance gates, evidence-bearing attestations and strict mode. Current overall result is deliberately `NOT_READY_FOR_PRODUCTION`. |
| F-17 | Medium | Confirmed defect | `.github/workflows/ci.yml` | Workflow actions used mutable major-version references, creating avoidable supply-chain risk. | Fixed by pinning `actions/checkout` and `actions/setup-python` to verified full commit SHAs while retaining readable version comments. |
| F-18 | Medium | Confirmed defect | `scripts/validate_dataset.py`; `tests/test_release_hygiene.py` | Repository hygiene rejected legitimate `.gitignore`, `.gitattributes` and `.github` controls, preventing a valid public source layout from passing its own checks. | Added explicit repository-metadata handling, continued rejection of secret dotfiles such as `.env`, and regression coverage. |
| F-19 | High | Confirmed defect | `app/server.py:24-30,51-52,84-85,97-103`; `app/tests/test_server.py` | The original loopback service accepted arbitrary Host headers and allowed an operator to bind to a non-loopback address. That weakened the local trust boundary and enabled DNS-rebinding-style access. | Added a loopback Host allowlist, rejected untrusted requests with 421, prohibited non-loopback binding and added an integration regression test. |
| F-20 | Medium | Confirmed defect | `app/analyzer.py`; `app/reporting.py:9-70`; `app/tests/test_v2.py` | HTML/PDF reports omitted the actual submitted message and explicit source link, and the HTML risk badge always used a red background regardless of the assessed band. This reduced evidentiary value and could miscommunicate risk. | Results now carry a dedicated evidence input, both reports show the submitted message/link, and risk bands use consistent red/orange/yellow/green/blue indicators. Report output is escaped and regression-tested. |
| F-21 | Low | Confirmed defect | `app/safehtml.py:40-62` | Static HTML parser failures were silently discarded, leaving investigators unable to distinguish a complete parse from a partial parse. | Narrowed handled exceptions and exposed `parse_error` in the inspection result. |
| F-22 | Low | Confirmed defect | `app/safehtml.py:72-101` | HTTP response/wrapped socket objects were not closed explicitly on every path. Repeated optional inspections could retain resources until garbage collection. | Added deterministic response and connection closure. Resource-warning test mode remains enabled in CI. |
| F-23 | High | Needs verification | `app/classifier.py:17-109`; `app/tests/curated_cases.py` | The local classifier is trained on 34 development seed messages and the 270 regression cases are curated transformations, not an independent representative evaluation. Its “calibrated” score is not a real-world fraud probability. | Preserved as an experimental bounded signal, added prominent research-status disclosures, and retained production blocking until independent campaign-separated validation and calibration are complete. |
| F-24 | Medium | Needs verification | `app/data/public_suffix_list.dat`; `app/data/MPL-2.0-Public-Suffix-List.txt` | The vendored Public Suffix List includes the MPL-2.0 notice but does not carry a verifiable upstream commit/date record in this package. Staleness cannot be established from the distributed file alone. | Preserve the licence and file. Record upstream URL, retrieval time and digest when refreshing it before a formal release. |

## Security and privacy review

- No credential-shaped values, private keys or API tokens were found in maintained source or documentation.
- No professional API, cloud-model call, analytics SDK, shell execution, dynamic evaluation, pickle or unsafe YAML loading was found.
- Generation, validation, split materialisation and release assembly operate offline. Checker live checks are opt-in direct DNS/TLS or guarded target-page retrieval; OCR invokes a locally installed Tesseract binary without a shell.
- The checker is bound to loopback and validates Host headers. Optional HTML retrieval pins the connection to a DNS-vetted public IP, limits ports/body/redirects and never executes page scripts.
- Generated links are reserved `.invalid`/`.example` indicators after de-obfuscation; the validator inspects `text`, `text_en` and conversation turns.
- Records remain synthetic, use safe placeholders and contain no imported external-source records.

## Licensing and provenance review

- Root `LICENSE` is PolyForm Noncommercial 1.0.0.
- README and dataset notice retain NexVision Lab copyright, the SPDX identifier and the requirement for separate written authorisation for commercial use, paid services, hosted services, production deployment and commercial redistribution.
- Source and test files now carry matching copyright/SPDX notices.
- External datasets are referenced only; their records are not redistributed.

## Verification performed

| Command/workflow | Result |
|---|---|
| `python3 scripts/generate_dataset.py` | PASS; deterministic 64,000-record corpus generated |
| Repeat generation plus SHA-256 comparison | PASS; canonical corpus byte-identical |
| `python3 scripts/validate_dataset.py` | PASS; 21/21 dataset checks |
| `python3 -W error::ResourceWarning -m unittest discover -s tests -v` | PASS; 20/20 tests |
| `python3 -m compileall -q scripts tests` | PASS |
| `python3 -m unittest discover -s app/tests -v` | PASS; 28/28 checker tests and 270 curated cases |
| `node --check app/static/app.js` | PASS |
| Representative HTML/PDF report with markup-bearing evidence | PASS; evidence retained and HTML escaped |
| `python3 scripts/build_release.py` | PASS; archive allowlist, required entries and CRC verified |
| `python3 scripts/release_manifest.py` | PASS; complete distributed-file SHA-256 manifest verified |
| `python3 scripts/production_readiness.py` | Technical PASS; overall `NOT_READY_FOR_PRODUCTION` with seven blocked human/governance gates |
| `python3 scripts/production_readiness.py --strict` | Expected exit 2; fail-closed promotion gate verified |
| Extracted-release validation, tests, manifest verification and compilation | PASS; 21/21 checks and 20/20 tests from packaged files |
| Secret/network/risky-API/artifact searches with `rg` | PASS for maintained source; contextual domain terms reviewed manually |
| Representative split materialisation in an isolated temporary directory | PASS; correct outputs and zero temporary residues |

No third-party linter, type checker or JSON Schema engine is bundled or installed. The checker has one pinned optional PDF dependency (`reportlab==4.4.9`) plus optional system Tesseract OCR; syntax compilation, custom schema/record checks and behavioural tests were run.

## Unresolved risks and required human review

1. Native-speaker validation for every non-English language and relevant regional register.
2. Independent real-world, campaign-separated evaluation before performance or production claims.
3. Fresh legal/licence review before ingesting any external dataset named in the research manifest.
4. Git history, pull-request and branch-protection audit after the project is placed in GitHub.
5. Bias, calibration, false-positive and abstention evaluation by language, country context, subtype and channel.
6. Human confirmation that the retained unused language helpers are intended shared assets; otherwise move them into a separately governed module in a future release.
7. Enable protected-branch review rules and private vulnerability reporting after repository creation.

## Final statement

**No visible artifacts were found in the audited maintained scope after remediation.** This is an evidence statement about the files and workflows inspected. It is not an unsupported claim that the repository contains no AI-generated work, because authorship cannot be proved or disproved from coding style alone.

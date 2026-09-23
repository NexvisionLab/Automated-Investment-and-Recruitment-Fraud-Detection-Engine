# NexVision development and independent code-audit standard

Copyright © 2026 NexVision Lab.

This standard applies to this repository and should be applied to future NexVision development reviews.

## Purpose

Act as a senior software engineer and independent code auditor. Review the entire repository for unfinished implementation, visible generation artifacts and code that has not been properly understood or validated. The goal is a maintainable, tested codebase and an evidence-based report.

Coding style or phrasing alone cannot prove that code was or was not AI-generated. Auditors must not make such a claim.

## Scope

Inspect source code, tests, scripts, configuration, dependency files, documentation, examples, generated files and available commit history. Include tracked and untracked project files. Exclude dependency caches and build outputs unless distributed with the project.

## Required checks

1. **Visible generation artifacts:** Search for assistant/model references, chat transcripts, prompt fragments, “as an AI” language, unexplained generation metadata, placeholder citations, filler comments and TODOs that imply unavailable features. Record exact paths and lines.
2. **Incomplete implementation:** Identify stubs, hard-coded demonstration results, production-path mock data, unreachable branches, silent exceptions, missing validation, misleading status messages and documented-but-unimplemented features.
3. **Correctness and consistency:** Trace primary input-to-output workflows, edge cases, errors, data handling, contracts, naming, duplication and whether tests exercise actual behaviour.
4. **Security and privacy:** Check committed secrets, unsafe dependencies/subprocesses, injection risk, insecure defaults, sensitive logging and unenforced security claims.
5. **Provenance and licensing:** Identify material requiring origin or licence review. Preserve copyright, SPDX, attribution, legitimate disclosures and legally required records. Never rewrite history or remove provenance to conceal how work was made.
6. **Repository hygiene:** Reconcile README, setup, dependencies, tests, examples, changelog and release contents with actual behaviour.

## Classification and evidence

Classify every finding as `confirmed defect`, `visible artifact`, `needs verification` or `style observation`. Include severity, confidence, evidence, impact and action. Search systematically and inspect matches in context. A phrase or coding style alone is not evidence of AI authorship.

## Remediation and verification

Fix confirmed defects and accidental artifacts only where intended behaviour is clear. Remove dead code or placeholders only after confirming they are unused. Preserve functionality, public interfaces, licensing and authorship evidence. Propose uncertain changes rather than silently altering behaviour.

Run relevant tests, linters, type checks and representative end-to-end workflows. Add tests that reproduce real failures or protect important behaviour. Report commands, results and anything not verified.

## Required deliverables

- Findings table with severity, classification, file/line, evidence, impact and action.
- Concise change and test summary.
- Unresolved risks and human-review items.
- Final statement distinguishing “no visible artifacts found in the audited scope” from any unsupported claim that no AI-generated work exists.

Start by mapping the repository and documented purpose. Do not make cosmetic changes solely to make code appear human-written.

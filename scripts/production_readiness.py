#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Evaluate technical and human production-readiness gates without self-approval."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from release_manifest import verify_manifest


ROOT = Path(__file__).resolve().parents[1]
ATTESTATIONS = ROOT / "metadata/production_attestations.json"
JSON_REPORT = ROOT / "quality/production_readiness_report.json"
MD_REPORT = ROOT / "quality/PRODUCTION_READINESS_REPORT.md"


def approved(attestation: dict[str, Any]) -> bool:
    return (
        attestation.get("status") == "approved"
        and all(isinstance(attestation.get(field), str) and attestation[field].strip() for field in ("reviewer", "reviewed_at", "evidence"))
    )


def gate(gate_id: str, name: str, status: str, evidence: str, owner: str) -> dict[str, str]:
    return {"id": gate_id, "name": name, "status": status, "evidence": evidence, "owner": owner}


def evaluate(root: Path = ROOT) -> dict[str, Any]:
    validation = json.loads((root / "quality/validation_report.json").read_text(encoding="utf-8"))
    language_audit = json.loads((root / "quality/language_audit.json").read_text(encoding="utf-8"))
    attestations = json.loads((root / "metadata/production_attestations.json").read_text(encoding="utf-8"))
    with (root / "metadata/external_sources_manifest.csv").open(encoding="utf-8", newline="") as handle:
        sources = list(csv.DictReader(handle))

    manifest_failures = verify_manifest(root)
    technical = [
        gate("T01", "Dataset validation", "PASS" if validation.get("status") == "PASS" else "BLOCKED", "quality/validation_report.json", "Engineering"),
        gate("T02", "Complete release manifest", "PASS" if not manifest_failures else "BLOCKED", "metadata/release_manifest.json", "Engineering"),
        gate("T03", "Synthetic provenance and safe indicators", "PASS" if validation.get("checks", {}).get("safe_provenance_flags") and validation.get("checks", {}).get("reserved_urls_only") else "BLOCKED", "validation checks: safe_provenance_flags, reserved_urls_only", "Data governance"),
        gate("T04", "External records excluded", "PASS" if all(row.get("included_in_records") == "No" for row in sources) else "BLOCKED", "metadata/external_sources_manifest.csv", "Data governance"),
    ]

    human_specs = [
        ("G01", "Native-language review", "native_language_review", "quality/native_review_matrix.csv", "Language review lead"),
        ("G02", "Independent real-world validation", "external_real_world_validation", "campaign- and time-separated evaluation report", "Validation lead"),
        ("G03", "Bias, calibration and abstention review", "bias_calibration_review", "per-language/subtype/channel metrics", "ML governance"),
        ("G04", "Legal and privacy review", "legal_privacy_review", "approved lawful-basis, privacy and data-use record", "Legal/privacy"),
        ("G05", "Security release review", "security_release_review", "signed security review and threat assessment", "Security"),
        ("G06", "Git repository governance", "git_repository_governance", "protected branch, review and immutable release evidence", "Repository owner"),
        ("G07", "Production owner approval", "production_owner_approval", "written NexVision Lab approval", "Product owner"),
    ]
    governance = [
        gate(gate_id, name, "PASS" if approved(attestations.get(key, {})) else "BLOCKED", evidence, owner)
        for gate_id, name, key, evidence, owner in human_specs
    ]
    if language_audit.get("human_validated_languages"):
        governance[0]["evidence"] += f"; recorded languages: {language_audit['human_validated_languages']}"

    technical_status = "PASS" if all(item["status"] == "PASS" for item in technical) else "BLOCKED"
    overall_status = "READY_FOR_PRODUCTION" if technical_status == "PASS" and all(item["status"] == "PASS" for item in governance) else "NOT_READY_FOR_PRODUCTION"
    return {
        "dataset_version": validation.get("dataset_version"),
        "evaluated_at": "2026-09-23",
        "technical_release_status": technical_status,
        "overall_status": overall_status,
        "technical_gates": technical,
        "governance_gates": governance,
        "blocked_gate_count": sum(item["status"] != "PASS" for item in technical + governance),
        "interpretation": "Technical PASS permits research release packaging only. Production use requires every governance gate to be independently approved with evidence.",
    }


def write_reports(report: dict[str, Any], root: Path = ROOT) -> None:
    json_path = root / "quality/production_readiness_report.json"
    md_path = root / "quality/PRODUCTION_READINESS_REPORT.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    lines = [
        "# Production readiness report", "",
        f"**Overall status: {report['overall_status']}**", "",
        f"Technical release status: **{report['technical_release_status']}**",
        f"Blocked gates: **{report['blocked_gate_count']}**", "",
        "Technical PASS means the synthetic research release is reproducible and internally consistent. It does not authorize operational or commercial deployment.", "",
        "| Gate | Requirement | Status | Evidence | Owner |", "|---|---|---|---|---|",
    ]
    for item in report["technical_gates"] + report["governance_gates"]:
        lines.append(f"| {item['id']} | {item['name']} | **{item['status']}** | {item['evidence']} | {item['owner']} |")
    lines.extend([
        "", "## Decision", "",
        "Do not use this synthetic dataset as the sole basis for a production scam decision system while any governance gate is blocked.",
        "Populate `metadata/production_attestations.json` only after the named reviewer has approved linked evidence. Self-attestation by the generator or build process is not sufficient.", "",
    ])
    md_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="exit with status 2 unless every production gate passes")
    args = parser.parse_args()
    report = evaluate()
    write_reports(report)
    print(json.dumps({key: report[key] for key in ("overall_status", "technical_release_status", "blocked_gate_count")}, sort_keys=True))
    if args.strict and report["overall_status"] != "READY_FOR_PRODUCTION":
        raise SystemExit(2)


if __name__ == "__main__":
    main()

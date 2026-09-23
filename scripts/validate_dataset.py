#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "records.jsonl"
EXPECTED = 64_000
EXPECTED_LANGUAGES = 19
EXPECTED_LEAVES = 32
ALLOWED_REPOSITORY_METADATA = {".gitignore", ".gitattributes"}


def normalize_url_obfuscation(text: str) -> str:
    return (
        text.replace("\u200b", "")
        .replace("：//", "://")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
    )


def is_reserved_url(url: str) -> bool:
    cleaned = url.rstrip(".,;:!?)]}>'\"")
    parsed = urlsplit(cleaned)
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    hostname = (parsed.hostname or "").rstrip(".").lower()
    return hostname in {"invalid", "example"} or hostname.endswith((".invalid", ".example"))


def content_hash_payload(row: dict) -> dict:
    return {
        "label": row["label"],
        "domain": row["domain"],
        "taxonomy_id": row["taxonomy_id"],
        "language": row["language"],
        "text": row["text"],
        "text_en": row.get("text_en"),
        "turns": row.get("turns", []),
        "signals": row.get("signals", []),
        "scenario_cue_en": row.get("scenario_cue_en"),
        "requested_action": row.get("requested_action"),
        "harm_vector": row.get("harm_vector"),
        "severity": row.get("severity"),
        "annotation_confidence": row.get("annotation_confidence"),
        "label_basis": row.get("label_basis"),
        "ood_reason": row.get("ood_reason"),
        "variant_type": row.get("variant_type"),
    }


def is_transient_project_file(path: Path, root: Path = ROOT) -> bool:
    relative = path.relative_to(root)
    if ".git" in relative.parts or ".github" in relative.parts:
        return False
    if relative.as_posix() in ALLOWED_REPOSITORY_METADATA:
        return False
    return any(part.startswith(".") for part in relative.parts) or path.suffix in {".tmp", ".partial", ".bak", ".pyc"}


def main() -> None:
    rows = [json.loads(line) for line in DATA.read_text(encoding="utf-8").splitlines() if line]
    failures: list[str] = []
    ids = [row["id"] for row in rows]
    hashes = [row["content_sha256"] for row in rows]
    group_splits: dict[str, set[str]] = defaultdict(set)
    family_splits: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        group_splits[row["campaign_group_id"]].add(row["split"])
        family_splits[row["variant_family_id"]].add(row["split"])
        expected_hash = hashlib.sha256(json.dumps(content_hash_payload(row), ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        if expected_hash != row["content_sha256"]:
            failures.append(f"hash mismatch: {row['id']}")
        searchable_content = "\n".join([row["text"], row.get("text_en", ""), *(turn.get("text", "") for turn in row.get("turns", []))])
        for url in re.findall(r"https?://[^\s]+", normalize_url_obfuscation(searchable_content), flags=re.I):
            if not is_reserved_url(url):
                failures.append(f"non-reserved URL: {row['id']} {url}")
        if row["synthetic"] is not True or row["contains_live_indicator"] is not False:
            failures.append(f"unsafe provenance flags: {row['id']}")

    checks = {
        "record_count": len(rows) == EXPECTED,
        "unique_ids": len(ids) == len(set(ids)),
        "unique_content": len(hashes) == len(set(hashes)),
        "language_count": len({row["language"] for row in rows}) == EXPECTED_LANGUAGES,
        "taxonomy_leaf_count": len({row["taxonomy_id"] for row in rows if row["label"] == "scam"}) == EXPECTED_LEAVES,
        "domain_balance": Counter(row["domain"] for row in rows) == {"job": 32_000, "investment": 32_000},
        "label_counts": Counter(row["label"] for row in rows) == {"scam": 32_000, "legitimate": 22_000, "awareness": 6_000, "ambiguous_ood": 4_000},
        "record_type_counts": Counter(row["record_type"] for row in rows) == {"single_message": 52_000, "conversation": 12_000},
        "leaf_balance": set(Counter(row["taxonomy_id"] for row in rows if row["label"] == "scam").values()) == {1000},
        "campaign_split_isolation": all(len(splits) == 1 for splits in group_splits.values()),
        "variant_family_split_isolation": all(len(splits) == 1 for splits in family_splits.values()),
        "reserved_urls_only": not any("non-reserved URL" in item for item in failures),
        "content_hashes_valid": not any("hash mismatch" in item for item in failures),
        "safe_provenance_flags": not any("unsafe provenance" in item for item in failures),
        "no_transient_release_files": not any(
            is_transient_project_file(path)
            for path in ROOT.rglob("*") if path.is_file() and "__pycache__" not in path.parts
        ),
    }
    language_counts = Counter(row["language"] for row in rows)
    checks["language_balance"] = max(language_counts.values()) - min(language_counts.values()) <= 2
    checks["multilingual_english_cue_removed"] = all(
        not row.get("scenario_cue_en") or row["scenario_cue_en"] not in row["text"]
        for row in rows if row["language"] != "en"
    )
    checks["ood_abstention_metadata"] = all(
        row.get("ood_reason") and row.get("annotation_confidence") == 0.5 and "abstention_recommended" in row["signals"]
        for row in rows if row["label"] == "ambiguous_ood"
    )
    checks["robustness_variants_present"] = set(row["variant_type"] for row in rows if row["label"] == "scam") == {
        "clean", "defanged_url", "zero_width", "fullwidth_punctuation", "spaced_tokens", "mixed_punctuation"
    }
    curated = [json.loads(line) for line in (ROOT / "samples" / "curated_eval_512.jsonl").read_text(encoding="utf-8").splitlines() if line]
    checks["curated_eval_integrity"] = (
        len(curated) == 512
        and all(row["split"] == "test" for row in curated)
        and len({row["id"] for row in curated}) == 512
        and Counter(row["label"] for row in curated) == {"scam": 256, "legitimate": 128, "awareness": 64, "ambiguous_ood": 64}
    )
    checks["all_required_fields"] = all(all(key in row for key in (
        "id", "record_type", "label", "domain", "taxonomy_id", "language", "country", "channel",
        "text", "text_en", "signals", "synthetic", "source_id", "campaign_group_id", "variant_family_id",
        "requested_action", "harm_vector", "severity", "annotation_confidence", "split", "content_sha256"
    )) for row in rows)
    status = "PASS" if all(checks.values()) and not failures else "FAIL"
    report = {
        "status": status, "dataset_version": "1.2.0", "validated_at": "2026-09-23",
        "checks": checks, "failures": failures[:100],
        "counts": {
            "records": len(rows), "labels": Counter(row["label"] for row in rows),
            "domains": Counter(row["domain"] for row in rows), "record_types": Counter(row["record_type"] for row in rows),
            "languages": language_counts, "splits": Counter(row["split"] for row in rows),
        },
        "limitations": [
            "All included records are synthetic and require external validation before performance claims.",
            "Non-English leaf labels require native-speaker review.",
            "External source records are not redistributed in this package.",
            "Campaign isolation prevents generator-family leakage only; it is not a substitute for independent real-world testing.",
        ],
    }
    (ROOT / "quality" / "validation_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = ["# Dataset QA report", "", f"**Status: {status}**", "", f"Records: {len(rows):,}", "", "## Checks", ""]
    summary.extend(f"- {'PASS' if value else 'FAIL'} — {name.replace('_', ' ')}" for name, value in checks.items())
    summary.extend(["", "## Important limitations", ""] + [f"- {item}" for item in report["limitations"]])
    (ROOT / "quality" / "QA_REPORT.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "records": len(rows), "checks_passed": sum(checks.values()), "checks_total": len(checks)}, indent=2))
    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

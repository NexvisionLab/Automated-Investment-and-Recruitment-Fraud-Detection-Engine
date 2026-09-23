#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Create and verify a complete manifest for distributed repository files."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("metadata/release_manifest.json")
OMITTED_SPLITS = {"data/train.jsonl", "data/validation.jsonl", "data/test.jsonl"}
TRANSIENT_SUFFIXES = {".tmp", ".partial", ".bak", ".pyc", ".zip"}


def should_include(path: Path, root: Path = ROOT) -> bool:
    relative = path.relative_to(root)
    if path.is_symlink() or relative.as_posix() in OMITTED_SPLITS:
        return False
    if "__pycache__" in relative.parts:
        return False
    if any(part.startswith(".") and part != ".github" for part in relative.parts):
        return False
    if path.suffix.lower() in TRANSIENT_SUFFIXES:
        return False
    return path.is_file()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path = ROOT, version: str | None = None) -> dict[str, Any]:
    manifest_path = root / MANIFEST_RELATIVE
    files = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path == manifest_path or not should_include(path, root):
            continue
        relative = path.relative_to(root).as_posix()
        files.append({"path": relative, "size_bytes": path.stat().st_size, "sha256": sha256_file(path)})
    if version is None:
        schema = json.loads((root / "schema/record.schema.json").read_text(encoding="utf-8"))
        version = schema["properties"]["version"]["const"]
    release_digest = hashlib.sha256(
        "".join(f"{item['path']}\0{item['size_bytes']}\0{item['sha256']}\n" for item in files).encode()
    ).hexdigest()
    return {
        "dataset_version": version,
        "algorithm": "SHA-256",
        "generated_at": "2026-09-23",
        "file_count": len(files),
        "total_size_bytes": sum(item["size_bytes"] for item in files),
        "release_digest": release_digest,
        "files": files,
    }


def write_manifest(root: Path = ROOT, version: str | None = None) -> dict[str, Any]:
    manifest = build_manifest(root, version)
    path = root / MANIFEST_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(root: Path = ROOT) -> list[str]:
    expected = json.loads((root / MANIFEST_RELATIVE).read_text(encoding="utf-8"))
    actual = build_manifest(root, expected.get("dataset_version"))
    if expected == actual:
        return []
    expected_files = {item["path"]: item for item in expected.get("files", [])}
    actual_files = {item["path"]: item for item in actual.get("files", [])}
    failures = [path for path in sorted(expected_files.keys() | actual_files.keys()) if expected_files.get(path) != actual_files.get(path)]
    return failures or ["manifest_metadata"]


def main() -> None:
    manifest = write_manifest()
    failures = verify_manifest()
    if failures:
        raise SystemExit(f"release manifest verification failed: {failures}")
    print(json.dumps({"status": "PASS", "files": manifest["file_count"], "release_digest": manifest["release_digest"]}))


if __name__ == "__main__":
    main()

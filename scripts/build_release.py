#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Build and verify a deterministic source-and-data release archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from release_manifest import MANIFEST_RELATIVE, verify_manifest, write_manifest


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "NexVision_ScamIntel_Dataset_v1.2.0"
OMITTED_SPLITS = {"data/train.jsonl", "data/validation.jsonl", "data/test.jsonl"}
TRANSIENT_SUFFIXES = {".tmp", ".partial", ".bak", ".pyc", ".zip"}


def should_include(path: Path, root: Path = ROOT) -> bool:
    relative = path.relative_to(root)
    if path.is_symlink():
        return False
    if relative.as_posix() in OMITTED_SPLITS:
        return False
    if "__pycache__" in relative.parts:
        return False
    if any(part.startswith(".") and part != ".github" for part in relative.parts):
        return False
    if path.suffix.lower() in TRANSIENT_SUFFIXES:
        return False
    return path.is_file()


def build(output: Path) -> tuple[str, int]:
    write_manifest(ROOT)
    manifest_failures = verify_manifest(ROOT)
    if manifest_failures:
        raise RuntimeError(f"release manifest verification failed: {manifest_failures}")
    files = sorted((path for path in ROOT.rglob("*") if should_include(path)), key=lambda path: path.relative_to(ROOT).as_posix())
    if not files:
        raise RuntimeError("release would contain no files")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{relative}", date_time=(2026, 9, 23, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    verify(output)
    digest = hashlib.sha256()
    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest(), output.stat().st_size


def verify(output: Path) -> None:
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("release archive contains duplicate entries")
        prohibited = [
            name for name in names
            if ("/." in name and "/.github/" not in name) or "__pycache__" in name or Path(name).suffix.lower() in TRANSIENT_SUFFIXES
            or any(name.endswith(f"/{item}") for item in OMITTED_SPLITS)
        ]
        if prohibited:
            raise RuntimeError(f"release archive contains prohibited entries: {prohibited}")
        required = {
            f"{ARCHIVE_ROOT}/data/records.jsonl",
            f"{ARCHIVE_ROOT}/LICENSE",
            f"{ARCHIVE_ROOT}/README.md",
            f"{ARCHIVE_ROOT}/quality/CODE_AUDIT_REPORT.md",
            f"{ARCHIVE_ROOT}/quality/PRODUCTION_READINESS_REPORT.md",
            f"{ARCHIVE_ROOT}/{MANIFEST_RELATIVE.as_posix()}",
            f"{ARCHIVE_ROOT}/.github/workflows/ci.yml",
        }
        missing = sorted(required.difference(names))
        if missing:
            raise RuntimeError(f"release archive is missing required files: {missing}")
        corrupt = archive.testzip()
        if corrupt:
            raise RuntimeError(f"release archive failed CRC verification at {corrupt}")
        manifest = json.loads(archive.read(f"{ARCHIVE_ROOT}/{MANIFEST_RELATIVE.as_posix()}").decode("utf-8"))
        expected_names = {f"{ARCHIVE_ROOT}/{item['path']}" for item in manifest["files"]}
        expected_names.add(f"{ARCHIVE_ROOT}/{MANIFEST_RELATIVE.as_posix()}")
        if set(names) != expected_names:
            unexpected = sorted(set(names) - expected_names)
            omitted = sorted(expected_names - set(names))
            raise RuntimeError(f"archive/manifest mismatch: unexpected={unexpected}, missing={omitted}")
        for item in manifest["files"]:
            name = f"{ARCHIVE_ROOT}/{item['path']}"
            digest = hashlib.sha256()
            size = 0
            with archive.open(name) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            if size != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                raise RuntimeError(f"archive content does not match manifest: {item['path']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path, default=ROOT.parent / f"{ARCHIVE_ROOT}.zip")
    args = parser.parse_args()
    digest, size = build(args.output.resolve())
    print(f"archive={args.output.resolve()}")
    print(f"size_bytes={size}")
    print(f"sha256={digest}")


if __name__ == "__main__":
    main()

"""Local-only screenshot OCR using the system Tesseract binary."""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

MAX_IMAGE_BYTES = 8_000_000
# Tesseract language codes such as "eng", "chi_sim", or "eng+chi_sim" - nothing that could be a path or an option.
LANGUAGES = re.compile(r"[A-Za-z][A-Za-z_]{1,15}(?:\+[A-Za-z][A-Za-z_]{1,15}){0,3}")


def _decode(data_url: str) -> tuple[bytes, str]:
    if not data_url.startswith("data:image/") or ";base64," not in data_url:
        raise ValueError("Expected a base64 PNG or JPEG data URL")
    header, encoded = data_url.split(",", 1)
    try: raw = base64.b64decode(encoded, validate=True)
    except Exception as exc: raise ValueError("Invalid base64 image") from exc
    if len(raw) > MAX_IMAGE_BYTES: raise ValueError("Image exceeds 8 MB")
    if raw.startswith(b"\x89PNG\r\n\x1a\n"): ext = ".png"
    elif raw.startswith(b"\xff\xd8\xff"): ext = ".jpg"
    else: raise ValueError("Only PNG and JPEG screenshots are accepted")
    return raw, ext


def ocr_data_url(data_url: str, languages: str = "eng") -> dict:
    if not LANGUAGES.fullmatch(languages):
        raise ValueError("Invalid OCR language code")
    binary = shutil.which("tesseract")
    if not binary: return {"available": False, "text": "", "error": "Local Tesseract is not installed"}
    raw, ext = _decode(data_url)
    with tempfile.TemporaryDirectory(prefix="nexvision-ocr-") as directory:
        path = Path(directory) / ("capture" + ext); path.write_bytes(raw)
        proc = subprocess.run([binary, str(path), "stdout", "-l", languages, "--psm", "6"], capture_output=True, timeout=25, check=False)
    text = proc.stdout.decode("utf-8", "replace").strip()
    return {"available": True, "text": text[:100_000], "characters": len(text), "engine": "local-tesseract", "uploaded": False,
            "warning": proc.stderr.decode("utf-8", "replace")[-300:] if proc.returncode else ""}

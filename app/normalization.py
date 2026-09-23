"""Loss-aware normalization for scam-message analysis.

The analyzer keeps the original input for evidence and produces a normalized
view for matching.  Nothing in this module performs network I/O.
"""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, asdict


# High-frequency Greek/Cyrillic homoglyphs used in brand and keyword evasion.
# This deliberately maps only visually close characters; the original text is
# always retained so an investigator can see what was actually supplied.
CONFUSABLES = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
    "у": "y", "У": "Y", "і": "i", "І": "I", "ј": "j", "Ј": "J",
    "һ": "h", "Һ": "H", "ԁ": "d", "ԛ": "q", "ɡ": "g",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X", "α": "a", "ε": "e", "ι": "i", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "y", "χ": "x", "K": "K", "ſ": "s",
})

LEET_WORDS = {
    "p4y": "pay", "p@y": "pay", "tr4nsfer": "transfer", "dep0sit": "deposit",
    "t0pup": "topup", "j0b": "job", "w0rk": "work", "pr0fit": "profit",
    "retrn": "return", "guar4nteed": "guaranteed", "cr7pto": "crypto",
    "wh4tsapp": "whatsapp", "te1egram": "telegram", "c0mmission": "commission",
}


@dataclass(frozen=True)
class NormalizationResult:
    original: str
    normalized: str
    skeleton: str
    transformations: tuple[str, ...]
    suspicious_unicode: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _scripts(text: str) -> set[str]:
    scripts: set[str] = set()
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "ARABIC", "HEBREW", "TAMIL"):
            if script in name:
                scripts.add(script)
                break
    return scripts


def unicode_signals(text: str) -> list[str]:
    findings: list[str] = []
    controls = [c for c in text if unicodedata.category(c) in {"Cf", "Cc"} and c not in "\n\r\t"]
    if controls:
        findings.append(f"Contains {len(controls)} invisible/control character(s)")
    scripts = _scripts(text)
    if "LATIN" in scripts and ({"CYRILLIC", "GREEK"} & scripts):
        findings.append("Mixed Latin and lookalike Greek/Cyrillic scripts")
    if any(ord(c) > 127 and c.translate(CONFUSABLES) != c for c in text):
        findings.append("Contains Unicode lookalike characters")
    return findings


def _collapse_spaced_letters(text: str) -> str:
    # "p a y  n o w" -> "pay now" while avoiding ordinary short initials.
    pat = re.compile(r"(?<!\w)(?:[A-Za-z0-9][ \t]){2,}[A-Za-z0-9](?!\w)")
    return pat.sub(lambda m: re.sub(r"\s+", "", m.group(0)), text)


def normalize_detailed(text: str) -> NormalizationResult:
    original = str(text or "")
    value = original
    changes: list[str] = []
    nfkc = unicodedata.normalize("NFKC", value)
    if nfkc != value:
        changes.append("Unicode compatibility normalization (NFKC)")
        value = nfkc
    stripped = "".join(
        c for c in value
        if not (unicodedata.category(c) in {"Cf", "Cc"} and c not in "\n\r\t")
    )
    if stripped != value:
        changes.append("Invisible/control characters removed")
        value = stripped
    defanged = re.sub(r"(?i)hxxps?\s*:\s*//", lambda m: "https://" if "s" in m.group(0).lower() else "http://", value)
    defanged = re.sub(r"\[\s*\.\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", ".", defanged, flags=re.I)
    defanged = re.sub(r"\[\s*at\s*\]|\(\s*at\s*\)", "@", defanged, flags=re.I)
    if defanged != value:
        changes.append("Defanged URL/email notation restored")
        value = defanged
    skeleton = value.translate(CONFUSABLES)
    if skeleton != value:
        changes.append("Unicode lookalikes mapped for matching")
    collapsed = _collapse_spaced_letters(skeleton)
    if collapsed != skeleton:
        changes.append("Spaced-letter obfuscation collapsed")
    leet = collapsed
    for source, target in LEET_WORDS.items():
        leet = re.sub(rf"(?i)(?<!\w){re.escape(source)}(?!\w)", target, leet)
    if leet != skeleton:
        changes.append("Common leetspeak tokens decoded")
    # Normalize punctuation runs and horizontal whitespace, but preserve lines.
    leet = re.sub(r"[\u2010-\u2015]", "-", leet)
    leet = re.sub(r"[ \t]+", " ", leet)
    leet = re.sub(r"\n{3,}", "\n\n", leet).strip()
    return NormalizationResult(
        original=original,
        normalized=leet,
        skeleton=skeleton,
        transformations=tuple(changes),
        suspicious_unicode=tuple(unicode_signals(original)),
    )


def normalize(text: str) -> str:
    return normalize_detailed(text).normalized


def script_profile(text: str) -> dict:
    scripts = sorted(_scripts(text))
    letters = sum(1 for c in text if c.isalpha())
    recognized = sum(1 for c in text if c.isalpha() and any(s in unicodedata.name(c, "") for s in scripts))
    return {"scripts": scripts, "letter_count": letters, "recognized_ratio": recognized / max(1, letters)}

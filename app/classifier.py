"""Small, transparent, fully local multilingual text classifier.

This is intentionally not a downloaded foundation model. It uses a bundled
seed corpus and character n-gram Naive Bayes so analysis is reproducible and
works without network access or API keys.
"""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache

from normalization import normalize, script_profile


SAFE = [
    "Your interview is scheduled with the hiring manager. No payment is required.",
    "We never ask candidates for money, gift cards, OTPs, or bank passwords.",
    "Salary is paid monthly after work. Apply through our official careers page.",
    "Past performance is not indicative of future results. Capital is at risk.",
    "Returns are not guaranteed and you may lose some or all of your investment.",
    "Please read the prospectus and verify our licence in the regulator register.",
    "The parcel you ordered has shipped to your home address.",
    "Reminder: do not transfer money to anyone claiming to be our recruiter.",
    "This survey pays participants; it does not require a deposit.",
    "Investment values can rise or fall and withdrawal fees are disclosed in the prospectus.",
    "面试不收取任何费用，请通过官方网站申请职位。",
    "投资有风险，回报不受保证，您可能损失本金。",
    "Permohonan kerja ini tidak memerlukan bayaran atau deposit.",
    "Pelaburan mempunyai risiko dan pulangan tidak dijamin.",
    "வேலைக்கு விண்ணப்பிக்க கட்டணம் தேவையில்லை.",
    "முதலீட்டில் ஆபத்து உள்ளது; லாபம் உத்தரவாதம் இல்லை.",
]

SCAM = [
    "Pay a registration fee now to secure this remote job.",
    "Top up your task account to clear the negative balance and withdraw commission.",
    "Receive packages at home, repackage them, and forward them for weekly salary.",
    "Deposit this cheque, buy equipment from our vendor, and send the balance back.",
    "Use your bank account to receive client payments and keep ten percent.",
    "Guaranteed 30 percent weekly return with zero risk. Limited slots today.",
    "Pay the tax and unlock fee before your investment profit can be released.",
    "Download our trading APK from Telegram and enable unknown sources.",
    "Like videos for commission. Complete combo orders by recharging USDT.",
    "Your task mistake froze the account; deposit more to repair it.",
    "Can top up first lah then can withdraw your commission today.",
    "The Telegram group members all posted profit screenshots and successful withdrawals.",
    "充值完成任务，然后支付保证金才能提现佣金。",
    "保证每天收益，零风险，马上转账投资。",
    "Bayar deposit dahulu sebelum mula tugas dan keluarkan komisen.",
    "Pulangan dijamin tanpa risiko, pindah wang hari ini.",
    "வேலை தொடங்க முன்பணம் செலுத்தி கமிஷனை திரும்பப் பெறுங்கள்.",
    "ஆபத்து இல்லை உத்தரவாத லாபம், இன்றே பணம் செலுத்துங்கள்.",
]


def _ngrams(text: str) -> Counter[str]:
    text = re.sub(r"\s+", " ", normalize(text).lower())
    padded = f"  {text}  "
    feats: Counter[str] = Counter()
    for n in (3, 4, 5):
        feats.update(padded[i:i+n] for i in range(max(0, len(padded) - n + 1)))
    for word in re.findall(r"[^\W_]{2,}", text, re.UNICODE):
        feats["w:" + word] += 2
    return feats


@lru_cache(maxsize=1)
def _model():
    counts = {0: Counter(), 1: Counter()}
    totals = {0: 0, 1: 0}
    docs = {0: len(SAFE), 1: len(SCAM)}
    vocab = set()
    for label, rows in ((0, SAFE), (1, SCAM)):
        for row in rows:
            f = _ngrams(row); counts[label].update(f); totals[label] += sum(f.values()); vocab.update(f)
    return counts, totals, docs, len(vocab)


SUPPORTED_SCRIPTS = ("LATIN", "CJK", "TAMIL")


def supported_share(text: str) -> float:
    """Fraction of the letters that are in a script the local model was trained on."""
    letters = supported = 0
    for char in text:
        if not char.isalpha():
            continue
        letters += 1
        name = unicodedata.name(char, "")
        if any(script in name for script in SUPPORTED_SCRIPTS):
            supported += 1
    return supported / letters if letters else 0.0


def predict(text: str, script_text: str | None = None) -> dict:
    """`script_text` is the message as submitted. The scripts must be judged from it, not from `text`:
    the analyzer normalizes Cyrillic/Greek look-alikes into Latin letters to catch obfuscation, which
    turns genuine Russian into Latin-looking text and would otherwise hide that it is unsupported."""
    feats = _ngrams(text)
    counts, totals, docs, vocab = _model()
    scores = {}
    for label in (0, 1):
        score = math.log((docs[label] + 1) / (sum(docs.values()) + 2))
        denom = totals[label] + vocab
        for feat, freq in feats.items():
            score += min(freq, 3) * math.log((counts[label][feat] + 1) / denom)
        scores[label] = score
    delta = max(-30.0, min(30.0, scores[1] - scores[0]))
    raw = 1 / (1 + math.exp(-delta))
    # Conservative temperature scaling fitted to the bundled development seed.
    calibrated = 1 / (1 + math.exp(-delta / 2.4))
    profile = script_profile(script_text if script_text is not None else text)
    supported = supported_share(script_text if script_text is not None else text) >= 0.5
    very_short = len(re.sub(r"\W", "", text, flags=re.UNICODE)) < 12
    uncertain = 0.35 <= calibrated <= 0.65
    abstain = not supported or very_short or (uncertain and len(feats) < 80)
    reasons = []
    if not supported: reasons.append("Writing system is outside the supported local model profile")
    if very_short: reasons.append("Too little text for a stable language-model signal")
    if uncertain and len(feats) < 80: reasons.append("Model score is uncertain and evidence is sparse")
    return {
        "model": "local-char-ngram-nb-v2", "raw_scam_probability": round(raw, 4),
        "calibrated_score": round(calibrated, 4), "abstained": abstain,
        "abstention_reasons": reasons, "script_profile": profile,
        "supported_languages": ["English", "Singlish", "Chinese", "Malay/Indonesian", "Tamil"],
        "calibration_note": "Internal temperature scaling on bundled development examples; not a population fraud probability.",
    }

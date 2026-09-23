# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import base64
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, analyze_conversation, inspect_url
from domain_intel import email_domain_analysis, registrable_domain
from normalization import normalize_detailed
from ocr_local import ocr_data_url
from reporting import html_report, pdf_report
from safehtml import inspect_html
from curated_cases import CASE_COUNT, RISKY_CASES, SAFE_CASES


class CuratedRegressionTests(unittest.TestCase):
    def test_matrix_has_at_least_250_cases(self): self.assertGreaterEqual(CASE_COUNT, 250)

    def test_risky_matrix(self):
        misses = []
        for case_id, expected, text in RISKY_CASES:
            ids = {x["id"] for x in analyze(text)["findings"]}
            if expected not in ids: misses.append((case_id, expected, ids))
        self.assertEqual(misses, [])

    def test_safe_matrix(self):
        false_high = []
        for case_id, text in SAFE_CASES:
            result = analyze(text)
            if result["risk_band"] in {"High", "Critical"}: false_high.append((case_id, result["risk_score"], [x["id"] for x in result["findings"]]))
        self.assertEqual(false_high, [])


class FeatureTests(unittest.TestCase):
    def test_unicode_and_spaced_obfuscation(self):
        result = normalize_detailed("p а y  d e p 0 s i t\u200b now")
        self.assertIn("pay", result.normalized.lower())
        self.assertTrue(result.suspicious_unicode)

    def test_public_suffix(self):
        self.assertEqual(registrable_domain("jobs.example.co.uk")["registrable_domain"], "example.co.uk")
        self.assertEqual(registrable_domain("a.b.example.com.sg")["registrable_domain"], "example.com.sg")

    def test_brand_and_email_mismatch(self):
        self.assertTrue(inspect_url("https://dbs-secure-login.xyz")["brand_findings"])
        self.assertGreater(email_domain_analysis("recruiter@gmail.com", "realcompany.com")["risk_points"], 20)

    def test_conversation_escalation(self):
        result = analyze("Recruiter: Easy product boosting work on Telegram.\nRecruiter: Your first small payout succeeded.\nRecruiter: Top up USDT for the next task.\nRecruiter: Negative balance; pay a fee to unlock withdrawal.")
        self.assertGreaterEqual(len(result["conversation"]["stages"]), 4)
        self.assertGreaterEqual(result["conversation"]["escalation_score"], 20)

    def test_multilingual(self):
        for text in ["充值完成任务，然后支付保证金才能提现佣金。", "Bayar deposit dahulu sebelum mula tugas dan keluarkan komisen.", "வேலை தொடங்க முன்பணம் செலுத்தி கமிஷனை திரும்பப் பெறுங்கள்."]:
            self.assertTrue(analyze(text)["findings"])

    def test_out_of_distribution_abstention(self):
        self.assertTrue(analyze("שלום עולם זה טקסט קצר")["local_classifier"]["abstained"])

    def test_safe_html_static_only(self):
        result = inspect_html("<title>Profit</title><script>alert(1)</script><form><input type=password></form><p>Guaranteed profit with zero risk</p>", "http://example.com")
        self.assertEqual(result["script_tags"], 1); self.assertGreater(result["risk_points"], 20)

    def test_reports(self):
        result = analyze("Pay a fee before you start this job.", source_url="https://example.invalid/job")
        report = html_report(result)
        self.assertIn(b"NexVision OSINT Investigation Report", report)
        self.assertIn(b"Pay a fee before you start this job.", report)
        self.assertIn(b"https://example.invalid/job", report)
        self.assertIn(b"Critical", report)
        self.assertTrue(pdf_report(result).startswith(b"%PDF"))


if __name__ == "__main__": unittest.main()

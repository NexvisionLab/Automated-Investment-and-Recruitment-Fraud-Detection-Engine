# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze, inspect_url, normalize, online_domain_check


class AnalyzerTests(unittest.TestCase):
    def test_task_investment_hybrid_is_critical(self):
        result = analyze("Top up 500 USDT to unlock tasks. Guaranteed 30% daily profit. Pay a fee to release your withdrawal.")
        self.assertEqual(result["verdict"]["level"], "critical")
        ids = {x["id"] for x in result["findings"]}
        self.assertIn("task_deposit", ids)
        self.assertIn("guaranteed_returns", ids)
        self.assertIn("withdrawal_fee", ids)

    def test_reshipping_detected(self):
        result = analyze("Work from home as a package inspector. Receive parcels, repackage them and forward to another address.")
        self.assertGreaterEqual(result["verdict"]["score"], 40)
        self.assertEqual(result["verdict"]["primary_pattern"], "Reshipping scam")

    def test_benign_job_copy_is_not_high(self):
        result = analyze("Software engineer role. Apply through our careers page. Two interviews. No payment is required.")
        self.assertLess(result["verdict"]["score"], 20)

    def test_deobfuscates_urls(self):
        self.assertEqual(normalize("hxxps://evil[.]example"), "https://evil.example")

    def test_url_signals(self):
        result = inspect_url("http://user@example.xyz/login-secure")
        self.assertIn("No HTTPS", result["signals"])
        self.assertIn("Credentials or deceptive @ syntax in URL", result["signals"])

    def test_score_is_bounded(self):
        message = " ".join(["guaranteed risk-free 500% daily return pay crypto now top up task withdrawal fee package inspector receive parcels repackage forward personal bank account receive money"] * 5)
        self.assertEqual(analyze(message)["verdict"]["score"], 100)

    def test_investment_fee_does_not_mislabel_as_job_fee(self):
        result = analyze("Pay USDT now to unlock your investment withdrawal.")
        ids = {x["id"] for x in result["findings"]}
        self.assertNotIn("job_upfront_fee", ids)

    def test_legitimate_risk_disclosure_is_not_flagged(self):
        result = analyze("Investment returns are not guaranteed. All investments carry risk and you may lose money.")
        ids = {x["id"] for x in result["findings"]}
        self.assertNotIn("guaranteed_returns", ids)
        self.assertNotIn("no_risk", ids)
        self.assertEqual(result["verdict"]["level"], "low")

    def test_educational_warning_is_not_a_guarantee(self):
        result = analyze("Warning: there are no guaranteed returns. Verify the firm before investing.")
        self.assertNotIn("guaranteed_returns", {x["id"] for x in result["findings"]})

    def test_single_upfront_job_fee_is_high_risk(self):
        result = analyze("Pay a $99 registration fee before you start work as our remote assistant.")
        self.assertEqual(result["verdict"]["level"], "high")

    def test_fixed_income_term_does_not_trigger_guarantee(self):
        result = analyze("The portfolio includes fixed income securities whose value may fall.")
        self.assertNotIn("guaranteed_returns", {x["id"] for x in result["findings"]})

    def test_unsupported_scripts_abstain_instead_of_reporting_low_risk(self):
        # Regression: normalization maps Cyrillic/Greek look-alikes to Latin, so genuine Russian
        # text looked "Latin", skipped abstention, and a clear scam was banded "Low".
        for text in (
            "Здравствуйте! Работа на дому, оплатите взнос 5000 рублей для начала работы.",
            "Καλημέρα, πληρώστε μια αμοιβή για να ξεκινήσετε την εργασία.",
            "ادفع رسوم التسجيل الآن لبدء العمل",
        ):
            result = analyze(text)
            self.assertEqual(result["risk_band"], "Needs review", text)
            self.assertTrue(result["local_classifier"]["abstained"], text)

    def test_lookalike_letter_evasion_in_english_is_still_analyzed(self):
        # The counterpart: an English scam using a few Cyrillic look-alikes must NOT abstain.
        result = analyze("Earn $500 daily! Pаy a 300 USDT dеposit to unlоck your tаsks.")
        self.assertFalse(result["local_classifier"]["abstained"])
        self.assertEqual(result["risk_band"], "Critical")

    def test_html_inspector_survives_valueless_attributes(self):
        # Regression: <input type> gives the attribute the value None, and the
        # inspector called .lower() on it, so a hostile page could crash its own inspection.
        from safehtml import inspect_html
        page = '<form><input type><input type="PASSWORD"><a href>x</a><img src></form>'
        result = inspect_html(page, "http://login.example.test/")
        self.assertEqual(result["password_fields"], 1)
        self.assertIn("Password form without HTTPS source", result["signals"])

    def test_model_alone_cannot_raise_an_ordinary_message_above_low(self):
        # Regression: the small classifier rates plain delivery and invoice wording as a near-certain scam
        # (calibrated score above 0.99), and with no rule matched that alone put the message at "Elevated".
        for text in (
            "Your parcel from Amazon will arrive tomorrow between 2pm and 6pm. Track at amazon.com/orders.",
            "Please pay the invoice of $450 by bank transfer to the account on the invoice before Friday.",
        ):
            result = analyze(text)
            self.assertEqual(result["findings"], [], text)
            self.assertLessEqual(result["fusion"]["model_component"], 10, text)
            self.assertEqual(result["risk_band"], "Low", text)

    def test_link_evidence_is_not_discarded_when_no_rule_matched(self):
        # Regression: a blanket "no rule matched, cap at 20" threw away a brand look-alike link, so a
        # "verify now" text pointing at dbs-secure-login.xyz was rated Low.
        result = analyze("DBS ALERT: Your account is suspended. Verify now at http://dbs-secure-login.xyz to avoid closure.")
        self.assertEqual(result["findings"], [])
        self.assertGreaterEqual(result["fusion"]["url_component"], 25)
        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertNotEqual(result["risk_band"], "Low")

    def test_rule_matches_still_get_the_full_model_contribution(self):
        result = analyze("Top up 500 USDT to unlock tasks. Guaranteed 30% daily profit. Pay a fee to release your withdrawal.")
        self.assertGreater(result["fusion"]["model_component"], 10)
        self.assertFalse(result["fusion"]["model_uncorroborated"])

    def test_private_address_online_check_is_blocked(self):
        result = online_domain_check("127.0.0.1")
        self.assertTrue(any("non-public" in warning for warning in result["warnings"]))


if __name__ == "__main__":
    unittest.main()

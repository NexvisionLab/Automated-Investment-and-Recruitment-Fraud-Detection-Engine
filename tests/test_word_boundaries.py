# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rules that start with a short word must match that word, not the start of a longer one.

"No action is needed today" matched the urgency rule because "act" sits inside "action"; "I know the risks" matched the
no-risk rule because "no" sits inside "know"; "The second draft was approved" matched the regulator rule because "sec"
sits inside "second". Each ordinary sentence below was rated Elevated before the word boundaries were added.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))

from analyzer import analyze  # noqa: E402


def rules_hit(text):
    return {f["id"] for f in analyze(text, online_checks=False)["findings"]}


ORDINARY = [
    ("pressure", "Microsoft: your Windows 10 support ends next October. See our guide at support.microsoft.com on how to upgrade. No action is needed today."),
    ("pressure", "Your payment is due today. You can pay by GIRO or in the app, no action is needed."),
    ("pressure", "The board acted now on the proposal and will announce the decision at the meeting."),
    ("pressure", "She joined the company now that the team has grown, and can start on Monday."),
    ("no_risk", "I know the risks of this project and I have accepted them for the launch next quarter."),
    ("no_risk", "The council announced a plan to renovate the old market; nobody rejected the risky proposal."),
    ("fake_regulation", "The second draft was approved and licensed for use by the legal team on Tuesday afternoon."),
    ("fake_regulation", "The mass transit licensed operator has been regulated since 2019 according to the city report."),
    ("fake_regulation", "Section 4 of the agreement was approved by the committee, and the minutes are attached."),
]

REAL_SCAM_WORDINGS = [
    ("pressure", "Act now, offer ends today! Limited slots left."),
    ("pressure", "Invest today before the offer closes."),
    ("pressure", "Start investing now and double your money."),
    ("pressure", "Join now, exclusive offer for the first 50 members."),
    ("pressure", "Transfer immediately or lose your place."),
    ("pressure", "Pay within 24 hours to secure your slot."),
    ("no_risk", "Trade with no risk and keep all the profit."),
    ("no_risk", "This is a zero risk strategy for your savings."),
    ("no_risk", "You can trade without any risk at all."),
    ("fake_regulation", "Our fund is MAS approved and fully licensed."),
    ("fake_regulation", "We are SEC regulated and FCA certified."),
    ("fake_regulation", "Licensed by ASIC, so your money is guaranteed."),
]


class WordBoundaryTests(unittest.TestCase):
    def test_ordinary_sentences_do_not_trip_the_rules(self):
        for rule, text in ORDINARY:
            with self.subTest(rule=rule, text=text[:50]):
                self.assertNotIn(rule, rules_hit(text))

    def test_the_real_scam_wordings_still_do(self):
        for rule, text in REAL_SCAM_WORDINGS:
            with self.subTest(rule=rule, text=text[:50]):
                self.assertIn(rule, rules_hit(text))

    def test_an_ordinary_sentence_is_rated_low(self):
        for _, text in ORDINARY:
            with self.subTest(text=text[:50]):
                self.assertEqual(analyze(text, online_checks=False)["risk_band"], "Low")


if __name__ == "__main__":
    unittest.main()

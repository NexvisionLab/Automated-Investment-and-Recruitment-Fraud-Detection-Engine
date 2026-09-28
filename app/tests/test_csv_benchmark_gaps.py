# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scam patterns the engine missed, and genuine messages it wrongly flagged, found by scoring a labelled set of 1,000 job and
investment messages (half the scam templates scored Low; 14% of the genuine ones were flagged) and by a live miss: a grant
scam asking for a "10% commercial co-investment escrow deposit ... prior to federal fund release" scored 4/100.

That labelled set is 40 sentence templates repeated 25 times, so a rule that copies a template's wording would pass it and
help nobody. Every message below is worded differently from the set and is either longer or built differently, so they test
whether the rules describe the scam and not the template."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyzer import analyze

FLAGGED = 25  # the "Elevated" band starts here

SCAMS = [
    # Recruiter asks for a deposit or fee before an offer or contract.
    ("job_recruiter_deposit", "Congratulations, your application has advanced. Our hiring agency requires a refundable S$200 clearance deposit before we can send the employment contract. It is returned with your first salary."),
    ("job_recruiter_deposit", "Thanks for interviewing! Before HR issues the offer letter, the recruitment agency asks candidates to pay a S$150 processing charge. It will be refunded after your probation period."),
    # Told to buy equipment from one named seller.
    ("job_assigned_supplier", "Your onboarding pack is ready. To begin, order the ergonomic workstation set from our approved vendor at the link below, costing S$980; finance will refund you with your first paycheck."),
    ("job_assigned_supplier", "Please purchase the laptop and headset through the designated supplier our IT team uses, and send the receipt for reimbursement."),
    # Identity documents and bank codes.
    ("sensitive_data", "To complete your background screening, submit a photo of both sides of your driver's licence together with the security codes your bank app sent you."),
    # Password phishing dressed as onboarding.
    ("credential_request", "Your HR onboarding portal is ready. Log in with your current email password at the link so we can activate your payroll before Friday."),
    # Wallet approval.
    ("wallet_approval", "Join our Web3 QA testing team. Connect your crypto wallet to our test dApp and approve the token allowance so we can simulate transactions; you will receive S$300 per session."),
    ("wallet_approval", "Sync your MetaMask wallet with our sandbox and give unlimited spending permission, testers earn S$500 weekly."),
    # Payment redirected to a new account.
    ("payment_instruction_change", "Notice from your wealth manager: we have changed our custodian and the fund subscription must now go to a different bank account. Please disregard the details on your earlier invoice and pay S$5,000 using the new instructions attached."),
    # Pre-listing access sold to a private person.
    ("insider_allocation_payment", "Our private trading circle gets pre-IPO shares before the public. Send S$3,000 to our allocation manager's personal account by Monday to lock in the discounted price, and keep this within the group."),
    # An official body said to want money.
    ("regulator_payment_demand", "The financial authority has approved your investment application, however you are required to transfer S$2,000 to the clearance department before we can proceed."),
    # Recovery of lost money for a fee.
    ("recovery_fee", "We are a licensed asset recovery agency and have located the S$12,000 you lost to an online trading site. To release it to you, pay our S$250 legal fee upfront."),
    # Pump and dump.
    ("pump_group", "Our crypto signals group is about to pump a low-cap coin. Buy S$500 worth of the coin before 3pm and hold until the admins call the sell signal, members are guaranteed 30% out."),
    # Documents held back until payment.
    ("pay_before_disclosure", "Allocation is nearly gone. We can share the audited accounts and prospectus only once your S$3,000 subscription payment has cleared."),
    # Fee before withdrawal, worded three ways.
    ("withdrawal_fee", "Your profits of S$8,400 are ready. Our compliance department levies a 15% anti-money-laundering charge that must be paid before we can process your withdrawal."),
    ("withdrawal_fee", "The balance can be withdrawn, but a separate S$300 tax payment is due first. It cannot be deducted from the balance."),
    # A promised return with no risk attached.
    ("guaranteed_returns", "We promise you a 9% return each quarter, regardless of what markets do. Send the S$2,000 subscription today."),
    # Grants, funds, loans, inheritances that must be paid for first (the live miss, in its own words and in others).
    ("grant_release_fee", "Your organisation has been approved for a federal development grant of $250,000. To proceed, we require a 10% commercial co-investment escrow deposit from an authorized industrial partner or approved sponsor prior to federal fund release."),
    ("grant_release_fee", "Congratulations, your small-business relief award is ready. Before the funds can be released you must pay a $1,200 insurance and processing fee to our clearing agent."),
    ("grant_release_fee", "Your inheritance of 400,000 pounds is held by the estate trustee. Disbursement of the funds requires a refundable legal deposit of 900 pounds paid to our solicitor."),
    ("grant_release_fee", "Your loan has been approved. An escrow deposit of 5% must be paid before disbursement of the loan."),
]

GENUINE = [
    "Our grant programme requires applicants to provide a 10% matching contribution from their own funds. Awards are paid in three instalments after each milestone report is approved by the review panel.",
    "Your application for the community grant has been shortlisted. No fee is charged at any stage; funds are released to your organisation's bank account after the signed agreement.",
    "The council will release the grant funds once the completed compliance form is returned. There is no cost to applicants.",
    "Reminder: our bank details have not changed. If anyone tells you we have moved to a new account, do not pay; call us on the number printed on your last statement.",
    "We have shipped your company laptop by courier. Please sign for it and keep the packaging; nothing needs to be bought or paid by you.",
    "Your offer letter has been issued. Fees for the background check are paid by us, and you will not be asked to pay any deposit.",
    "Scam awareness: fraudsters may pose as recruiters and ask you to pay a deposit before issuing an offer letter. Real employers never do.",
    "Your statement shows a 12% annualised return over the last 12 months. Past performance is not a reliable guide.",
    "Interview confirmed for Tuesday 10am. Please bring your NRIC to reception for the visitor pass; we will not ask for any banking details.",
    "Payroll is processed on the 25th. To update your bank details, please log in to the HR system through the intranet yourself; HR will never ask for your password.",
    "The fund's audited accounts and prospectus are available on our website. You can read them before deciding whether to subscribe.",
    "Your crypto wallet provider has updated its app. Never approve an unlimited token allowance for a site you do not trust.",
    "We recruit through our careers page only. Our recruiter will never ask for payment, and the S$80 medical check is billed to the company.",
    "HR needs you to complete the tax form before your first payroll.",
    "Our recovery team has restored access to your account. You do not need to pay anything.",
    "Trading note: the token is thinly traded, so spreads are wide. This is not advice, and you should not buy it without reading the risks.",
    # Messages that quote scam wording in order to warn about it, in the shape the labelled set uses.
    "This guide explains how tax may affect returns; it does not ask you to pay a fee to unlock withdrawals or send money to a new account.",
    "A message promising 12% monthly returns and asking for S$850 up front may be a scam. Verify any firm independently before sending funds.",
    "The employee receives wages and never receives customer funds, whatever a recruiter may tell you.",
]


class CsvBenchmarkGapTests(unittest.TestCase):
    def test_each_scam_is_flagged_by_the_intended_rule(self):
        for rule_id, text in SCAMS:
            with self.subTest(rule=rule_id, text=text[:60]):
                result = analyze(text, online_checks=False)
                self.assertIn(rule_id, {f["id"] for f in result["findings"]})
                self.assertGreaterEqual(result["risk_score"], FLAGGED)

    def test_genuine_messages_are_not_flagged(self):
        for text in GENUINE:
            with self.subTest(text=text[:60]):
                result = analyze(text, online_checks=False)
                self.assertLess(result["risk_score"], FLAGGED, [f["id"] for f in result["findings"]])

    def test_the_grant_scam_that_scored_four_now_names_the_advance_fee(self):
        result = analyze("Your organisation has been approved for a federal development grant of $250,000. To proceed, we require a 10% commercial co-investment escrow deposit from an authorized industrial partner or approved sponsor prior to federal fund release.", online_checks=False)
        self.assertEqual(result["findings"][0]["id"], "grant_release_fee")
        self.assertNotEqual(result["risk_band"], "Low")

    def test_the_word_check_in_background_check_is_not_a_cheque(self):
        # fake_cheque matched "check" anywhere, so an ordinary offer letter that mentions a background check scored 41.
        for text in (
            "Your offer letter has been issued. The background check is arranged by us and there is no deposit for you to pay.",
            "We will run a credit check and a reference check before the start date; please buy nothing in advance.",
        ):
            with self.subTest(text=text[:50]):
                self.assertNotIn("fake_cheque", {f["id"] for f in analyze(text, online_checks=False)["findings"]})
        # ...while a real fake-cheque job is still caught.
        self.assertIn("fake_cheque", {f["id"] for f in analyze("We will send you a cheque; deposit it, then buy the equipment from our vendor and wire back the balance.", online_checks=False)["findings"]})

    def test_a_scam_sentence_is_not_mistaken_for_a_warning(self):
        # "do not delay" is not a warning against paying; only a negation of the risky action counts.
        result = analyze("Do not delay the escrow deposit: it is required before the federal grant release and the offer expires today.", online_checks=False)
        self.assertIn("grant_release_fee", {f["id"] for f in result["findings"]})


if __name__ == "__main__":
    unittest.main()

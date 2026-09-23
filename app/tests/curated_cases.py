"""Deterministic, human-reviewed regression matrix.

Each base case expresses one intended semantic. Six context-preserving variants
exercise casing and surrounding conversational material without changing the
label. This yields 270 curated cases (25 risky x 6 + 20 safe x 6).
"""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
RISKY_BASES = [
    ("job_upfront_fee", "Pay a registration fee before you start work as our remote assistant."),
    ("task_deposit", "Top up your account to unlock the next product task and commission."),
    ("social_boosting", "Like and review products to earn daily commission."),
    ("negative_balance", "Your task balance is negative; top up now to continue."),
    ("task_mistake", "You made a wrong task submission; deposit money to reset it."),
    ("account_upgrade", "Upgrade your VIP account by paying a deposit."),
    ("fake_shop_funding", "Fund customer orders for your new virtual shop."),
    ("physical_cash", "Hand over the cash to our courier at the meeting point."),
    ("small_payout", "Your first small commission payment was successful so trust us."),
    ("group_testimonials", "Telegram group members are posting profit screenshots."),
    ("celebrity_endorsement", "This crypto platform is endorsed by a famous celebrity."),
    ("sideload_app", "Download our trading APK outside the app store and enable unknown sources."),
    ("reshipping", "Work as a package inspector: receive parcels, repackage and forward them."),
    ("money_mule", "Use your personal bank account to receive client money and transfer it onward."),
    ("fake_cheque", "Deposit our cheque, buy a laptop from our vendor and return the balance."),
    ("sensitive_data", "Send your Singpass login and OTP to complete onboarding."),
    ("chat_recruitment", "Contact our recruiter on WhatsApp for this job."),
    ("no_interview", "Immediate hire with no need for an interview."),
    ("guaranteed_returns", "Guaranteed 30 percent weekly investment return."),
    ("no_risk", "Our investment is risk-free and you cannot lose."),
    ("unrealistic_return", "Earn 500% profit daily with this trading strategy."),
    ("withdrawal_fee", "Pay the verification fee before your withdrawal can be released."),
    ("pressure", "Invest now; limited slots and this is your last chance."),
    ("unusual_payment", "Send the investment in USDT to our crypto wallet."),
    ("referral_income", "Invite friends and earn referral commission from every member."),
]

SAFE_BASES = [
    "Apply through our official careers page. No candidate payment is required.",
    "Your technical interview is scheduled for Tuesday with two team members.",
    "We never ask applicants to send money, gift cards, or passwords.",
    "Salary is paid after work under the signed employment contract.",
    "This survey pays participants and does not require a deposit.",
    "The parcel you purchased has shipped to your own delivery address.",
    "Returns are not guaranteed and you may lose all invested capital.",
    "All investments carry risk; read the regulated prospectus carefully.",
    "Past performance is not indicative of future results.",
    "Verify our licence independently in the regulator's official register.",
    "The portfolio holds fixed income securities whose value may fall.",
    "Do not install applications sent by strangers through chat messages.",
    "Never share an OTP, bank password, seed phrase, or private key.",
    "Warning: scammers may demand a fee before releasing a withdrawal.",
    "A legitimate recruiter will not ask you to top up a task account.",
    "We reimburse approved travel expenses through payroll after your visit.",
    "You can cancel the interview at any time without any charge.",
    "面试不收取任何费用，请通过官方网站申请职位。",
    "Pelaburan mempunyai risiko dan pulangan tidak dijamin.",
    "முதலீட்டில் ஆபத்து உள்ளது; லாபம் உத்தரவாதம் இல்லை.",
]


def variants(text):
    return [text, text.upper(), "Hello. " + text, text + " Thank you.", "Sender: " + text, "[10:30] Agent: " + text]


RISKY_CASES = [(f"risk-{i}-{j}", rule, value) for i, (rule, text) in enumerate(RISKY_BASES) for j, value in enumerate(variants(text))]
SAFE_CASES = [(f"safe-{i}-{j}", value) for i, text in enumerate(SAFE_BASES) for j, value in enumerate(variants(text))]
CASE_COUNT = len(RISKY_CASES) + len(SAFE_CASES)

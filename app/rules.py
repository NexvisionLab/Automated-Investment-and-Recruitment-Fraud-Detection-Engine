# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    severity: str
    weight: int
    pattern: str
    explanation: str
    action: str


A_JOB = "Stop contact and payments. Verify the role through the employer's independently located careers page and switchboard."
A_PAY = "Do not send more money. Contact your bank or exchange immediately if a transfer has occurred."
A_INV = "Pause and verify the exact entity and representative in the regulator's official register before investing."

RULES: tuple[Rule, ...] = (
    Rule("job_upfront_fee", "Advance-fee job scam", "Payment required to obtain or start work", "critical", 38,
         r"(?:pay|transfer|deposit|top[ -]?up|fee|purchase).{0,55}(?:before (?:you )?(?:start|work)|to (?:start|join|secure).{0,16}(?:job|role|position|work)|to (?:unlock|activate).{0,18}(?:job|task|account)|registration|training|onboarding|starter kit|background check)|(?:registration|training|onboarding|activation|processing) fee", "Genuine employers should not require a candidate to fund access to a job.", A_JOB),
    Rule("task_deposit", "Paid-task scam", "Deposit or top-up tied to tasks or commissions", "critical", 40,
         r"(?:deposit|top[ -]?up|recharge|prepay|advance|fund).{0,60}(?:task|order|mission|commission|withdraw|negative balance|merchant)|(?:task|order|mission|merchant).{0,60}(?:deposit|top[ -]?up|recharge|prepay|advance|fund)", "Task scams show fictitious earnings and demand escalating deposits.", A_PAY),
    Rule("social_boosting", "Paid-task scam", "Social-media or ecommerce boosting task", "high", 22,
         r"(?:like|rate|review|boost|optimi[sz]e|click|subscribe|follow).{0,35}(?:video|product|app|hotel|merchant|order|listing|tiktok|youtube|instagram).{0,55}(?:earn|commission|income|paid|salary)|(?:earn|commission).{0,40}(?:simple|easy|daily).{0,30}task", "Unsolicited commissions for simple online actions are a common scam lure.", A_JOB),
    Rule("negative_balance", "Paid-task scam", "Task balance becomes negative", "critical", 38,
         r"(?:negative|minus|insufficient).{0,25}(?:balance|wallet|account)|(?:balance|wallet|account).{0,25}(?:negative|minus).{0,40}(?:top[ -]?up|recharge|restore|continue)", "A fabricated negative balance creates pressure to add more money.", A_PAY),
    Rule("task_mistake", "Paid-task scam", "Payment demanded to correct a task mistake", "critical", 34,
         r"(?:wrong|mistake|error|incorrect).{0,35}(?:task|order|submission).{0,45}(?:pay|deposit|top[ -]?up|repair|rectify|reset)|(?:pay|deposit).{0,35}(?:correct|fix|reset).{0,25}(?:task|order)", "Scammers invent task mistakes to justify another payment.", A_PAY),
    Rule("account_upgrade", "Paid-task scam", "Account or tier upgrade required", "critical", 34,
         r"(?:upgrade|activate|unlock|increase).{0,30}(?:account|level|tier|vip|withdrawal limit).{0,45}(?:pay|deposit|top[ -]?up|fee)|(?:pay|deposit).{0,35}(?:upgrade|vip|higher tier)|\b(?:pay|deposit|top[ -]?up)\b[^.!?\n]{0,40}\bto (?:activate|unlock)\b[^.!?\n]{0,25}(?:account|membership|package|profile)", "A paid upgrade is often another advance-fee stage.", A_PAY),
    Rule("fake_shop_funding", "Paid-task scam", "Asked to fund orders for a fake online shop", "critical", 38,
         r"(?:online|e-?commerce|virtual).{0,20}(?:shop|store|business).{0,65}(?:fund|capital|purchase|advance|order)|(?:fund|advance|purchase).{0,45}(?:customer|merchant).{0,20}orders?", "Fake online shops can require victims to advance their own money for invented orders.", A_PAY),
    Rule("physical_cash", "Money movement scam", "Asked to hand over or collect physical cash", "critical", 42,
         r"(?:hand over|collect|deliver|carry|pass).{0,35}(?:cash|money|notes).{0,45}(?:agent|courier|representative|person|location)|(?:cash).{0,25}(?:handover|collection|courier)", "Physical cash collection is designed to bypass normal safeguards and traceability.", A_PAY),
    Rule("small_payout", "Confidence-building", "Small initial payout used to build trust", "high", 23,
         r"(?:small|first|initial).{0,25}(?:payment|payout|commission|profit|withdrawal).{0,45}(?:received|credited|successful|build|prove|trust)|(?:paid|credited).{0,30}(?:s?\$?\d{1,3}|a small amount).{0,40}(?:first|initial|test)", "Fraud rings may allow a small early withdrawal before escalating deposits.", A_PAY),
    Rule("group_testimonials", "Social proof manipulation", "Chat-group testimonials or profit screenshots", "high", 20,
         r"(?:whatsapp|telegram|chat).{0,25}(?:group|channel).{0,55}(?:testimonial|success|profit|earning|screenshot|members? (?:made|earned))|(?:members?|investors?).{0,35}(?:posting|showing|share).{0,30}(?:profit|payout|withdrawal) screenshots?", "Group members and screenshots may be fabricated to simulate social proof.", A_INV),
    Rule("celebrity_endorsement", "Investment impersonation", "Celebrity, politician or public figure endorsement", "high", 22,
         r"(?:endorsed|backed|recommended|approved|promoted).{0,35}(?:celebrity|minister|prime minister|president|politician|elon musk|public figure)|(?:celebrity|minister|politician|public figure).{0,35}(?:investment|crypto|platform|scheme)", "Endorsements can be fabricated or deepfaked and are not proof of legitimacy.", A_INV),
    Rule("sideload_app", "Malicious app delivery", "Asked to install an APK or off-store trading app", "critical", 44,
         r"(?:install|download|open).{0,35}(?:apk|android package|configuration profile|trading app).{0,45}(?:link|whatsapp|telegram|outside|not (?:on|in)).{0,25}(?:store|play|app)|(?:enable|allow).{0,25}(?:unknown sources|install unknown apps)", "Off-store apps can steal credentials, messages and banking access.", "Do not install it. Remove device permissions and contact your bank if you opened it."),
    Rule("reshipping", "Reshipping scam", "Asked to receive, repackage or forward parcels", "critical", 44,
         r"(?:receive|accept).{0,35}(?:parcel|package|shipment|goods).{0,70}(?:reship|re-ship|forward|send|new address|overseas address|(?:post|mail|ship) (?:it |them |these )?(?:on )?to)|(?:repack|repackage|shipping agent|package inspector|parcel agent|quality control manager)|\bre-?label\w*\b.{0,60}(?:parcel|package|goods|shipment)|(?:parcel|package|goods|shipment)s?\b.{0,60}\bre-?label", "Reshipping jobs can make a victim an intermediary for stolen goods.", A_JOB),
    Rule("money_mule", "Money-mule recruitment", "Personal account requested to receive or move funds", "critical", 46,
         r"(?:your|personal|own).{0,25}(?:bank|payment|crypto|wallet) account.{0,75}(?:receive|collect|transfer|forward|process)|(?:receive|collect).{0,40}(?:funds|money|payments).{0,55}(?:send|transfer|forward|keep a percentage)", "Moving third-party funds may facilitate fraud or money laundering.", A_PAY),
    Rule("fake_cheque", "Fake-cheque job scam", "Cheque supplied for equipment or onward payment", "critical", 40,
         r"(?:cheque|check).{0,60}(?:equipment|supplies|vendor|deposit|buy|purchase)|(?:buy|purchase).{0,35}(?:laptop|equipment|supplies).{0,45}(?:cheque|check|reimburse)|(?:overpayment|overpaid).{0,35}(?:refund|send back|return)", "A cheque may appear available before being reversed, leaving the recipient liable.", A_PAY),
    Rule("sensitive_data", "Identity harvesting", "Sensitive identity, authentication or banking data requested", "critical", 35,
         r"\b(?:send|share|provide|upload|tell)\b[^.!?\n]{0,35}(?:singpass|passport|nric|social security|bank login|bank statement|one[ -]?time password|otp|seed phrase|private key|screen sharing|anydesk)", "Early requests for secrets or identity documents can enable takeover and identity theft.", "Do not share the data or code. Contact the organization through an independently verified channel."),
    Rule("chat_recruitment", "Recruitment impersonation", "Recruitment moved immediately to a chat app", "medium", 10,
         r"(?:contact|message|chat|interview|reply).{0,25}(?:whatsapp|telegram|signal)|(?:whatsapp|telegram).{0,40}(?:recruiter|hiring|job|work)", "Chat-only hiring is common in unsolicited job scams.", A_JOB),
    Rule("no_interview", "Recruitment impersonation", "Immediate hire without a normal interview", "high", 16,
         r"(?:hired|selected|job offer|offer letter).{0,45}(?:without|no need|skip).{0,20}(?:interview|application)|(?:immediate hire|guaranteed job|instant employment)", "An unexplained offer without selection checks is inconsistent with normal hiring.", A_JOB),
    Rule("guaranteed_returns", "Investment scam", "Guaranteed or certain investment returns", "critical", 39,
         r"(?:guaranteed|assured|certain).{0,35}(?:return|profit|yield|income|roi)|fixed.{0,18}(?:return|profit|yield|roi)|(?:return|profit|yield|roi).{0,30}(?:guaranteed|assured|risk[ -]?free)", "All investments carry risk; certainty claims are a classic warning.", A_INV),
    Rule("no_risk", "Investment scam", "Claims of no risk or no possibility of loss", "high", 28,
         r"(?:no|zero|without|little).{0,12}risk|risk[ -]?free|can(?:not|'t| never) lose|capital (?:fully )?protected", "Risk-elimination claims may materially misrepresent an offer.", A_INV),
    Rule("unrealistic_return", "Investment scam", "Extreme short-term return claimed", "critical", 34,
         r"(?:earn|make|profit|return|roi|yield|double).{0,35}(?:\d{2,4}\s*%|\$\s*\d{3,}|s\$\s*\d{3,}).{0,35}(?:day|daily|week|weekly|hour|overnight)|(?:\d{2,4}\s*%).{0,25}(?:return|profit|roi|daily|weekly)|double your (?:money|capital).{0,25}(?:day|week|month)|\b(?:turn(?:ed|s)?|grew|grow(?:s)?|flipped|made)\s+(?:s?\$\s*)?\d[\d,]{2,}\s+into\s+(?:s?\$\s*)?\d[\d,]{3,}", "Extreme short-term returns conflict with ordinary risk-return relationships.", A_INV),
    Rule("withdrawal_fee", "Advance-fee investment scam", "More money demanded to release a withdrawal", "critical", 42,
         r"(?:pay|deposit|transfer|settle).{0,45}(?:tax|fee|margin|verification|unlock|release|security deposit).{0,45}(?:withdraw|withdrawal|funds|profit|balance)|(?:withdraw|release).{0,35}(?:after|once).{0,25}(?:fee|tax|deposit|top[ -]?up)", "Fraudulent platforms invent fees and taxes before a supposed release.", A_PAY),
    Rule("pressure", "High-pressure solicitation", "Urgency or scarcity blocks due diligence", "medium", 13,
         r"(?:act|invest|join|pay|transfer|reply).{0,18}(?:now|today|immediately|within \d+ (?:minutes?|hours?))|(?:limited|exclusive).{0,18}(?:slots?|time|offer)|last chance|don't miss out|do not tell (?:anyone|your bank|family)", "Urgency and secrecy can suppress independent checking.", "Pause and verify every claim through a source not supplied by the sender."),
    Rule("unusual_payment", "Suspicious payment request", "Payment through hard-to-recover channels", "high", 25,
         r"(?:pay|send|transfer|deposit|invest).{0,45}(?:crypto|bitcoin|btc|usdt|gift card|voucher|wire transfer|personal account|paynow)|(?:wallet address|gift card code|crypto wallet)", "These payment methods can be difficult to reverse and may hide the beneficiary.", A_PAY),
    Rule("secret_strategy", "Investment scam", "Secret, insider or proven system claimed", "high", 19,
         r"(?:secret|proven|exclusive|insider|ai[- ]powered).{0,30}(?:method|system|strategy|signal|algorithm)|inside information|can't reveal.{0,20}(?:strategy|method)", "Secrecy substitutes a story for independently verifiable disclosure.", A_INV),
    Rule("referral_income", "Ponzi/pyramid indicator", "Rewards depend on recruiting others", "high", 24,
         r"(?:recruit|refer|invite|bring).{0,35}(?:friend|family|people|member|investor).{0,40}(?:bonus|commission|profit|reward|tier)|(?:referral|downline).{0,30}(?:bonus|income|commission)", "Recruitment-dependent rewards may indicate a pyramid or Ponzi structure.", A_INV),
    Rule("fake_regulation", "Regulatory impersonation", "Regulatory approval asserted in a pitch", "high", 18,
         r"(?:mas|sec|fca|asic).{0,22}(?:approved|licensed|regulated|certified|guaranteed)|(?:government|regulator).{0,20}(?:approved|backed|certified)", "Licence claims must be checked against the regulator's own exact listing.", A_INV),
    Rule("romance_grooming", "Relationship investment scam", "Online relationship steers toward investment", "high", 20,
         r"(?:met|match|friend|relationship|dating).{0,45}(?:crypto|investment|trading|platform)|(?:friend|partner|uncle|mentor).{0,35}(?:teach|show|introduce).{0,25}(?:trade|invest|crypto)", "Fraudsters may build trust over time before introducing a fake investment.", A_INV),
    Rule("fake_dashboard", "Investment scam", "Dashboard or screenshots presented as proof", "high", 20,
         r"(?:dashboard|account|platform|app).{0,40}(?:shows?|display|balance|profit).{0,35}(?:profit|return|earnings|withdrawal)|(?:profit|balance).{0,25}(?:screenshot|screen capture)", "A displayed balance is not evidence that assets exist or can be withdrawn.", A_INV),
    Rule("survey_deposit", "Paid-task scam", "Survey or questionnaire requires a deposit", "critical", 34,
         r"(?:survey|questionnaire|market research).{0,55}(?:deposit|top[ -]?up|recharge|prepay|unlock)|(?:deposit|top[ -]?up).{0,45}(?:survey|questionnaire)", "Legitimate survey work should not require the participant to fund it.", A_PAY),
    # Multilingual high-confidence anchors (English/Singlish, Chinese, Malay/Indonesian, Tamil).
    Rule("singlish_payment", "Advance-fee scam", "Singlish payment pressure", "critical", 34,
         r"(?:can|must|need) (?:lah |leh )?(?:pay|transfer|top ?up).{0,45}(?:first|now|today)|top ?up first (?:then|den) can", "Local conversational phrasing can still contain a clear advance-fee demand.", A_PAY),
    Rule("zh_task_payment", "Paid-task scam", "Chinese-language task deposit demand", "critical", 40,
         r"(?:充值|垫付|入金|转账).{0,20}(?:任务|订单|佣金|提现|解冻)|(?:任务|订单|提现).{0,20}(?:充值|垫付|解冻|保证金)", "This wording links a payment or deposit to tasks or withdrawal.", A_PAY),
    Rule("zh_guarantee", "Investment scam", "Chinese-language guaranteed return claim", "critical", 38,
         r"(?:保证|稳赚|零风险|保本).{0,18}(?:收益|回报|盈利|投资)|(?:收益|回报).{0,15}(?:保证|稳赚)", "Guaranteeing investment profit or zero risk is a major warning.", A_INV),
    Rule("ms_payment", "Advance-fee scam", "Malay/Indonesian payment-before-work demand", "critical", 38,
         r"(?:bayar|deposit|top ?up|pindah wang).{0,40}(?:dulu|sebelum).{0,25}(?:kerja|tugas|komisen|pengeluaran)|(?:tugas|kerja).{0,35}(?:deposit|bayar dahulu)", "The message requires funding before work or withdrawal.", A_PAY),
    Rule("ta_payment", "Advance-fee scam", "Tamil-language deposit or guaranteed-return demand", "critical", 38,
         r"(?:முன்பணம்|டெபாசிட்|பணம் செலுத்த).{0,30}(?:வேலை|பணி|கமிஷன்|திரும்பப் பெற)|(?:உத்தரவாத|ஆபத்து இல்லை).{0,20}(?:லாபம்|வருமானம்)", "The message contains an advance payment or guaranteed-profit formulation.", A_PAY),
)

RULES_VERSION = "2026.09-SPF-FTC-MAS"

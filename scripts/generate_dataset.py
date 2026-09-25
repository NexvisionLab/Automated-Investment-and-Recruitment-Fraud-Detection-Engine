#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Generate the NexVision job and investment scam research dataset.

All message content is synthetic, deterministic, privacy-safe, and uses reserved
domains or explicit placeholders. The generator never contacts a network API.
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

from language_seed import LANGUAGE_NAMES, PHRASES


VERSION = "1.2.0"
SEED = 20260923
CREATED_AT = "2026-09-23"
ROOT = Path(__file__).resolve().parents[1]

LANGUAGES = tuple(LANGUAGE_NAMES)
COUNTRIES = {
    "en": ("SG", "US", "GB", "AU", "CA", "NZ", "IN", "AE"),
    "zh": ("SG", "CN", "HK", "TW", "MY"), "ms": ("SG", "MY", "BN"),
    "ta": ("SG", "IN", "LK", "MY"), "id": ("ID", "SG", "MY"),
    "es": ("ES", "MX", "AR", "CO", "US"), "pt": ("BR", "PT"),
    "fr": ("FR", "CA", "BE", "CH"), "de": ("DE", "AT", "CH"),
    "hi": ("IN", "SG", "AE"), "bn": ("BD", "IN"), "ur": ("PK", "IN", "AE"),
    "ar": ("AE", "SA", "EG", "JO"), "ja": ("JP",), "ko": ("KR",),
    "th": ("TH",), "vi": ("VN",), "tl": ("PH", "SG"), "ru": ("RU", "KZ"),
}
CURRENCY = {
    "SG": "SGD", "US": "USD", "GB": "GBP", "AU": "AUD", "CA": "CAD",
    "NZ": "NZD", "IN": "INR", "AE": "AED", "CN": "CNY", "HK": "HKD",
    "TW": "TWD", "MY": "MYR", "BN": "BND", "LK": "LKR", "ID": "IDR",
    "ES": "EUR", "MX": "MXN", "AR": "ARS", "CO": "COP", "BR": "BRL",
    "PT": "EUR", "FR": "EUR", "BE": "EUR", "CH": "CHF", "DE": "EUR",
    "AT": "EUR", "BD": "BDT", "PK": "PKR", "SA": "SAR", "EG": "EGP",
    "JO": "JOD", "JP": "JPY", "KR": "KRW", "TH": "THB", "VN": "VND",
    "PH": "PHP", "RU": "RUB", "KZ": "KZT",
}
CHANNELS = ("sms", "whatsapp", "telegram", "email", "social_media_dm", "job_board", "chat_group")
DEADLINES = ("15 minutes", "30 minutes", "one hour", "today", "before 6 PM", "within 24 hours")
PAYMENT_METHODS = ("bank_transfer", "crypto", "gift_card", "cash_deposit", "e_wallet", "none")
FICTIONAL_JOB_BRANDS = (
    "Example Northstar Careers", "Example Meridian Talent", "Example Cedarline Staffing",
    "Example Bluehaven Recruitment", "Example Atlas Remote Work", "Example Harbour Jobs",
)
FICTIONAL_INVESTMENT_BRANDS = (
    "Example Meridian Capital", "Example CedarPeak Trading", "Example Northstar Crypto",
    "Example Harbour Wealth", "Example Atlas Quant", "Example Bluehaven Markets",
)
ROLES = ("data entry assistant", "product reviewer", "remote coordinator", "mystery shopper", "payment assistant", "warehouse coordinator")
ASSETS = ("cryptocurrency", "forex", "gold", "pre-IPO shares", "real estate units", "automated trading")
AMOUNTS = (49, 75, 99, 120, 250, 399, 500, 750, 1000, 1500, 2500, 5000)

VARIANT_TYPES = ("clean", "defanged_url", "zero_width", "fullwidth_punctuation", "spaced_tokens", "mixed_punctuation")
ACTION_BY_MECHANISM = {
    "impersonation": "move_off_platform", "fake_offer": "submit_application", "task_deposit": "pay_deposit",
    "upfront_fee": "pay_fee", "fake_check": "return_funds", "reshipping": "reship_goods",
    "money_mule": "forward_funds", "credential": "share_sensitive_data", "malware": "install_software",
    "trafficking": "travel_or_surrender_documents", "grooming": "invest_funds", "social_proof": "invest_funds",
    "fake_platform": "deposit_or_pay_withdrawal_fee", "guaranteed_return": "invest_funds",
    "recruitment": "pay_and_recruit", "market_manipulation": "buy_asset", "scarcity": "reserve_allocation",
    "affinity": "invest_funds", "fake_asset": "pay_deposit", "recovery": "pay_recovery_fee",
}
HARM_BY_ACTION = {
    "move_off_platform": "social_engineering", "submit_application": "identity_or_fee_exposure",
    "pay_deposit": "financial_loss", "pay_fee": "financial_loss", "return_funds": "financial_loss",
    "reship_goods": "criminal_facilitation", "forward_funds": "money_laundering_exposure",
    "share_sensitive_data": "identity_theft", "install_software": "device_compromise",
    "travel_or_surrender_documents": "physical_safety_and_exploitation", "invest_funds": "investment_loss",
    "deposit_or_pay_withdrawal_fee": "investment_loss", "pay_and_recruit": "financial_and_social_harm",
    "buy_asset": "market_manipulation_loss", "reserve_allocation": "investment_loss",
    "pay_recovery_fee": "repeat_victimisation",
}


def tax(tid: str, domain: str, name: str, definition: str, mechanism: str,
        signals: list[str], stages: list[str]) -> dict[str, Any]:
    return {"id": tid, "domain": domain, "name": name, "definition": definition,
            "mechanism": mechanism, "signals": signals, "lifecycle_stages": stages}


TAXONOMY = [
    tax("J01", "job", "Recruiter impersonation", "Impersonates a recruiter or employer to obtain money, data, or access.", "impersonation", ["unsolicited_contact", "brand_impersonation", "off_platform"], ["contact", "trust_building"]),
    tax("J02", "job", "Fake job advertisement", "Advertises a role that does not exist or materially misrepresents the employer.", "fake_offer", ["unrealistic_pay", "minimal_screening", "urgency"], ["contact", "offer"]),
    tax("J03", "job", "Task or optimisation scam", "Offers paid rating or optimisation tasks before demanding deposits to continue or withdraw.", "task_deposit", ["simple_tasks", "commission", "unlock_payment"], ["offer", "payment", "withdrawal_block"]),
    tax("J04", "job", "Work-from-home data-entry scam", "Uses an easy remote-work promise to collect fees or personal information.", "fake_offer", ["remote_work", "high_pay", "no_interview"], ["contact", "offer"]),
    tax("J05", "job", "Registration or processing-fee scam", "Requires payment before an application, interview, or job can proceed.", "upfront_fee", ["upfront_fee", "refundable_claim", "urgency"], ["offer", "payment"]),
    tax("J06", "job", "Training or certification-fee scam", "Requires payment for mandatory training, licensing, or certification controlled by the scammer.", "upfront_fee", ["mandatory_training", "fee", "scarcity"], ["offer", "payment"]),
    tax("J07", "job", "Equipment-purchase scam", "Directs the applicant to buy equipment from a fake supplier or send money for reimbursement.", "upfront_fee", ["equipment_purchase", "approved_vendor", "reimbursement_claim"], ["offer", "payment"]),
    tax("J08", "job", "Fake-cheque or overpayment scam", "Sends a false payment and instructs the applicant to return or forward real funds.", "fake_check", ["overpayment", "refund_request", "money_transfer"], ["payment", "escalation"]),
    tax("J09", "job", "Reshipping or parcel-mule job", "Recruits a person to receive and forward goods acquired through fraud.", "reshipping", ["receive_packages", "remove_labels", "reship"], ["offer", "execution"]),
    tax("J10", "job", "Money-mule or payment-agent recruitment", "Recruits a person to receive, convert, or forward criminal proceeds.", "money_mule", ["use_bank_account", "retain_commission", "forward_funds"], ["offer", "execution"]),
    tax("J11", "job", "Mystery-shopper scam", "Uses shopping assignments, fake cheques, or gift-card purchases to steal funds.", "fake_check", ["mystery_shopper", "gift_cards", "fake_check"], ["offer", "payment"]),
    tax("J12", "job", "Government-job placement scam", "Impersonates a public body and charges for placement, forms, or clearance.", "impersonation", ["government_impersonation", "processing_fee", "authority"], ["offer", "payment"]),
    tax("J13", "job", "Visa or overseas-placement scam", "Promises overseas employment while charging for visas, travel, or placement.", "upfront_fee", ["overseas_job", "visa_fee", "travel_payment"], ["offer", "payment"]),
    tax("J14", "job", "Employment identity harvesting", "Uses recruitment as a pretext to obtain identity, banking, or authentication data.", "credential", ["identity_documents", "bank_details", "otp_request"], ["application", "credential_request"]),
    tax("J15", "job", "Interview malware or fake meeting application", "Directs the applicant to install unsafe software or open a malicious interview file.", "malware", ["install_application", "apk", "remote_access"], ["interview", "installation"]),
    tax("J16", "job", "Labour-trafficking recruitment", "Uses deceptive overseas employment to facilitate coercion, confinement, or forced criminal activity.", "trafficking", ["travel_pressure", "passport_request", "remote_location"], ["offer", "travel", "control"]),
    tax("I01", "investment", "Relationship-investment scam", "Builds friendship or romance before directing the victim to a controlled investment platform.", "grooming", ["relationship_grooming", "private_tip", "controlled_platform"], ["contact", "trust_building", "investment"]),
    tax("I02", "investment", "Fake investment chat group", "Uses a coordinated group, fake experts, and fabricated testimonials to induce deposits.", "social_proof", ["chat_group", "fake_expert", "testimonials"], ["contact", "trust_building", "payment"]),
    tax("I03", "investment", "Fake trading website or application", "Displays fabricated balances and profits on a platform controlled by the scammer.", "fake_platform", ["platform_link", "fabricated_profit", "withdrawal_block"], ["investment", "payment", "withdrawal_block"]),
    tax("I04", "investment", "Cryptocurrency or token investment scam", "Promotes a false crypto, token, mining, staking, or liquidity opportunity.", "guaranteed_return", ["crypto", "wallet_payment", "guaranteed_return"], ["offer", "payment"]),
    tax("I05", "investment", "Forex or CFD trading scam", "Promotes unauthorised or fictitious leveraged trading with unrealistic returns.", "guaranteed_return", ["forex", "leverage", "account_manager"], ["offer", "payment"]),
    tax("I06", "investment", "AI or automated trading-bot scam", "Claims an automated or AI system produces consistent low-risk profits.", "guaranteed_return", ["ai_claim", "automated_trading", "risk_free"], ["offer", "payment"]),
    tax("I07", "investment", "High-yield guaranteed-return programme", "Promises implausible fixed daily, weekly, or monthly investment returns.", "guaranteed_return", ["high_yield", "guaranteed_return", "urgency"], ["offer", "payment"]),
    tax("I08", "investment", "Ponzi scheme", "Uses new participants' money to pay apparent returns to earlier participants.", "social_proof", ["consistent_returns", "referrals", "opaque_strategy"], ["trust_building", "payment", "escalation"]),
    tax("I09", "investment", "Pyramid or investment-MLM scheme", "Rewards recruitment and entry fees rather than genuine investment activity.", "recruitment", ["recruit_members", "entry_fee", "tiered_rewards"], ["offer", "recruitment", "payment"]),
    tax("I10", "investment", "Pump-and-dump or stock-tip manipulation", "Promotes a security using false claims before insiders sell at an inflated price.", "market_manipulation", ["secret_tip", "buy_now", "price_target"], ["promotion", "purchase"]),
    tax("I11", "investment", "Pre-IPO or private-placement scam", "Offers fictitious or unauthorised shares before an alleged public listing.", "scarcity", ["pre_ipo", "exclusive_allocation", "deadline"], ["offer", "payment"]),
    tax("I12", "investment", "Clone-firm or adviser impersonation", "Misuses the identity of a regulated firm or professional to solicit investments.", "impersonation", ["clone_firm", "fake_adviser", "lookalike_domain"], ["contact", "verification", "payment"]),
    tax("I13", "investment", "Affinity investment fraud", "Exploits a shared community, religion, occupation, or nationality to build trust.", "affinity", ["shared_identity", "community_endorsement", "social_proof"], ["trust_building", "offer"]),
    tax("I14", "investment", "Commodity or precious-metal fraud", "Promotes fictitious or misrepresented gold, commodity, or futures investments.", "guaranteed_return", ["commodity", "storage_claim", "guaranteed_return"], ["offer", "payment"]),
    tax("I15", "investment", "Real-estate or land investment fraud", "Offers non-existent, unauthorised, or materially misrepresented property investments.", "fake_asset", ["property_units", "exclusive_deal", "deposit"], ["offer", "payment"]),
    tax("I16", "investment", "Recovery or reload scam", "Targets prior victims with a promise to recover losses after another advance payment.", "recovery", ["prior_victim", "recovery_fee", "guarantee"], ["recontact", "payment"]),
]
TAX_BY_DOMAIN = {domain: [x for x in TAXONOMY if x["domain"] == domain] for domain in ("job", "investment")}
SCENARIO_CUES = {
    "J01": "I am the assigned recruiter; continue on private chat",
    "J02": "immediate vacancy with no formal interview",
    "J03": "rate products and optimise orders to earn commission",
    "J04": "easy remote data-entry work with unusually high pay",
    "J05": "pay the registration fee before the application proceeds",
    "J06": "mandatory training certificate must be purchased from us",
    "J07": "buy equipment from our approved supplier and await reimbursement",
    "J08": "deposit the company cheque and return the excess payment",
    "J09": "receive parcels, remove labels, and reship them",
    "J10": "receive funds in your account, keep commission, and forward the balance",
    "J11": "mystery-shopper assignment requires gift-card purchases",
    "J12": "government placement requires an administrative clearance payment",
    "J13": "overseas placement requires visa and travel fees in advance",
    "J14": "upload identity documents, bank details, and the verification code",
    "J15": "install the interview application or APK before the meeting",
    "J16": "travel immediately and surrender your passport for processing",
    "I01": "a trusted online friend has a private investment tip",
    "I02": "join the private expert group and follow member testimonials",
    "I03": "profits appear on the private platform but withdrawal needs another deposit",
    "I04": "exclusive token, mining, staking, or liquidity investment",
    "I05": "managed forex or CFD account with low risk and high leverage",
    "I06": "AI trading bot produces consistent automated profits",
    "I07": "fixed high daily return is guaranteed",
    "I08": "existing members receive steady returns funded by new deposits",
    "I09": "earn more by recruiting members into paid investment tiers",
    "I10": "confidential stock tip says buy before the price target is announced",
    "I11": "limited pre-IPO allocation closes before the public listing",
    "I12": "regulated adviser profile directs payment to a different account",
    "I13": "trusted community members have already joined this opportunity",
    "I14": "gold or commodity units include guaranteed storage and returns",
    "I15": "exclusive property units require a reservation deposit before inspection",
    "I16": "lost investment funds can be recovered after a recovery fee",
}

ENGLISH_PHRASES = {
    "job_offer": ("part-time job", "work from home", "simple tasks with commission"),
    "task_unlock": ("pay to unlock the next task", "deposit to withdraw earnings", "your task balance is negative"),
    "investment": ("investment opportunity", "cryptocurrency investment", "private trading platform"),
    "guaranteed_return": ("guaranteed profit", "risk-free returns", "daily returns"),
    "advance_fee": ("processing fee", "refundable deposit", "release fee"),
    "money_transfer": ("transfer the money now", "make the payment", "send the funds"),
    "secret_request": ("send the OTP", "provide your password", "share the verification code"),
    "tech_support": ("install this interview application", "install the remote access application", "open the interview APK"),
    "delivery_claim": ("receive and resend parcels", "remove the original labels", "forward packages to our warehouse"),
    "recovery_offer": ("we can recover your lost funds", "pay the recovery fee", "guaranteed asset recovery"),
    "urgency": ("act immediately", "final notice", "within one hour"),
}
SAFE_NEGATION = {
    "en": "No fee, deposit, password, OTP, or money transfer is required.",
    "zh": "无需支付费用、押金或转账，也不要提供密码或验证码。", "ms": "Tiada yuran, deposit, kata laluan, OTP atau pindahan wang diperlukan.",
    "ta": "கட்டணம், வைப்பு, கடவுச்சொல், OTP அல்லது பணப் பரிமாற்றம் தேவையில்லை.", "id": "Tidak diperlukan biaya, deposit, kata sandi, OTP, atau transfer uang.",
    "es": "No se requiere tarifa, depósito, contraseña, OTP ni transferencia de dinero.", "pt": "Nenhuma taxa, depósito, senha, OTP ou transferência de dinheiro é necessária.",
    "fr": "Aucun frais, dépôt, mot de passe, OTP ou transfert d’argent n’est requis.", "de": "Es sind keine Gebühr, Kaution, Passwort, OTP oder Geldüberweisung erforderlich.",
    "hi": "कोई शुल्क, जमा, पासवर्ड, ओटीपी या धन हस्तांतरण आवश्यक नहीं है।", "bn": "কোনো ফি, জমা, পাসওয়ার্ড, ওটিপি বা টাকা পাঠানো প্রয়োজন নেই।",
    "ur": "کسی فیس، جمع، پاس ورڈ، او ٹی پی یا رقم کی منتقلی کی ضرورت نہیں ہے۔", "ar": "لا يلزم دفع رسوم أو وديعة أو تقديم كلمة مرور أو رمز تحقق أو تحويل أموال.",
    "ja": "手数料、保証金、パスワード、OTP、送金は必要ありません。", "ko": "수수료, 보증금, 비밀번호, OTP 또는 송금이 필요하지 않습니다.",
    "th": "ไม่ต้องชำระค่าธรรมเนียม เงินมัดจำ รหัสผ่าน OTP หรือโอนเงิน", "vi": "Không yêu cầu phí, tiền đặt cọc, mật khẩu, OTP hoặc chuyển tiền.",
    "tl": "Walang bayad, deposito, password, OTP, o pagpapadala ng pera na kailangan.", "ru": "Не требуются комиссия, депозит, пароль, OTP или перевод денег.",
}
SAFE_CONTEXT = {
    "en": ("Your official interview is confirmed.", "Your routine investment statement is ready.", "Verify independently through the official organisation."),
    "zh": ("您的正式面试已确认。", "您的定期投资结单已准备好。", "请通过机构的官方渠道独立核实。"),
    "ms": ("Temu duga rasmi anda telah disahkan.", "Penyata pelaburan berkala anda sudah tersedia.", "Sahkan melalui saluran rasmi organisasi."),
    "ta": ("உங்கள் அதிகாரப்பூர்வ நேர்காணல் உறுதிப்படுத்தப்பட்டுள்ளது.", "உங்கள் வழக்கமான முதலீட்டு அறிக்கை தயாராக உள்ளது.", "நிறுவனத்தின் அதிகாரப்பூர்வ வழியில் சரிபார்க்கவும்."),
    "id": ("Wawancara resmi Anda telah dikonfirmasi.", "Laporan investasi rutin Anda sudah tersedia.", "Verifikasi melalui saluran resmi organisasi."),
    "es": ("Su entrevista oficial está confirmada.", "Su estado de inversión periódico está listo.", "Verifique por el canal oficial de la organización."),
    "pt": ("Sua entrevista oficial está confirmada.", "Seu extrato periódico de investimento está pronto.", "Verifique pelo canal oficial da organização."),
    "fr": ("Votre entretien officiel est confirmé.", "Votre relevé d’investissement périodique est disponible.", "Vérifiez par le canal officiel de l’organisation."),
    "de": ("Ihr offizielles Vorstellungsgespräch ist bestätigt.", "Ihr regulärer Anlagebericht ist verfügbar.", "Prüfen Sie dies über den offiziellen Kanal der Organisation."),
    "hi": ("आपका आधिकारिक साक्षात्कार पुष्ट हो गया है।", "आपका नियमित निवेश विवरण तैयार है।", "संगठन के आधिकारिक माध्यम से स्वतंत्र पुष्टि करें।"),
    "bn": ("আপনার আনুষ্ঠানিক সাক্ষাৎকার নিশ্চিত হয়েছে।", "আপনার নিয়মিত বিনিয়োগ বিবরণী প্রস্তুত।", "প্রতিষ্ঠানের সরকারি চ্যানেলে যাচাই করুন।"),
    "ur": ("آپ کا سرکاری انٹرویو تصدیق شدہ ہے۔", "آپ کا باقاعدہ سرمایہ کاری بیان تیار ہے۔", "ادارے کے سرکاری ذریعے سے تصدیق کریں۔"),
    "ar": ("تم تأكيد مقابلتك الرسمية.", "كشف الاستثمار الدوري الخاص بك جاهز.", "تحقق بشكل مستقل عبر القناة الرسمية للمؤسسة."),
    "ja": ("正式な面接が確認されました。", "定期的な投資明細が用意されました。", "組織の公式窓口から独自に確認してください。"),
    "ko": ("공식 면접이 확인되었습니다.", "정기 투자 명세서가 준비되었습니다.", "기관의 공식 채널을 통해 독립적으로 확인하세요."),
    "th": ("ยืนยันการสัมภาษณ์อย่างเป็นทางการแล้ว", "รายการลงทุนประจำงวดพร้อมแล้ว", "ตรวจสอบผ่านช่องทางทางการขององค์กร"),
    "vi": ("Cuộc phỏng vấn chính thức của bạn đã được xác nhận.", "Báo cáo đầu tư định kỳ của bạn đã sẵn sàng.", "Hãy xác minh qua kênh chính thức của tổ chức."),
    "tl": ("Kumpirmado ang opisyal mong panayam.", "Handa na ang regular mong investment statement.", "Mag-verify sa opisyal na channel ng organisasyon."),
    "ru": ("Ваше официальное собеседование подтверждено.", "Регулярный инвестиционный отчёт готов.", "Проверьте информацию через официальный канал организации."),
}
AWARENESS_BY_LANG = {
    "en": "scam alert", "zh": "诈骗提醒", "ms": "amaran penipuan",
    "ta": "மோசடி எச்சரிக்கை", "id": "peringatan penipuan", "es": "alerta de estafa",
    "pt": "aviso de fraude", "fr": "alerte arnaque", "de": "betrugswarnung",
    "hi": "धोखाधड़ी चेतावनी", "bn": "প্রতারণা সতর্কতা", "ur": "فراڈ سے خبردار",
    "ar": "تحذير من الاحتيال", "ja": "詐欺注意", "ko": "사기 주의",
    "th": "เตือนภัยมิจฉาชีพ", "vi": "cảnh báo lừa đảo", "tl": "babala sa scam",
    "ru": "предупреждение о мошенничестве",
}

MECHANISM_KEYS = {
    "impersonation": ("job_offer", "urgency"), "fake_offer": ("job_offer", "guaranteed_return"),
    "task_deposit": ("job_offer", "task_unlock"), "upfront_fee": ("job_offer", "advance_fee"),
    "fake_check": ("job_offer", "money_transfer"), "reshipping": ("job_offer", "delivery_claim"),
    "money_mule": ("job_offer", "money_transfer"), "credential": ("job_offer", "secret_request"),
    "malware": ("job_offer", "tech_support"), "trafficking": ("job_offer", "urgency"),
    "grooming": ("investment", "guaranteed_return"), "social_proof": ("investment", "guaranteed_return"),
    "fake_platform": ("investment", "guaranteed_return"), "guaranteed_return": ("investment", "guaranteed_return"),
    "recruitment": ("investment", "advance_fee"), "market_manipulation": ("investment", "urgency"),
    "scarcity": ("investment", "urgency"), "affinity": ("investment", "guaranteed_return"),
    "fake_asset": ("investment", "advance_fee"), "recovery": ("recovery_offer", "advance_fee"),
}

EXTERNAL_SOURCES = [
    ("EMSCAD", "job_posting", "17880", "public", "licence review required", "https://emscad.samos.aegean.gr/", "No"),
    ("Anansi", "job_message", "29209", "paper; corpus access unconfirmed", "author permission required", "https://arxiv.org/abs/2602.24223", "No"),
    ("Investment deceptive content", "investment_social", "16202", "public", "CC BY 4.0", "https://data.mendeley.com/datasets/6wnd7jrt6z/2", "No"),
    ("Taiwan investment chatrooms", "investment_conversation", "29438", "release unconfirmed", "author permission required", "https://www.researchgate.net/publication/372953766_Constructing_an_Investment_Scam_Detection_Model_Based_on_Emotional_Fluctuations_Throughout_the_Investment_Scam_Life_Cycle", "No"),
    ("SCAMBENCH", "mixed_message", "3670", "gated", "CC BY-NC 4.0", "https://huggingface.co/datasets/Shouninger/ScamBench", "No"),
    ("MultiAgentFraudBench", "synthetic_social", "11900", "public", "CC BY-NC-SA 4.0", "https://huggingface.co/datasets/ninty-seven/MultiAgentFraudBench", "No"),
    ("PreScam", "mixed_conversation", "11573", "release unconfirmed", "author permission required", "https://arxiv.org/abs/2605.12243", "No"),
    ("BanglaPhish-2026", "synthetic_message", "6000", "public", "CC BY-NC 4.0", "https://github.com/Xrenes/BanglaPhish-2026", "No"),
    ("Bangla-English financial scams", "mixed_message", "not published", "public", "CC BY 4.0", "https://data.mendeley.com/datasets/znsk27yk3h/2", "No"),
    ("COVA-X", "synthetic_conversation", "10985", "paper", "licence review required", "https://arxiv.org/abs/2606.06879", "No"),
    ("TeleAntiFraud-28k", "audio_text", "28511", "public sanitized", "dataset terms review required", "https://github.com/JimmyMa99/TeleAntiFraud", "No"),
    ("IMC25 smishing", "multilingual_message", "27718", "public", "CC BY 4.0", "https://github.com/reportsmishing/Smishing-Dataset-IMC25", "No"),
    ("Smishtank", "smishing_message", "1090", "public", "source terms review required", "https://arxiv.org/abs/2402.18430", "No"),
    ("UCI SMS Spam Collection", "sms_contrast", "5574", "public", "CC BY 4.0", "https://archive.ics.uci.edu/dataset/228/sms+spam+collection", "No"),
    ("ScamFerret", "website", "4780", "public artifact", "repository and captured-content rights review", "https://github.com/ScamFerret/artifact", "No"),
]


def phrase(language: str, key: str, index: int) -> str:
    pack = ENGLISH_PHRASES if language == "en" else PHRASES.get(language, ENGLISH_PHRASES)
    values = pack.get(key) or ENGLISH_PHRASES.get(key) or (key.replace("_", " "),)
    return values[index % len(values)]


def reference(number: int) -> str:
    digest = hashlib.sha256(f"{SEED}:{number}".encode()).hexdigest()[:10].upper()
    return f"NV-{digest}"


def split_for(group_id: str) -> str:
    value = int(hashlib.sha256(group_id.encode()).hexdigest()[:8], 16) % 100
    return "train" if value < 80 else "validation" if value < 90 else "test"


def content_hash(record: dict[str, Any]) -> str:
    payload = {
        "label": record["label"],
        "domain": record["domain"],
        "taxonomy_id": record["taxonomy_id"],
        "language": record["language"],
        "text": record["text"],
        "text_en": record.get("text_en"),
        "turns": record.get("turns", []),
        "signals": record.get("signals", []),
        "scenario_cue_en": record.get("scenario_cue_en"),
        "requested_action": record.get("requested_action"),
        "harm_vector": record.get("harm_vector"),
        "severity": record.get("severity"),
        "annotation_confidence": record.get("annotation_confidence"),
        "label_basis": record.get("label_basis"),
        "ood_reason": record.get("ood_reason"),
        "variant_type": record.get("variant_type"),
    }
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def context_for(i: int, language: str) -> dict[str, Any]:
    country = COUNTRIES[language][i % len(COUNTRIES[language])]
    return {
        "language": language, "language_name": LANGUAGE_NAMES[language], "country": country,
        "currency": CURRENCY[country], "channel": CHANNELS[(i // 3) % len(CHANNELS)],
        "native_review_status": "required" if language != "en" else "internal_template_review",
    }


def apply_variant(text: str, variant: str, language: str) -> str:
    """Create safe, deterministic robustness variants without changing meaning."""
    if variant == "defanged_url":
        return text.replace("https://", "hxxps://").replace(".invalid", "[.]invalid")
    if variant == "zero_width":
        marker = "\u200b"
        return text.replace(" ", marker + " ", 2)
    if variant == "fullwidth_punctuation":
        return text.replace(":", "：").replace("!", "！").replace("?", "？")
    if variant == "spaced_tokens" and language == "en":
        return re.sub(r"\b(fee|deposit|profit|payment)\b", lambda m: " ".join(m.group(0)), text, flags=re.I)
    if variant == "mixed_punctuation":
        return text.replace(". ", "... ", 1).replace(" — ", " !!! ", 1)
    return text


def scam_text(domain: str, subtype: dict[str, Any], language: str, i: int, ref: str) -> tuple[str, list[str], str, str]:
    first_key, second_key = MECHANISM_KEYS[subtype["mechanism"]]
    first, second = phrase(language, first_key, i), phrase(language, second_key, i // 2)
    urgent = phrase(language, "urgency", i // 3)
    money = phrase(language, "money_transfer", i // 5)
    company = (FICTIONAL_JOB_BRANDS if domain == "job" else FICTIONAL_INVESTMENT_BRANDS)[i % 6]
    object_name = ROLES[(i // 7) % len(ROLES)] if domain == "job" else ASSETS[(i // 7) % len(ASSETS)]
    cue = SCENARIO_CUES[subtype["id"]]
    link = f"https://{domain}-{subtype['id'].lower()}-{i % 97}.invalid/{ref.lower()}"
    amount = AMOUNTS[i % len(AMOUNTS)]
    english_patterns = (
        f"{urgent}. {company}: {first} — {object_name}. {cue}. {second}. {money} {amount}. {link} Ref: {ref}",
        f"{company} | {first}. {cue}. {second}; {urgent}. {link} Ref: {ref}",
        f"{first}: {object_name}. {cue}. {second}. {money} {amount}. Contact us off-platform. Ref: {ref}",
        f"{urgent} — {first}. {company} says: {cue}. {second}. Use {link}. Ref: {ref}",
    )
    # The target-language text deliberately excludes English subtype prose.
    # Leaf detail remains available in scenario_cue_en and text_en for auditability.
    local_patterns = (
        f"{urgent}. {first}. {second}. {money} {amount}. {link} Ref: {ref}",
        f"{first}. {second}; {urgent}. {link} Ref: {ref}",
        f"{first}. {second}. {money} {amount}. Ref: {ref}",
        f"{urgent} — {first}. {second}. {link}. Ref: {ref}",
    )
    text_en = english_patterns[i % len(english_patterns)]
    text = text_en if language == "en" else local_patterns[i % len(local_patterns)]
    signals = list(dict.fromkeys(subtype["signals"] + (["contains_url"] if i % 4 != 2 else []) + (["off_platform"] if i % 3 == 0 else [])))
    if i % 4 == 2:
        text = re.sub(r"https://\S+", "[LINK REDACTED]", text)
        text_en = re.sub(r"https://\S+", "[LINK REDACTED]", text_en)
    variant = VARIANT_TYPES[(i // 4) % len(VARIANT_TYPES)]
    text = apply_variant(text, variant, language)
    return text, signals, text_en, variant


def legitimate_text(domain: str, language: str, i: int, ref: str) -> str:
    safe = SAFE_CONTEXT[language]
    topic = phrase(language, "job_offer" if domain == "job" else "investment", i)
    company = (FICTIONAL_JOB_BRANDS if domain == "job" else FICTIONAL_INVESTMENT_BRANDS)[i % 6] if language == "en" else "[ORGANISATION]"
    context = safe[0] if domain == "job" else safe[1]
    return f"{company}: {context} {topic}. {SAFE_NEGATION[language]} {safe[2]} Ref: {ref}"


def awareness_text(domain: str, language: str, i: int, ref: str) -> str:
    warning = AWARENESS_BY_LANG.get(language, "scam alert")
    topic = phrase(language, "job_offer" if domain == "job" else "investment", i)
    risky = phrase(language, "advance_fee" if domain == "job" else "guaranteed_return", i)
    return f"{warning}: {topic}; {risky}. {SAFE_NEGATION[language]} {SAFE_CONTEXT[language][2]} Ref: {ref}"


def ood_text(domain: str, language: str, i: int, ref: str) -> tuple[str, str]:
    contexts = SAFE_CONTEXT[language]
    local = f"{contexts[i % 3]} Ref: {ref}"
    english = (
        f"General career planning discussion with no offer or request. Ref: {ref}" if domain == "job"
        else f"General market education with no recommendation or transaction request. Ref: {ref}"
    )
    return local if language != "en" else english, english


def conversation(domain: str, subtype: dict[str, Any] | None, language: str, i: int,
                 ref: str, scam: bool) -> tuple[list[dict[str, str]], str, list[str], str, str]:
    if not scam:
        base = legitimate_text(domain, language, i, ref)
        turns = [
            {"role": "organisation", "text": base},
            {"role": "recipient", "text": SAFE_CONTEXT[language][2]},
            {"role": "organisation", "text": SAFE_NEGATION[language]},
        ]
        joined = "\n".join(f"[{x['role']}] {x['text']}" for x in turns)
        return turns, joined, ["verified_channel", "no_payment_request"], joined if language == "en" else "Verified legitimate conversation; no fee, credential, or transfer request.", "clean"
    if subtype is None:
        raise ValueError("scam conversations require a taxonomy subtype")
    bait, signals, bait_en, variant = scam_text(domain, subtype, language, i, ref)
    turns = [
        {"role": "unknown_sender", "text": bait.split("Ref:")[0].strip()},
        {"role": "recipient", "text": SAFE_CONTEXT[language][2]},
        {"role": "unknown_sender", "text": f"{phrase(language, 'urgency', i)}. {phrase(language, MECHANISM_KEYS[subtype['mechanism']][1], i)}."},
        {"role": "recipient", "text": SAFE_NEGATION[language]},
        {"role": "unknown_sender", "text": f"{phrase(language, 'money_transfer', i)} {AMOUNTS[i % len(AMOUNTS)]}. https://case-{i % 97}.invalid/{ref.lower()} Ref: {ref}"},
    ]
    joined = "\n".join(f"[{x['role']}] {x['text']}" for x in turns)
    text_en = f"[unknown_sender] {bait_en}\n[recipient] Verify independently.\n[unknown_sender] Payment pressure escalates."
    return turns, joined, list(dict.fromkeys(signals + ["conversation_escalation"])), text_en, variant


def make_record(number: int, record_type: str, label: str, domain: str, language: str,
                taxonomy_id: str, text: str, signals: list[str], turns: list[dict[str, str]] | None = None,
                text_en: str | None = None, variant_type: str = "clean", ood_reason: str | None = None) -> dict[str, Any]:
    ctx = context_for(number, language)
    subtype = next((x for x in TAXONOMY if x["id"] == taxonomy_id), None)
    family_width = len(LANGUAGES) * (16 if label == "scam" else 1) * (5 if label == "scam" else 8)
    campaign_key = number // family_width
    group_id = f"NVG-{domain}-{taxonomy_id}-{language}-{campaign_key:06d}"
    action = ACTION_BY_MECHANISM.get(subtype["mechanism"], "none") if subtype else "none"
    label_name = {"legitimate": "Legitimate hard negative", "awareness": "Awareness or negated context", "ambiguous_ood": "Out-of-distribution abstention case"}.get(label, "Research sample")
    record = {
        "id": f"NVJI-{number:07d}", "version": VERSION, "record_type": record_type,
        "label": label, "domain": domain, "taxonomy_id": taxonomy_id,
        "taxonomy_name": subtype["name"] if subtype else label_name,
        **ctx, "text": text, "text_en": text_en or text, "turns": turns or [], "signals": signals,
        "scenario_cue_en": SCENARIO_CUES.get(taxonomy_id),
        "leaf_text_specificity": "leaf_level" if language == "en" else ("mechanism_level" if label == "scam" else "not_applicable"),
        "language_variant": "english" if language == "en" else "native_script_template",
        "translation_status": "source_english" if language == "en" else "auditable_template_not_human_verified",
        "variant_type": variant_type, "variant_family_id": group_id,
        "requested_action": action, "harm_vector": HARM_BY_ACTION.get(action, "none"),
        "severity": "high" if label == "scam" and action in {"forward_funds", "install_software", "travel_or_surrender_documents", "share_sensitive_data"} else ("medium" if label == "scam" else "none"),
        "annotation_confidence": 1.0 if label in {"scam", "legitimate", "awareness"} else 0.5,
        "label_basis": "generator_ground_truth" if label != "ambiguous_ood" else "designed_abstention_case",
        "review_status": "internal_template_review" if language == "en" else "native_speaker_review_required",
        "ood_reason": ood_reason,
        "lifecycle_stage": (subtype["lifecycle_stages"][number % len(subtype["lifecycle_stages"])] if subtype else "prevention"),
        "payment_method": (PAYMENT_METHODS[number % 5] if label == "scam" else "none"),
        "synthetic": True, "contains_live_indicator": False, "pii_status": "safe_placeholders_only",
        "code_switch_status": "none",
        "source_id": "NEXVISION-SYNTH-2026-02", "source_type": "deterministic_synthetic_template",
        "generator_seed": SEED, "campaign_group_id": group_id, "split": split_for(group_id),
        "created_at": CREATED_AT,
    }
    record["content_sha256"] = content_hash(record)
    return record


def generate() -> list[dict[str, Any]]:
    rng = random.Random(SEED)
    records: list[dict[str, Any]] = []
    number = 1

    def language_for(offset: int) -> str:
        return LANGUAGES[offset % len(LANGUAGES)]

    # 24,000 scam single messages: 12,000 per domain.
    for domain in ("job", "investment"):
        types = TAX_BY_DOMAIN[domain]
        for i in range(12_000):
            lang = language_for(number - 1)
            subtype = types[i % len(types)]
            ref = reference(number)
            text, signals, text_en, variant = scam_text(domain, subtype, lang, i, ref)
            records.append(make_record(number, "single_message", "scam", domain, lang, subtype["id"], text, signals, text_en=text_en, variant_type=variant))
            number += 1

    # 18,000 legitimate hard negatives: 9,000 per domain.
    for domain in ("job", "investment"):
        for i in range(9_000):
            lang = language_for(number - 1)
            ref = reference(number)
            text = legitimate_text(domain, lang, i, ref)
            records.append(make_record(number, "single_message", "legitimate", domain, lang, f"{domain[0].upper()}00-L", text,
                                       ["official_verification", "no_payment_request", "negated_risk_terms"],
                                       text_en="Official verified communication. No fee, credential, deposit, or transfer is requested."))
            number += 1

    # 6,000 awareness/negated cases: 3,000 per domain.
    for domain in ("job", "investment"):
        for i in range(3_000):
            lang = language_for(number - 1)
            ref = reference(number)
            text = awareness_text(domain, lang, i, ref)
            records.append(make_record(number, "single_message", "awareness", domain, lang, f"{domain[0].upper()}00-A", text,
                                       ["awareness_context", "negated_risk_terms"],
                                       text_en="Scam awareness warning: do not pay fees, send credentials, or trust guaranteed returns."))
            number += 1

    # 8,000 scam conversations: 4,000 per domain.
    for domain in ("job", "investment"):
        types = TAX_BY_DOMAIN[domain]
        for i in range(4_000):
            lang = language_for(number - 1)
            subtype = types[i % len(types)]
            ref = reference(number)
            turns, text, signals, text_en, variant = conversation(domain, subtype, lang, i, ref, True)
            records.append(make_record(number, "conversation", "scam", domain, lang, subtype["id"], text, signals, turns, text_en, variant))
            number += 1

    # 4,000 legitimate conversations: 2,000 per domain.
    for domain in ("job", "investment"):
        for i in range(2_000):
            lang = language_for(number - 1)
            ref = reference(number)
            turns, text, signals, text_en, variant = conversation(domain, None, lang, i, ref, False)
            records.append(make_record(number, "conversation", "legitimate", domain, lang, f"{domain[0].upper()}00-L", text, signals, turns, text_en, variant))
            number += 1

    # 4,000 abstention/OOD cases: unrelated or underspecified content.
    for domain in ("job", "investment"):
        for i in range(2_000):
            lang = language_for(number - 1)
            ref = reference(number)
            text, text_en = ood_text(domain, lang, i, ref)
            reason = ("insufficient_evidence" if i % 2 == 0 else "adjacent_but_non_transactional")
            records.append(make_record(number, "single_message", "ambiguous_ood", domain, lang, f"{domain[0].upper()}00-O", text,
                                       ["abstention_recommended"], text_en=text_en, ood_reason=reason))
            number += 1

    if len(records) != 64_000:
        raise RuntimeError(f"generator invariant failed: expected 64,000 records, got {len(records):,}")
    rng.shuffle(records)
    return records


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> None:
    for folder in ("data", "metadata", "quality", "samples", "schema", "taxonomy"):
        (ROOT / folder).mkdir(parents=True, exist_ok=True)
    records = generate()
    write_jsonl(ROOT / "data" / "records.jsonl", records)
    with (ROOT / "metadata" / "split_index.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("id", "split", "campaign_group_id", "variant_family_id"))
        writer.writerows((x["id"], x["split"], x["campaign_group_id"], x["variant_family_id"]) for x in records)
    sample = []
    for taxonomy_id in [x["id"] for x in TAXONOMY]:
        sample.extend([x for x in records if x["taxonomy_id"] == taxonomy_id][:10])
    write_jsonl(ROOT / "samples" / "taxonomy_sample_320.jsonl", sample)
    with (ROOT / "samples" / "taxonomy_sample_320.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, lineterminator="\n", fieldnames=("id", "label", "domain", "taxonomy_id", "language", "country", "channel", "text", "split"))
        writer.writeheader()
        writer.writerows({key: row[key] for key in writer.fieldnames} for row in sample)
    # Stable, compact evaluation set: subtype coverage plus hard-negative,
    # awareness and abstention slices. These records remain duplicates of the
    # canonical test partition and are provided only for convenient evaluation.
    test_rows = sorted((x for x in records if x["split"] == "test"), key=lambda x: x["id"])
    curated: list[dict[str, Any]] = []
    for taxonomy_id in [x["id"] for x in TAXONOMY]:
        curated.extend([x for x in test_rows if x["taxonomy_id"] == taxonomy_id][:8])
    for label, count in (("legitimate", 128), ("awareness", 64), ("ambiguous_ood", 64)):
        curated.extend([x for x in test_rows if x["label"] == label][:count])
    if len(curated) != 512:
        raise RuntimeError(f"evaluation slice invariant failed: expected 512 records, got {len(curated)}")
    write_jsonl(ROOT / "samples" / "curated_eval_512.jsonl", curated)
    with (ROOT / "samples" / "curated_eval_512_index.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("id", "label", "domain", "taxonomy_id", "language", "variant_type", "severity", "slice"))
        for row in curated:
            slice_name = f"leaf:{row['taxonomy_id']}" if row["label"] == "scam" else f"label:{row['label']}"
            writer.writerow((row["id"], row["label"], row["domain"], row["taxonomy_id"], row["language"], row["variant_type"], row["severity"], slice_name))
    write_json(ROOT / "taxonomy" / "taxonomy.json", {"version": VERSION, "leaf_count": len(TAXONOMY), "items": TAXONOMY})
    taxonomy_md = ["# Job and investment scam taxonomy", "", "The 32 scam leaf types are balanced at 1,000 scam records each.", ""]
    for domain in ("job", "investment"):
        taxonomy_md.extend([f"## {domain.title()} scams", "", "| ID | Type | Mechanism | Definition |", "|---|---|---|---|"])
        taxonomy_md.extend(f"| {item['id']} | {item['name']} | {item['mechanism']} | {item['definition']} |" for item in TAX_BY_DOMAIN[domain])
        taxonomy_md.append("")
    (ROOT / "taxonomy" / "TAXONOMY.md").write_text("\n".join(taxonomy_md) + "\n", encoding="utf-8", newline="\n")
    write_json(ROOT / "metadata" / "languages.json", {
        "count": len(LANGUAGES), "languages": [{"code": code, "name": LANGUAGE_NAMES[code], "native_review_status": "required" if code != "en" else "internal_template_review"} for code in LANGUAGES]
    })
    with (ROOT / "metadata" / "external_sources_manifest.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("name", "modality", "published_count", "access", "licence_or_requirement", "source_url", "included_in_records"))
        writer.writerows(EXTERNAL_SOURCES)
    counts = {
        "total": len(records), "by_label": Counter(x["label"] for x in records),
        "by_domain": Counter(x["domain"] for x in records), "by_type": Counter(x["record_type"] for x in records),
        "by_language": Counter(x["language"] for x in records), "by_split": Counter(x["split"] for x in records),
        "scam_by_taxonomy": Counter(x["taxonomy_id"] for x in records if x["label"] == "scam"),
        "by_variant": Counter(x["variant_type"] for x in records),
        "by_severity": Counter(x["severity"] for x in records),
        "by_requested_action": Counter(x["requested_action"] for x in records),
    }
    write_json(ROOT / "metadata" / "dataset_stats.json", counts)
    write_json(ROOT / "metadata" / "evaluation_slices.json", {
        "curated_eval_512": {
            "source_split": "test", "record_count": len(curated),
            "by_label": Counter(x["label"] for x in curated),
            "by_domain": Counter(x["domain"] for x in curated),
            "by_language": Counter(x["language"] for x in curated),
            "scam_by_taxonomy": Counter(x["taxonomy_id"] for x in curated if x["label"] == "scam"),
        }
    })
    write_json(ROOT / "quality" / "language_audit.json", {
        "version": VERSION,
        "non_english_records": sum(x["language"] != "en" for x in records),
        "non_english_records_requiring_native_review": sum(x["language"] != "en" and x["review_status"] == "native_speaker_review_required" for x in records),
        "english_scenario_cue_in_non_english_text": sum(bool(x["language"] != "en" and x.get("scenario_cue_en") and x["scenario_cue_en"] in x["text"]) for x in records),
        "human_validated_languages": [],
        "interpretation": "No English leaf-cue injection was detected; native-speaker validation is still required for every non-English language.",
    })
    hashes = {}
    for relative in ("data/records.jsonl", "metadata/split_index.csv", "taxonomy/taxonomy.json", "samples/taxonomy_sample_320.jsonl", "samples/curated_eval_512.jsonl"):
        hashes[relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    write_json(ROOT / "metadata" / "checksums.json", {"algorithm": "SHA-256", "files": hashes})


if __name__ == "__main__":
    main()

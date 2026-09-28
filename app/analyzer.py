# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

from classifier import predict
from domain_intel import brand_impersonation, dns_email_domain_analysis, email_domain_analysis, registrable_domain, verification_workflow
from normalization import fold_for_matching, normalize, normalize_detailed
from rules import RULES as _ENGLISH_AND_ASIAN_RULES, RULES_VERSION
from rules_multilingual import LANGUAGE_RULES, LANGUAGE_RULE_IDS, awareness_near, fold_german, language_applies, language_warning, sentence_warns_in_any_language

RULES = _ENGLISH_AND_ASIAN_RULES + LANGUAGE_RULES

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\"]+|\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|sg|xyz|top|vip|app|work|click)\b")
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")
HANDLE_RE = re.compile(r"(?<!\w)@[A-Za-z0-9_]{3,32}\b")
CRYPTO_PATTERNS = (("Bitcoin", re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")), ("Ethereum/EVM", re.compile(r"\b0x[a-fA-F0-9]{40}\b")), ("TRON", re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")))
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly"}
UNCORROBORATED_MODEL_CAP = 10  # max points the classifier alone can add when no rule matched; Elevated starts at 25
SUSPICIOUS_TLDS = {"top", "xyz", "click", "work", "vip", "live", "buzz", "cyou", "quest", "cam"}


def _clip(value: str, length: int = 220) -> str:
    return re.sub(r"\s+", " ", value).strip()[:length]


def _evidence(text: str, match: re.Match[str], radius: int = 55) -> str:
    return _clip(text[max(0, match.start() - radius): min(len(text), match.end() + radius)])


# A sentence that quotes a scam in order to warn about it ("a message promising 12% returns ... may be a scam", "this guide does
# not ask you to pay a fee to unlock withdrawals") has the scam's wording in it and the opposite intent. The cues are tied to
# the risky action ("do not send", "never asks you to pay"), not to a bare "do not", so a scam sentence such as "Do not delay
# the deposit" is not mistaken for a warning.
_WARNING_SENTENCE = re.compile(
    r"\b(?:never|do not|don'?t|does not|doesn'?t|will not|won'?t|should not|must not|not)\s+(?:\w+\s+){0,2}"
    r"(?:ask|asks|request|requests|require|requires|charge|charges|demand|demands|send|pay|transfer|remit|share|provide|approve|"
    r"authori[sz]e|enter|click|install|download|deposit|top[ -]?up|forward|give|receive|handle)\b"
    r"|\bnever\s+(?:receives?|handles?|moves?|forwards?)\b"
    r"|\bignore\s+(?:any\s+|all\s+)?(?:messages?|emails?|calls?|requests?)\b"
    r"|\bif\s+(?:anyone|someone|a\s+message|an\s+email|you\s+(?:receive|get|are\s+asked|are\s+contacted))\b"
    r"|\b(?:may|might|could|can)\s+be\s+(?:a\s+)?(?:scam|fraud|phishing)\b|\b(?:is|are)\s+(?:a\s+)?(?:scam|fraud)s?\b"
    r"|\bscam\s+(?:alert|awareness)\b|\bfraud\s+(?:alert|awareness)\b|\bscams?\s+(?:often|typically|usually|commonly)\b|\bred\s+flags?\b|\bwarning\s+signs?\b"
    r"|\b(?:scammers?|fraudsters?|impersonators?)\b",
    re.I,
)
# Rules that describe a demand for money, a credential or an approval, and so can be quoted in a warning. Rules about the
# other side of a pitch (a claimed licence, a celebrity, a chat group) are not listed: a warning rarely contains them.
_WARNING_GUARDED_RULES = frozenset({
    "task_deposit", "sensitive_data", "unusual_payment", "withdrawal_fee", "unrealistic_return", "money_mule", "job_upfront_fee",
    "job_recruiter_deposit", "job_assigned_supplier", "payment_instruction_change", "credential_request", "wallet_approval",
    "recovery_fee", "pump_group", "insider_allocation_payment", "regulator_payment_demand", "grant_release_fee",
    "pay_before_disclosure", "fake_cheque", "sideload_app", "social_boosting",
})


def _sentence_of(text: str, match: re.Match[str]) -> str:
    start = max(text.rfind(c, 0, match.start()) for c in ".!?\n") + 1
    ends = [i for i in (text.find(c, match.end()) for c in ".!?\n") if i != -1]
    return text[start: min(ends) if ends else len(text)]


def _is_warning_sentence(text: str, match: re.Match[str]) -> bool:
    return bool(_WARNING_SENTENCE.search(_sentence_of(text, match)))


def _negated_or_educational(rule_id: str, text: str, match: re.Match[str]) -> bool:
    window = text[max(0, match.start() - 95): min(len(text), match.end() + 95)].lower()
    if rule_id in _WARNING_GUARDED_RULES and _is_warning_sentence(text, match):
        return True
    if rule_id in LANGUAGE_RULE_IDS and (not language_applies(rule_id, text) or language_warning(rule_id, text, match)):
        return True
    # The older rules read English, Chinese, Malay and Tamil; a warning about the same scam in another language still quotes it
    # (an English rule firing on a Tagalog fraud warning that mentions "guaranteed returns").
    if rule_id in _WARNING_GUARDED_RULES | {"guaranteed_returns", "no_risk"} and (sentence_warns_in_any_language(_sentence_of(text, match)) or awareness_near(window)):
        return True
    # A genuine payroll or bank notice about a negative balance says why ("due to bank charges", "overdraft"); a task scam invents one.
    if rule_id == "negative_balance" and re.search(r"overdraft|bank charges?|bank fees?|due to (?:bank )?(?:charges|fees|interest)|interest (?:charged|accrued)|payroll notice|final pay|dahil sa (?:bank|maintaining|fee|charge)|maintaining balance|insufficient funds|(?:returned|bounced) (?:cheque|check)|na-?return|service fee|monthly fee", window):
        return True
    # "A 25% annualised historical return" on a statement is a past figure with a disclaimer, not a promise of a fast one.
    if rule_id == "unrealistic_return" and re.search(r"annuali[sz]ed|per annum|p\.a\.|historical|past performance|year[- ]to[- ]date|since inception|last (?:year|quarter)", window) and not re.search(r"daily|weekly|per (?:day|week)|overnight|guarantee|risk[- ]free", window):
        return True
    if rule_id == "guaranteed_returns" and re.search(r"(?:returns?|profits?|yields?|roi)\s+(?:are|is|can be)?\s*not\s+(?:guaranteed|assured)|cannot guarantee|no\s+(?:returns?|profits?)?\s*(?:are\s+)?guaranteed|there are no guaranteed returns|(?:do not|don'?t|cannot|can'?t|never|no one can|nobody can)\s+(?:promise|guarantee|assure)", window):
        return True
    if rule_id == "no_risk" and re.search(r"not risk[ -]?free|no (?:investment|product|trade|strategy) (?:is|can be) risk[ -]?free|(?:all|every) investments? (?:carry|have|involve) risk", window):
        return True
    # An ordinary employee-referral bonus ("refer a friend who joins our team ... after 3 months") is not a pyramid scheme.
    # It only counts as one when profit, tiers, deposits or the like appear alongside it.
    if rule_id == "referral_income" and re.search(r"join(?:s|ed)? (?:our|the) (?:team|company|firm)|employee referral|complete[sd]? (?:their )?(?:\d+|three|six) months?|probation", window) and not re.search(r"daily|weekly|profit|commission|tier|downline|invest|deposit|activation|usdt|crypto|recharge|level", window):
        return True
    if rule_id in {"job_upfront_fee", "task_deposit", "sensitive_data", "unusual_payment", "sideload_app"} and re.search(r"(?:never|do not|don't|avoid|won't|will not).{0,60}(?:pay|transfer|deposit|share|send|install|download|top[ -]?up)", window):
        return True
    if rule_id == "job_upfront_fee":
        # "There is no registration fee", "we never charge any fee" and "the company pays for your visa" promise the opposite of
        # a fee demand, and a fee that is not about a job (a course, a subscription) is not a job scam.
        # Only the sentence the fee is in counts: "There is no interview fee. But you must pay a registration fee" is still a demand.
        start = max(text.rfind(c, 0, match.start()) for c in ".!?\n") + 1
        ends = [i for i in (text.find(c, match.end()) for c in ".!?\n") if i != -1]
        sentence = text[start: min(ends) if ends else len(text)].lower()
        if re.search(r"\bno\s+(?:\w+\s+){0,2}fees?\b|\bwithout\s+(?:\w+\s+){0,2}fees?\b|(?:never|not|don't|do not|won't|will not)\s+(?:charge|ask|require)[^.!?]{0,40}\b(?:fees?|payments?|money)\b|free of (?:charge|cost)|at no (?:cost|charge)|(?:company|employer|we|firm)\s+(?:will\s+)?(?:pay|pays|cover|covers|bear|bears|reimburse\w*|sponsor\w*)\b[^.!?]{0,40}\b(?:fees?|permit|visa)\b", sentence):
            return True
        if not re.search(r"\b(?:job|role|position|hired?|hiring|employ\w*|recruit\w*|salary|shortlist\w*|vacanc\w*|candidates?|applicants?|interview|tasks?|commission|work|working|start|remote|assistant|staff|earn\w*|income|part[- ]time|full[- ]time)\b", text.lower()):
            return True
    return False


def extract_entities(text: str) -> dict:
    value = normalize(text)
    urls: list[str] = []
    for raw in URL_RE.findall(value):
        clean = raw.rstrip(".,;:!?)]}")
        if clean.lower().startswith("www."): clean = "https://" + clean
        if clean not in urls: urls.append(clean)
    wallets = [{"type": kind, "value": item} for kind, pattern in CRYPTO_PATTERNS for item in pattern.findall(value)]
    return {"urls": urls[:20], "emails": list(dict.fromkeys(EMAIL_RE.findall(value)))[:20], "phones": list(dict.fromkeys(_clip(x) for x in PHONE_RE.findall(value)))[:20], "handles": list(dict.fromkeys(HANDLE_RE.findall(value)))[:20], "crypto_wallets": wallets[:20]}


def inspect_url(url: str) -> dict:
    candidate = normalize(url.strip())
    if not re.match(r"(?i)^https?://", candidate): candidate = "https://" + candidate
    try:
        parsed = urllib.parse.urlsplit(candidate)
        host_unicode = (parsed.hostname or "").lower().rstrip(".")
        host = host_unicode.encode("idna").decode("ascii") if host_unicode else ""
    except (ValueError, UnicodeError):
        return {"url": url, "valid": False, "risk_points": 20, "signals": ["Malformed URL"]}
    psl = registrable_domain(host)
    signals: list[str] = []; points = 0
    if parsed.scheme != "https": signals.append("No HTTPS"); points += 6
    if parsed.username or parsed.password: signals.append("Credentials or deceptive @ syntax in URL"); points += 20
    try: ipaddress.ip_address(host.strip("[]")); signals.append("Uses an IP address instead of a domain"); points += 12
    except ValueError: pass
    if host in SHORTENERS: signals.append("Shortened URL conceals destination"); points += 10
    if psl["public_suffix"].split(".")[-1] in SUSPICIOUS_TLDS: signals.append(f"Higher-abuse-risk .{psl['public_suffix'].split('.')[-1]} domain ending"); points += 7
    if "xn--" in host: signals.append("Internationalized/punycode hostname"); points += 8
    if host.count(".") >= 4: signals.append("Many hostname levels"); points += 5
    if len(candidate) > 180: signals.append("Unusually long URL"); points += 5
    if re.search(r"(?i)(?:login|verify|wallet|bonus|claim|career|job|invest).{0,18}(?:secure|support|official)", host + parsed.path): signals.append("Trust or financial lure terms in URL"); points += 7
    brands = brand_impersonation(host)
    if brands: signals.append("Domain resembles a known brand but is not an expected official domain"); points += 22
    return {"url": candidate, "valid": bool(host and ("." in host or psl["valid"])), "host": host, "unicode_host": host_unicode, "scheme": parsed.scheme, **psl, "brand_findings": brands, "risk_points": min(points, 40), "signals": signals}


def _public_ips(host: str) -> tuple[list[str], str | None]:
    try:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        if not ips: return [], "Domain did not resolve"
        if any(not ipaddress.ip_address(x).is_global for x in ips): return [], "Blocked non-public address"
        return ips, None
    except (OSError, ValueError): return [], "Domain did not resolve"


def online_domain_check(host: str) -> dict:
    """Optional direct DNS/TLS checks; never calls a reputation or RDAP API."""
    host = registrable_domain(host)["registrable_domain"]
    if not host: return {"enabled": True, "error": "Invalid domain"}
    ips, error = _public_ips(host)
    result = dns_email_domain_analysis(host); result.update({"host": host, "ips": ips})
    if error: result["resolution_error"] = error
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure: cert = secure.getpeercert()
        result["tls"] = {"ok": True, "expires": cert.get("notAfter", ""), "issuer": dict(x[0] for x in cert.get("issuer", []))}
    except (OSError, ssl.SSLError): result["tls"] = {"ok": False}
    result["privacy"] = "Direct DNS/TLS only; message content is not transmitted."
    result["warnings"] = [error] if error else []
    return result


def _coerce_messages(text: str, messages: list[dict] | None) -> list[dict]:
    if messages:
        out = []
        for i, item in enumerate(messages[:200]):
            if not isinstance(item, dict): continue
            body = str(item.get("text", ""))[:20_000]
            if body.strip(): out.append({"index": i + 1, "sender": _clip(str(item.get("sender", "Unknown")), 60), "text": body, "timestamp": _clip(str(item.get("timestamp", "")), 60)})
        return out
    parsed = []
    for line in str(text).splitlines():
        match = re.match(r"\s*(?:\[([^\]]+)\]\s*)?([\w .+()-]{1,40})\s*:\s*(.+)", line)
        if match: parsed.append({"index": len(parsed)+1, "sender": match.group(2).strip(), "text": match.group(3).strip(), "timestamp": (match.group(1) or "").strip()})
    return parsed if len(parsed) >= 2 else [{"index": 1, "sender": "Input", "text": text, "timestamp": ""}]


STAGES = (("unsolicited_contact", r"(?:random|found your (?:number|profile)|recruiter|job opportunity|work from home|whatsapp|telegram)"), ("easy_task", r"(?:like|review|boost|subscribe|simple task|survey|order task)"), ("trust_payment", r"(?:first|small|test|initial).{0,25}(?:payment|payout|commission|withdrawal|profit)"), ("deposit", r"(?:deposit|top[ -]?up|recharge|prepay|transfer|usdt|paynow)"), ("problem", r"(?:negative balance|mistake|wrong task|frozen|tax|fee|upgrade|vip|unlock)"), ("exit_block", r"(?:withdraw|release|refund).{0,35}(?:fee|tax|deposit|blocked|pending|unlock)"))


def analyze_conversation(messages: list[dict]) -> dict:
    timeline = []; stage_positions = {}
    for msg in messages:
        value = normalize(msg["text"]).lower(); matched = [stage for stage, pattern in STAGES if re.search(pattern, value, re.I)]
        if matched:
            timeline.append({"message": msg["index"], "sender": msg["sender"], "timestamp": msg["timestamp"], "stages": matched, "excerpt": _clip(msg["text"], 150)})
            for stage in matched: stage_positions.setdefault(stage, msg["index"])
    ordered = [x for x, _ in STAGES if x in stage_positions]; indices = [stage_positions[x] for x in ordered]
    monotonic = sum(a <= b for a, b in zip(indices, indices[1:])); escalation = min(30, len(ordered) * 4 + monotonic * 2)
    return {"message_count": len(messages), "stages": ordered, "timeline": timeline, "escalation_score": escalation, "pattern": " -> ".join(ordered) if ordered else "No staged pattern detected"}


def _risk_band(score: int, abstained: bool, strong_rule: bool) -> tuple[str, str]:
    if abstained and not strong_rule: return "Needs review", "The local model abstained and no decisive rule resolved the case."
    if score >= 75: return "Critical", "Multiple strong indicators or a decisive high-harm pattern were detected."
    if score >= 50: return "High", "Strong scam indicators were detected."
    if score >= 25: return "Elevated", "Meaningful warning signs require independent verification."
    return "Low", "No strong indicator was found, but this is not proof of legitimacy."


def analyze(text: str, source_url: str = "", online_checks: bool = False, messages: list[dict] | None = None, claimed_company: str = "", claimed_domain: str = "", recruiter_email: str = "", claimed_license: str = "") -> dict:
    original_text = str(text or "")
    original_url = str(source_url or "")
    norm = normalize_detailed(original_text); value = norm.normalized
    conversation = analyze_conversation(_coerce_messages(text, messages)); findings = []; raw_rule_points = 0
    folded = fold_for_matching(value)
    folded_de = fold_german(folded)  # ae/oe/ue as well, for German typed without umlauts
    for rule in RULES:
        subject = (folded_de if rule.id.startswith("de_") else folded) if rule.fold else value
        match = re.search(rule.pattern, subject, flags=re.I | re.S)
        if not match or _negated_or_educational(rule.id, subject, match): continue
        # Latin folding keeps offsets, so the evidence shown is the message as it was written, accents and all.
        shown = value if len(subject) == len(value) else subject
        findings.append({"id": rule.id, "category": rule.category, "title": rule.title, "severity": rule.severity, "weight": rule.weight, "evidence": _evidence(shown, match), "explanation": rule.explanation, "action": rule.action}); raw_rule_points += rule.weight
    entities = extract_entities(value)
    if source_url and source_url not in entities["urls"]: entities["urls"].insert(0, source_url)
    url_analysis = [inspect_url(x) for x in entities["urls"][:10]]
    email_analysis = [email_domain_analysis(x, claimed_domain) for x in entities["emails"][:10]]
    if recruiter_email and recruiter_email not in entities["emails"]: email_analysis.insert(0, email_domain_analysis(recruiter_email, claimed_domain))
    url_points = min(28, sum(x.get("risk_points", 0) for x in url_analysis)); identity_points = min(25, sum(x.get("risk_points", 0) for x in email_analysis)); unicode_points = 7 if norm.suspicious_unicode else 0
    ml = predict(value, original_text); model_points = 0 if ml["abstained"] else round(ml["calibrated_score"] * 28); strong_rule = any(x["severity"] == "critical" for x in findings)
    # The classifier is trained on a few dozen sentences and is badly over-confident off that narrow style: it rates a plain
    # delivery notice or invoice reminder as a near-certain scam. With no rule matched it is the only evidence, so it may not
    # lift a message out of "Low" on its own.
    model_uncorroborated = not findings and model_points > UNCORROBORATED_MODEL_CAP
    if not findings: model_points = min(model_points, UNCORROBORATED_MODEL_CAP)
    rule_component = min(68, round(72 * (1 - pow(2.718281828, -raw_rule_points / 70))))
    total = min(100, rule_component + url_points + identity_points + unicode_points + conversation["escalation_score"] + model_points)
    band, summary = _risk_band(total, ml["abstained"], strong_rule)
    live = [online_domain_check(x["host"]) for x in url_analysis if online_checks and x.get("host")][:3]
    verification = verification_workflow(claimed_company, claimed_domain, recruiter_email, claimed_license)
    actions = list(dict.fromkeys(x["action"] for x in findings))[:6] or ["Verify the sender and offer through independently located official channels before acting."]
    primary = findings[0]["category"] if findings else "No decisive pattern"
    level = {"Critical": "critical", "High": "high", "Elevated": "caution", "Low": "low", "Needs review": "review"}[band]
    warnings = [x.get("resolution_error") for x in live if x.get("resolution_error")]
    result = {"product": "NexVision OSINT Job & Investment Scam Checker", "version": "2.0.0", "generated_at": datetime.now(timezone.utc).isoformat(), "risk_score": total, "risk_band": band, "summary": summary, "findings": findings, "recommended_actions": actions, "evidence_input": {"message": original_text, "source_url": original_url}, "normalization": norm.to_dict(), "conversation": conversation, "entities": entities, "url_analysis": url_analysis, "email_analysis": email_analysis, "verification": verification, "local_classifier": ml, "fusion": {"rule_points_raw": raw_rule_points, "rule_component": rule_component, "url_component": url_points, "identity_component": identity_points, "unicode_component": unicode_points, "conversation_component": conversation["escalation_score"], "model_component": model_points, "model_uncorroborated": model_uncorroborated, "method": "Conservative bounded additive fusion with diminishing rule returns"}, "online_checks": live, "online_checks_enabled": bool(online_checks), "privacy": "Core analysis is local. Optional live mode uses direct DNS/TLS only; it does not use paid/professional APIs or upload message content.", "limitations": ["A low score is not proof of legitimacy.", "Risk bands are decision-support labels, not real-world fraud probabilities.", "Human verification with official registries and the claimed organization remains necessary."], "rules_version": RULES_VERSION, "input_sha256": hashlib.sha256(original_text.encode("utf-8", "replace")).hexdigest()}
    # Stable v1 aliases for integrations while v2 clients migrate.
    result["verdict"] = {"score": total, "label": band, "level": level, "primary_pattern": primary}
    result["recommendations"] = actions
    result["warnings"] = warnings
    return result

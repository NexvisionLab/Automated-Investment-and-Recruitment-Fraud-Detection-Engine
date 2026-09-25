"""Offline-first domain, email and brand intelligence.

Core parsing uses a vendored Mozilla Public Suffix List. Optional DNS queries
go directly to the machine's configured resolver; no commercial reputation API
or cloud AI service is used.
"""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import urllib.parse
from functools import lru_cache
from pathlib import Path

from normalization import normalize

ROOT = Path(__file__).resolve().parent
PSL_PATH = ROOT / "data" / "public_suffix_list.dat"

BRANDS = {
    "dbs": {"dbs.com", "dbs.com.sg"}, "posb": {"posb.com.sg"},
    "ocbc": {"ocbc.com", "ocbc.com.sg"}, "uob": {"uobgroup.com", "uob.com.sg"},
    "mas": {"mas.gov.sg"}, "scamshield": {"scamshield.gov.sg"},
    "amazon": {"amazon.com", "amazon.sg"}, "shopee": {"shopee.sg"},
    "lazada": {"lazada.sg"}, "grab": {"grab.com"}, "tiktok": {"tiktok.com"},
    "youtube": {"youtube.com", "google.com"}, "indeed": {"indeed.com"},
    "linkedin": {"linkedin.com"}, "coinbase": {"coinbase.com"},
    "binance": {"binance.com"}, "interactive brokers": {"interactivebrokers.com"},
}


@lru_cache(maxsize=1)
def _psl() -> tuple[set[str], set[str], set[str]]:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in PSL_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        line = line.lower()
        if line.startswith("!"):
            exception.add(line[1:])
        elif line.startswith("*."):
            wildcard.add(line[2:])
        else:
            exact.add(line)
    return exact, wildcard, exception


def registrable_domain(host: str) -> dict:
    raw = (host or "").strip().strip(".").lower()
    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return {"host": raw, "valid": False, "registrable_domain": "", "public_suffix": ""}
    try:
        ipaddress.ip_address(ascii_host)
        return {"host": ascii_host, "valid": True, "registrable_domain": ascii_host, "public_suffix": ""}
    except ValueError:
        pass
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(not x for x in labels):
        return {"host": ascii_host, "valid": False, "registrable_domain": "", "public_suffix": ""}
    exact, wildcard, exception = _psl()
    suffix_len = 1
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            suffix_len = len(labels) - i - 1
            break
        if candidate in exact:
            suffix_len = max(suffix_len, len(labels) - i)
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wildcard:
            suffix_len = max(suffix_len, len(labels) - i)
    suffix = ".".join(labels[-suffix_len:])
    reg = ".".join(labels[-(suffix_len + 1):]) if len(labels) > suffix_len else ascii_host
    return {"host": ascii_host, "valid": True, "registrable_domain": reg, "public_suffix": suffix}


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        row = [i]
        for j, cb in enumerate(b, 1):
            row.append(min(row[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = row
    return prev[-1]


def brand_impersonation(host: str) -> list[dict]:
    parsed = registrable_domain(host)
    reg = parsed["registrable_domain"]
    if not reg:
        return []
    label = reg.split(".")[0].replace("-", "")
    findings = []
    for brand, official in BRANDS.items():
        compact = brand.replace(" ", "")
        claimed = compact in label or _distance(label, compact) <= (1 if len(compact) < 7 else 2)
        if claimed and reg not in official:
            findings.append({
                "brand": brand.title(), "domain": reg, "official_domains": sorted(official),
                "signal": "Brand-like domain is not an expected official domain", "risk_points": 22,
            })
    return findings


def email_domain_analysis(email: str, claimed_domain: str = "") -> dict:
    match = re.fullmatch(r"[^@\s]+@([^@\s]+)", normalize(email).strip())
    if not match:
        return {"email": email, "valid": False, "signals": ["Malformed email address"], "risk_points": 8}
    domain = match.group(1).lower().strip(".")
    parsed = registrable_domain(domain)
    signals: list[str] = []
    points = 0
    free_mail = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com"}
    if parsed["registrable_domain"] in free_mail:
        signals.append("Recruiter uses a public/free-mail domain")
        points += 10
    if claimed_domain:
        expected = registrable_domain(urllib.parse.urlsplit("//" + claimed_domain, scheme="https").hostname or claimed_domain)
        if expected["registrable_domain"] and expected["registrable_domain"] != parsed["registrable_domain"]:
            signals.append("Recruiter email domain does not match the claimed company domain")
            points += 22
    brands = brand_impersonation(domain)
    if brands:
        signals.append("Email domain resembles a known brand without matching its expected domain")
        points += 22
    return {"email": email, "valid": parsed["valid"], "domain": domain, **parsed, "brand_findings": brands,
            "signals": signals, "risk_points": min(points, 35)}


def _first_ipv4(text: str) -> str | None:
    for token in re.split(r"[\s,;]+", text):
        try:
            if ipaddress.ip_address(token).version == 4:
                return token
        except ValueError:
            continue
    return None


def _windows_resolvers() -> list[str]:
    """IPv4 DNS servers from the Windows TCP/IP interface settings (standard library only).

    The registry lists every interface, including inactive ones, so callers try them in order.
    """
    try:
        import winreg
    except ImportError:
        return []
    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    found: list[str] = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as interfaces:
            for index in range(winreg.QueryInfoKey(interfaces)[0]):
                with winreg.OpenKey(interfaces, winreg.EnumKey(interfaces, index)) as interface:
                    for value_name in ("NameServer", "DhcpNameServer"):
                        try:
                            value = str(winreg.QueryValueEx(interface, value_name)[0])
                        except OSError:
                            continue
                        found.extend(token for token in re.split(r"[\s,;]+", value) if _first_ipv4(token) == token)
    except OSError:
        pass
    return found


def _resolvers() -> list[str]:
    """The machine's configured resolvers, as the module documentation promises.

    Order: NEXVISION_DNS_RESOLVER override, /etc/resolv.conf, the Windows registry.
    Only if none can be read does it fall back to a public resolver (1.1.1.1),
    which is then the one place a queried domain name leaves the local network path.
    """
    override = os.environ.get("NEXVISION_DNS_RESOLVER", "").strip()
    if override and _first_ipv4(override) == override:
        return [override]
    found: list[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.startswith("nameserver "):
                value = _first_ipv4(line.split(None, 1)[1])
                if value:
                    found.append(value)
    except OSError:
        pass
    found.extend(_windows_resolvers())
    unique = list(dict.fromkeys(found))
    return unique or ["1.1.1.1"]


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode("idna") for x in name.rstrip(".").split(".")) + b"\0"


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("truncated DNS name")


def dns_query(name: str, qtype: int, timeout: float = 2.0) -> dict:
    """Minimal UDP DNS query for MX(15), TXT(16), NS(2), A(1), trying up to three configured resolvers."""
    result: dict = {"ok": False, "answers": [], "error": "NoResolver"}
    for resolver in _resolvers()[:3]:
        result = _dns_query_once(resolver, name, qtype, timeout)
        if result["ok"]:
            break
    return result


def _dns_query_once(resolver: str, name: str, qtype: int, timeout: float) -> dict:
    ident = secrets.randbits(16)
    packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", qtype, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver, 53))
        data, sender = sock.recvfrom(65535)
        if sender[0] != resolver:
            raise ValueError("DNS response from an unexpected address")
        rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
        if rid != ident:
            raise ValueError("DNS response mismatch")
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        records = []
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10]); off += 10
            rdata = data[off:off + rdlen]; off += rdlen
            if rtype == qtype:
                if qtype == 1 and len(rdata) == 4:
                    records.append(socket.inet_ntoa(rdata))
                elif qtype == 16:
                    pos, parts = 0, []
                    while pos < len(rdata):
                        n = rdata[pos]; pos += 1; parts.append(rdata[pos:pos+n].decode("utf-8", "replace")); pos += n
                    records.append("".join(parts))
                else:
                    records.append(rdata.hex())
        return {"ok": True, "rcode": flags & 0xF, "answers": records}
    except (OSError, ValueError, struct.error) as exc:
        return {"ok": False, "answers": [], "error": type(exc).__name__}
    finally:
        sock.close()


def dns_email_domain_analysis(domain: str) -> dict:
    """Explicitly invoked live check. It calls only the configured DNS resolver."""
    parsed = registrable_domain(domain)
    target = parsed["registrable_domain"]
    if not target:
        return {"enabled": True, "error": "Invalid domain"}
    try:
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(target, 443, type=socket.SOCK_STREAM)})
    except OSError:
        addresses = []
    mx = dns_query(target, 15)
    txt = dns_query(target, 16)
    dmarc = dns_query("_dmarc." + target, 16)
    spf = [v for v in txt.get("answers", []) if v.lower().startswith("v=spf1")]
    dmarc_records = [v for v in dmarc.get("answers", []) if v.lower().startswith("v=dmarc1")]
    signals = []
    if not addresses:
        signals.append("No web address record resolved")
    if mx.get("ok") and not mx.get("answers"):
        signals.append("No MX answer found")
    if txt.get("ok") and not spf:
        signals.append("No SPF record observed")
    if dmarc.get("ok") and not dmarc_records:
        signals.append("No DMARC record observed")
    return {"enabled": True, "domain": target, "addresses": addresses, "mx": mx, "spf": spf,
            "dmarc": dmarc_records, "signals": signals,
            "limitations": "DNS presence is not proof of legitimacy; absence may be benign. UDP replies may be truncated."}


def verification_workflow(claimed_company: str = "", claimed_domain: str = "", recruiter_email: str = "", claimed_license: str = "") -> dict:
    checks = []
    if claimed_company:
        checks.append({"status": "manual", "check": "Confirm the exact legal entity in the relevant company registry", "value": claimed_company})
    if claimed_license:
        checks.append({"status": "manual", "check": "Search the regulator's official register for this exact licence/reference", "value": claimed_license})
    if claimed_domain:
        checks.append({"status": "manual", "check": "Open the official register/company record independently and compare its published domain", "value": claimed_domain})
    email = email_domain_analysis(recruiter_email, claimed_domain) if recruiter_email else None
    if email:
        checks.append({"status": "warning" if email["risk_points"] else "reviewed", "check": "Compare recruiter email and claimed company domains", "value": recruiter_email, "signals": email["signals"]})
    checks.extend([
        {"status": "manual", "check": "Call a published switchboard number, not a number supplied in the message", "value": ""},
        {"status": "manual", "check": "Confirm the vacancy, representative, payment beneficiary, and licence separately", "value": ""},
    ])
    return {
        "checks": checks,
        "official_sources": [
            {"name": "Singapore MAS Financial Institutions Directory", "url": "https://eservices.mas.gov.sg/fid"},
            {"name": "Singapore MAS Investor Alert List", "url": "https://www.mas.gov.sg/investor-alert-list"},
            {"name": "Singapore ACRA BizFile", "url": "https://www.bizfile.gov.sg"},
            {"name": "Singapore ScamShield", "url": "https://www.scamshield.gov.sg"},
            {"name": "ICANN Lookup", "url": "https://lookup.icann.org"},
        ],
        "note": "Links are references for the investigator. This checker does not submit your evidence to them or call their APIs.",
    }

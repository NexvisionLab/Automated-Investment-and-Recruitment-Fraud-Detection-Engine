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


# Financial regulator, company registry and scam-reporting references by country (ISO 3166-1
# alpha-2). Each entry was individually verified against the agency's own site or recent official
# coverage, not guessed - these are links an investigator may actually click and trust, so a wrong
# or stale one is worse than no entry at all. Add a country only once its links are verified the
# same way; an unlisted country still gets _GLOBAL_SOURCES, never a blank list.
_COUNTRY_SOURCES = {
    "SG": {"name": "Singapore", "sources": [
        {"name": "Singapore MAS Financial Institutions Directory", "url": "https://eservices.mas.gov.sg/fid"},
        {"name": "Singapore MAS Investor Alert List", "url": "https://www.mas.gov.sg/investor-alert-list"},
        {"name": "Singapore ACRA BizFile", "url": "https://www.bizfile.gov.sg"},
        {"name": "Singapore ScamShield", "url": "https://www.scamshield.gov.sg"},
    ]},
    "US": {"name": "United States", "sources": [
        {"name": "SEC Investor.gov - Check Out Your Investment Professional",
         "url": "https://www.investor.gov/introduction-investing/getting-started/working-investment-professional/check-out-your-investment-professional"},
        {"name": "FTC - Report Fraud", "url": "https://reportfraud.ftc.gov"},
        {"name": "FBI IC3 - Internet Crime Complaint Center", "url": "https://www.ic3.gov"},
    ]},
    "GB": {"name": "United Kingdom", "sources": [
        {"name": "FCA Financial Services Register", "url": "https://www.fca.org.uk/firms/financial-services-register"},
        {"name": "Companies House - Find a Company", "url": "https://find-and-update.company-information.service.gov.uk"},
        {"name": "Action Fraud", "url": "https://www.actionfraud.police.uk"},
    ]},
    "AU": {"name": "Australia", "sources": [
        {"name": "ASIC MoneySmart - Check ASIC Lists", "url": "https://www.moneysmart.gov.au/tools-and-resources/check-asic-lists"},
        {"name": "Scamwatch - Report a Scam", "url": "https://www.scamwatch.gov.au/report-a-scam"},
        {"name": "ReportCyber (Australian Cyber Security Centre)", "url": "https://www.cyber.gov.au"},
    ]},
    "CA": {"name": "Canada", "sources": [
        {"name": "Canadian Securities Administrators - National Registration Search", "url": "https://www.securities-administrators.ca"},
        {"name": "Canadian Anti-Fraud Centre", "url": "https://antifraudcentre-centreantifraude.ca"},
    ]},
    "MY": {"name": "Malaysia", "sources": [
        {"name": "Bank Negara Malaysia - Financial Consumer Alert", "url": "https://www.bnm.gov.my/fca"},
        {"name": "SSM Company Search", "url": "https://www.ssm.com.my"},
        {"name": "National Scam Response Centre (997)",
         "url": "https://www.malaysia.gov.my/en/categories/safety-and-community/cybersecurity/nsrc-997-hotline"},
    ]},
    "IN": {"name": "India", "sources": [
        {"name": "SEBI SCORES - Investor Complaints", "url": "https://scores.sebi.gov.in"},
        {"name": "MCA Company Search", "url": "https://www.mca.gov.in"},
        {"name": "National Cyber Crime Reporting Portal", "url": "https://cybercrime.gov.in"},
    ]},
    "ID": {"name": "Indonesia", "sources": [
        {"name": "OJK (Financial Services Authority)", "url": "https://www.ojk.go.id"},
        {"name": "AHU Online - Company Search", "url": "https://ahu.go.id/pencarian/profil-pt"},
        {"name": "Polri (Indonesian National Police)", "url": "https://www.polri.go.id"},
    ]},
    "PH": {"name": "Philippines", "sources": [
        {"name": "SEC Philippines", "url": "https://www.sec.gov.ph"},
        {"name": "PNP (Philippine National Police)", "url": "https://www.pnp.gov.ph"},
    ]},
    "DE": {"name": "Germany", "sources": [
        {"name": "BaFin (Federal Financial Supervisory Authority)", "url": "https://www.bafin.de"},
        {"name": "Handelsregister - Company Register", "url": "https://www.handelsregister.de"},
        {"name": "Verbraucherzentrale Fakeshop-Finder", "url": "https://www.verbraucherzentrale.de/fakeshopfinder-71560"},
        {"name": "Bundeskriminalamt (Federal Criminal Police Office)", "url": "https://www.bka.de"},
    ]},
    "FR": {"name": "France", "sources": [
        {"name": "AMF - Listes noires et mises en garde", "url": "https://www.amf-france.org/fr/espace-epargnants/proteger-son-epargne/listes-noires-et-mises-en-garde"},
        {"name": "ABE Infoservice - Listes noires et alertes", "url": "https://www.abe-infoservice.fr/liste-noire/listes-noires-et-alertes-des-autorites"},
        {"name": "Infogreffe - Company Register", "url": "https://www.infogreffe.fr"},
        {"name": "PHAROS - Report Illicit Online Content", "url": "https://www.internet-signalement.gouv.fr"},
    ]},
    "IT": {"name": "Italy", "sources": [
        {"name": "CONSOB", "url": "https://www.consob.it"},
        {"name": "Registro Imprese - Company Register", "url": "https://www.registroimprese.it"},
        {"name": "Polizia Postale - Report Online Fraud", "url": "https://www.commissariatodips.it"},
    ]},
    "ES": {"name": "Spain", "sources": [
        {"name": "CNMV", "url": "https://www.cnmv.es"},
        {"name": "INCIBE", "url": "https://www.incibe.es"},
        {"name": "OSI - Oficina de Seguridad del Internauta", "url": "https://www.osi.es"},
        {"name": "Policía Nacional", "url": "https://www.policia.es"},
    ]},
    "NL": {"name": "Netherlands", "sources": [
        {"name": "AFM (Authority for the Financial Markets)", "url": "https://www.afm.nl"},
        {"name": "KVK Company Search", "url": "https://www.kvk.nl/zoeken"},
        {"name": "Fraudehelpdesk", "url": "https://www.fraudehelpdesk.nl"},
        {"name": "Politie (Dutch Police)", "url": "https://www.politie.nl"},
    ]},
    "CN": {"name": "China", "sources": [
        {"name": "National Enterprise Credit Information Publicity System", "url": "https://www.gsxt.gov.cn"},
        {"name": "CSRC (China Securities Regulatory Commission)", "url": "https://www.csrc.gov.cn"},
        {"name": "12377 - China Internet Illegal Information Reporting Center", "url": "https://www.12377.cn"},
    ]},
    "JP": {"name": "Japan", "sources": [
        {"name": "FSA - Licensed Financial Institutions List", "url": "https://www.fsa.go.jp/en/regulated/licensed/index.html"},
        {"name": "National Police Agency", "url": "https://www.npa.go.jp"},
    ]},
    "KR": {"name": "South Korea", "sources": [
        {"name": "FSS (Financial Supervisory Service)", "url": "https://www.fss.or.kr"},
        {"name": "DART - Electronic Disclosure System", "url": "https://dart.fss.or.kr"},
        {"name": "National Police Agency", "url": "https://www.police.go.kr"},
    ]},
    "TH": {"name": "Thailand", "sources": [
        {"name": "SEC Thailand", "url": "https://www.sec.or.th"},
        {"name": "DBD (Department of Business Development)", "url": "https://www.dbd.go.th"},
        {"name": "Royal Thai Police Online (Report a Scam)", "url": "https://www.thaipoliceonline.go.th"},
    ]},
    "VN": {"name": "Vietnam", "sources": [
        {"name": "State Securities Commission of Vietnam", "url": "https://www.ssc.gov.vn"},
        {"name": "Ministry of Public Security", "url": "https://en.mps.gov.vn"},
    ]},
    "NG": {"name": "Nigeria", "sources": [
        {"name": "SEC Nigeria - Scammer Alert", "url": "https://sec.gov.ng/for-investors/keep-track-of-circulars/scammer-alert/"},
        {"name": "CAC (Corporate Affairs Commission)", "url": "https://www.cac.gov.ng"},
        {"name": "EFCC (Economic and Financial Crimes Commission)", "url": "https://www.efccnigeria.org"},
    ]},
    "ZA": {"name": "South Africa", "sources": [
        {"name": "FSCA (Financial Sector Conduct Authority)", "url": "https://www.fsca.co.za"},
        {"name": "CIPC - Company Search", "url": "https://www.cipc.co.za"},
        {"name": "SAPS (South African Police Service)", "url": "https://www.saps.gov.za"},
    ]},
    "BR": {"name": "Brazil", "sources": [
        {"name": "CVM (Comissão de Valores Mobiliários)", "url": "https://www.cvm.gov.br"},
        {"name": "Portal do Investidor", "url": "https://www.portaldoinvestidor.gov.br"},
        {"name": "Polícia Federal", "url": "https://www.gov.br/pf"},
    ]},
    "MX": {"name": "Mexico", "sources": [
        {"name": "CNBV (Comisión Nacional Bancaria y de Valores)", "url": "https://www.gob.mx/cnbv"},
        {"name": "CONDUSEF", "url": "https://www.gob.mx/condusef"},
        {"name": "Guardia Nacional", "url": "https://www.gob.mx/guardianacional"},
    ]},
    "NZ": {"name": "New Zealand", "sources": [
        {"name": "FMA - Warnings and Alerts", "url": "https://www.fma.govt.nz/library/warnings-and-alerts"},
        {"name": "New Zealand Companies Register", "url": "https://www.companiesoffice.govt.nz"},
        {"name": "Netsafe", "url": "https://www.netsafe.org.nz"},
        {"name": "New Zealand Police - Report Fraud", "url": "https://www.police.govt.nz"},
    ]},
    "HK": {"name": "Hong Kong", "sources": [
        {"name": "SFC Alert List", "url": "https://www.sfc.hk/en/alert-list"},
        {"name": "Companies Registry", "url": "https://www.cr.gov.hk"},
        {"name": "Hong Kong Police Force", "url": "https://www.police.gov.hk"},
    ]},
    "SA": {"name": "Saudi Arabia", "sources": [
        {"name": "CMA - Unlicensed Companies List", "url": "https://cma.gov.sa/en/Awareness/Pages/ForexN.aspx"},
        {"name": "Absher - Report Cybercrime", "url": "https://www.absher.sa"},
    ]},
    "TR": {"name": "Turkey", "sources": [
        {"name": "SPK (Capital Markets Board)", "url": "https://spk.gov.tr"},
        {"name": "İhbarWeb - Internet Information Reporting Center", "url": "https://www.ihbarweb.org.tr"},
    ]},
    "PK": {"name": "Pakistan", "sources": [
        {"name": "SECP (Securities and Exchange Commission of Pakistan)", "url": "https://www.secp.gov.pk"},
        {"name": "FIA NR3C (National Response Centre for Cyber Crime)", "url": "https://www.nr3c.gov.pk"},
    ]},
    "BD": {"name": "Bangladesh", "sources": [
        {"name": "BSEC (Bangladesh Securities and Exchange Commission)", "url": "https://sec.gov.bd"},
        {"name": "CID - Cyber Police", "url": "https://cid.gov.bd"},
    ]},
    "CH": {"name": "Switzerland", "sources": [
        {"name": "FINMA (Swiss Financial Market Supervisory Authority)", "url": "https://www.finma.ch"},
        {"name": "Zefix - Central Business Names Index", "url": "https://www.zefix.ch"},
        {"name": "NCSC (National Cyber Security Centre) - Report an Incident", "url": "https://www.ncsc.admin.ch"},
    ]},
    "SE": {"name": "Sweden", "sources": [
        {"name": "Finansinspektionen - Investor Alerts", "url": "https://www.fi.se/en/our-registers/investor-alerts"},
        {"name": "Bolagsverket - Company Register", "url": "https://www.bolagsverket.se"},
        {"name": "Polisen (Swedish Police)", "url": "https://polisen.se"},
    ]},
    "IE": {"name": "Ireland", "sources": [
        {"name": "Central Bank of Ireland", "url": "https://www.centralbank.ie"},
        {"name": "CRO - Company Search", "url": "https://core.cro.ie"},
        {"name": "Garda - Cybercrime", "url": "https://www.garda.ie/cybercrime"},
    ]},
    "AR": {"name": "Argentina", "sources": [
        {"name": "CNV (Comisión Nacional de Valores)", "url": "https://www.cnv.gov.ar"},
    ]},
    "TW": {"name": "Taiwan", "sources": [
        {"name": "165 Anti-Fraud Hotline", "url": "https://165.npa.gov.tw"},
        {"name": "FSC (Financial Supervisory Commission)", "url": "https://www.fsc.gov.tw"},
    ]},
    "PL": {"name": "Poland", "sources": [
        {"name": "KNF - Public Warning List", "url": "https://www.knf.gov.pl/dla_konsumenta/ostrzezenia_publiczne"},
        {"name": "KRS - National Court Register Search", "url": "https://ekrs.ms.gov.pl"},
        {"name": "Policja (Polish Police)", "url": "https://www.policja.pl"},
    ]},
    "BE": {"name": "Belgium", "sources": [
        {"name": "FSMA (Financial Services and Markets Authority)", "url": "https://www.fsma.be"},
        {"name": "KBO Public Search - Company Register", "url": "https://kbopub.economie.fgov.be"},
        {"name": "Police - Report Fraud", "url": "https://www.police.be"},
    ]},
    "PT": {"name": "Portugal", "sources": [
        {"name": "CMVM (Comissão do Mercado de Valores Mobiliários)", "url": "https://www.cmvm.pt"},
        {"name": "Polícia Judiciária", "url": "https://www.policiajudiciaria.pt"},
    ]},
    "AT": {"name": "Austria", "sources": [
        {"name": "FMA (Financial Market Authority)", "url": "https://www.fma.gv.at"},
        {"name": "Watchlist Internet", "url": "https://www.watchlist-internet.at"},
        {"name": "Bundeskriminalamt (Federal Criminal Police Office)", "url": "https://www.bundeskriminalamt.at"},
    ]},
    "CL": {"name": "Chile", "sources": [
        {"name": "CMF (Comisión para el Mercado Financiero)", "url": "https://www.cmfchile.cl"},
        {"name": "PDI - Policía de Investigaciones", "url": "https://www.investigaciones.cl"},
    ]},
    "CO": {"name": "Colombia", "sources": [
        {"name": "Superintendencia Financiera de Colombia", "url": "https://www.superfinanciera.gov.co"},
        {"name": "CAI Virtual (Policía Nacional)", "url": "https://caivirtual.policia.gov.co"},
    ]},
    "KE": {"name": "Kenya", "sources": [
        {"name": "CMA (Capital Markets Authority)", "url": "https://www.cma.or.ke"},
        {"name": "DCI (Directorate of Criminal Investigations)", "url": "https://www.dci.go.ke"},
    ]},
    "EG": {"name": "Egypt", "sources": [
        {"name": "FRA (Financial Regulatory Authority)", "url": "https://fra.gov.eg"},
        {"name": "Ministry of Interior - Cybercrime Unit", "url": "https://moi.gov.eg"},
    ]},
    "RU": {"name": "Russia", "sources": [
        {"name": "Bank of Russia - Warning List", "url": "https://www.cbr.ru/inside/warning-list/"},
    ]},
    "IR": {"name": "Iran", "sources": [
        {"name": "SEO (Securities and Exchange Organization)", "url": "https://en.seo.ir"},
    ]},
}
_GLOBAL_SOURCES = [
    {"name": "ICANN Lookup (domain WHOIS)", "url": "https://lookup.icann.org"},
]


def verification_workflow(claimed_company: str = "", claimed_domain: str = "", recruiter_email: str = "", claimed_license: str = "",
                           country_code: str = "") -> dict:
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
    entry = _COUNTRY_SOURCES.get((country_code or "").strip().upper())
    note = "Links are references for the investigator. This checker does not submit your evidence to them or call their APIs."
    if not entry:
        note += " No country-specific list is available yet for your region; these are general references, alongside your own country's financial regulator and company registry."
    return {
        "checks": checks,
        "official_sources": (entry["sources"] if entry else []) + _GLOBAL_SOURCES,
        "region_label": entry["name"] if entry else "",
        "note": note,
    }

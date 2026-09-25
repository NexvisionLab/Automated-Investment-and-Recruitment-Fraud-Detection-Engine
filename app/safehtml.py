"""Safe static HTML inspection with optional SSRF-hardened direct fetching."""
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import html
import http.client
import ipaddress
import re
import socket
import ssl
import urllib.parse
from html.parser import HTMLParser

MAX_HTML = 600_000


class Inspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = []; self.text = []; self.forms = 0; self.passwords = 0; self.links = []; self.scripts = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title": self._in_title = True
        if tag == "form": self.forms += 1
        if tag == "script": self.scripts += 1
        if tag == "input" and (values.get("type") or "").lower() == "password": self.passwords += 1
        if tag in {"a", "link", "script", "img"}:
            value = values.get("href") or values.get("src")
            if value: self.links.append(value[:500])

    def handle_endtag(self, tag):
        if tag == "title": self._in_title = False

    def handle_data(self, data):
        if self._in_title: self.title.append(data)
        self.text.append(data)


def inspect_html(content: str, source_url: str = "") -> dict:
    parser = Inspector()
    parse_error = ""
    try: parser.feed(content[:MAX_HTML])
    except (AssertionError, ValueError) as exc: parse_error = type(exc).__name__
    visible = re.sub(r"\s+", " ", " ".join(parser.text)).strip()
    lower = visible.lower(); signals = []; points = 0
    patterns = [
        (r"(?:guaranteed|assured).{0,20}(?:profit|return)|zero risk", "Guaranteed-return language", 18),
        (r"(?:pay|deposit|top up).{0,30}(?:unlock|withdraw|task|commission)", "Advance-fee language", 22),
        (r"(?:whatsapp|telegram).{0,25}(?:contact|support|agent)", "Chat-app-only contact", 8),
        (r"(?:download|install).{0,20}(?:apk|unknown sources)", "Off-store application prompt", 25),
        (r"(?:wallet address|usdt|bitcoin|crypto).{0,30}(?:pay|deposit|send)", "Crypto payment prompt", 18),
    ]
    for pattern, label, weight in patterns:
        if re.search(pattern, lower): signals.append(label); points += weight
    if parser.passwords and not source_url.lower().startswith("https://"): signals.append("Password form without HTTPS source"); points += 15
    if parser.forms >= 3: signals.append("Multiple forms collect information"); points += 5
    return {"source_url": source_url, "title": re.sub(r"\s+", " ", "".join(parser.title)).strip()[:200],
            "forms": parser.forms, "password_fields": parser.passwords, "script_tags": parser.scripts,
            "links": parser.links[:30], "visible_text_excerpt": visible[:1000], "signals": signals,
            "risk_points": min(points, 45), "parse_error": parse_error,
            "safety": "Static parsing only; scripts are never executed."}


def _public_addresses(host: str, port: int) -> list[str]:
    addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError("URL does not resolve exclusively to public addresses")
    return addresses


def _read_response(sock: socket.socket) -> tuple[int, dict, bytes]:
    response = http.client.HTTPResponse(sock)
    try:
        response.begin()
        status = response.status; headers = {k.lower(): v for k, v in response.getheaders()}
        body = response.read(MAX_HTML + 1)
    finally:
        response.close()
    if len(body) > MAX_HTML: raise ValueError("HTML exceeds 600 KB safety limit")
    return status, headers, body


def fetch_and_inspect(url: str) -> dict:
    """Fetch one public HTTP(S) target and at most one public redirect.

    The connection is pinned to the DNS-vetted IP. This is direct webpage
    retrieval, not an API or reputation service.
    """
    current = url
    for redirect in range(2):
        parsed = urllib.parse.urlsplit(current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.port not in {None, 80, 443}:
            raise ValueError("Only public HTTP/HTTPS URLs on ports 80/443 are allowed")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ips = _public_addresses(parsed.hostname, port); raw = socket.create_connection((ips[0], port), timeout=5)
        conn = raw
        try:
            conn = ssl.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname) if parsed.scheme == "https" else raw
            path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            request = f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nUser-Agent: NexVision-SafeInspector/2.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode("ascii", "strict")); status, headers, body = _read_response(conn)
        finally:
            try: conn.close()
            except OSError: pass
        if status in {301, 302, 303, 307, 308} and redirect == 0:
            location = headers.get("location")
            if not location: break
            current = urllib.parse.urljoin(current, location); continue
        ctype = headers.get("content-type", "")
        if "html" not in ctype.lower(): raise ValueError("Target did not return HTML")
        charset = "utf-8"
        match = re.search(r"charset=([\w.-]+)", ctype, re.I)
        if match: charset = match.group(1)
        result = inspect_html(body.decode(charset, "replace"), current)
        result.update({"http_status": status, "content_type": ctype, "bytes_read": len(body), "resolved_ip": ips[0]})
        return result
    raise ValueError("Redirect could not be inspected safely")

# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
from __future__ import annotations

import argparse
import ipaddress
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from analyzer import analyze
from ocr_local import ocr_data_url
from reporting import html_report, pdf_report
from safehtml import fetch_and_inspect

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_BODY = 12_000_000


class Handler(BaseHTTPRequestHandler):
    server_version = "NexVisionScamChecker/2.0.0"

    def _trusted_host(self):
        value = self.headers.get("Host", "").strip()
        try:
            host = urlsplit("//" + value).hostname
            return host == "localhost" or (host is not None and ipaddress.ip_address(host).is_loopback)
        except ValueError:
            return False

    def _headers(self, status=200, content_type="application/json; charset=utf-8", length=None, disposition=None):
        self.send_response(status); self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer"); self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if disposition: self.send_header("Content-Disposition", disposition)
        if length is not None: self.send_header("Content-Length", str(length))
        self.end_headers()

    def _json(self, payload, status=200):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8"); self._headers(status, length=len(data)); self.wfile.write(data)

    def _payload(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY: raise OverflowError
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict): raise ValueError
        return value

    def do_POST(self):
        if not self._trusted_host(): return self._json({"error": "Untrusted Host header"}, 421)
        path = urlsplit(self.path).path
        try:
            payload = self._payload()
            if path == "/api/analyze":
                text = str(payload.get("text", ""))[:100_000]; source_url = str(payload.get("source_url", ""))[:2_000]
                ocr = None
                if payload.get("image_data"):
                    ocr = ocr_data_url(str(payload["image_data"]), str(payload.get("ocr_languages", "eng"))[:40])
                    if ocr.get("text"): text = (text + "\n\n[LOCAL OCR]\n" + ocr["text"]).strip()
                if not text.strip() and not source_url.strip(): return self._json({"error": "Paste a message, add a screenshot, or enter a URL"}, 400)
                result = analyze(text, source_url, bool(payload.get("online_checks", False)), payload.get("messages"), str(payload.get("claimed_company", ""))[:300], str(payload.get("claimed_domain", ""))[:500], str(payload.get("recruiter_email", ""))[:500], str(payload.get("claimed_license", ""))[:300])
                if ocr is not None: result["ocr"] = ocr
                if payload.get("inspect_html") and source_url:
                    try: result["html_inspection"] = fetch_and_inspect(source_url)
                    except Exception as exc: result["html_inspection"] = {"error": str(exc)[:300], "safety": "Fetch stopped safely"}
                return self._json(result)
            if path in {"/api/report/html", "/api/report/pdf"}:
                result = payload.get("result")
                if not isinstance(result, dict) or result.get("product") != "NexVision OSINT Job & Investment Scam Checker": return self._json({"error": "A valid analysis result is required"}, 400)
                if path.endswith("html"):
                    data = html_report(result); ctype = "text/html; charset=utf-8"; name = "nexvision-investigation-report.html"
                else:
                    data = pdf_report(result); ctype = "application/pdf"; name = "nexvision-investigation-report.pdf"
                self._headers(200, ctype, len(data), f'attachment; filename="{name}"'); self.wfile.write(data); return
            return self._json({"error": "Not found"}, 404)
        except OverflowError: return self._json({"error": "Request body must be between 1 byte and 12 MB"}, 413)
        except (json.JSONDecodeError, ValueError): return self._json({"error": "Invalid request"}, 400)
        except Exception as exc:
            self.log_error("Request failed safely: %s", type(exc).__name__)
            return self._json({"error": "Analysis failed safely; check the input and try again"}, 500)

    def do_GET(self):
        if not self._trusted_host(): return self._json({"error": "Untrusted Host header"}, 421)
        path = urlsplit(self.path).path
        if path == "/api/health": return self._json({"status": "ok", "version": "2.0.0", "offline_core": True, "professional_apis": False})
        if path == "/": path = "/index.html"
        target = (STATIC / path.lstrip("/")).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file(): return self._json({"error": "Not found"}, 404)
        data = target.read_bytes(); mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._headers(200, mime + ("; charset=utf-8" if mime.startswith("text/") or mime.endswith("javascript") else ""), len(data)); self.wfile.write(data)

    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description="NexVision OSINT Job & Investment Scam Checker")
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8787); args = parser.parse_args()
    try: loopback = args.host == "localhost" or ipaddress.ip_address(args.host).is_loopback
    except ValueError: loopback = False
    if not loopback: parser.error("--host must be a loopback address; this local application must not be exposed to a network")
    server = ThreadingHTTPServer((args.host, args.port), Handler); print(f"Checker running at http://{args.host}:{args.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__": main()

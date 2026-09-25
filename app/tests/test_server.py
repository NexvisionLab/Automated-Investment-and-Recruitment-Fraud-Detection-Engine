# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Handler, STATIC, ThreadingHTTPServer


class _StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.labels = []
        self.assets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if "id" in values:
            self.ids.append(values["id"])
        if tag == "label" and "for" in values:
            self.labels.append(values["for"])
        if tag == "script" and "src" in values:
            self.assets.append(values["src"])
        if tag == "link" and values.get("rel") == "stylesheet":
            self.assets.append(values.get("href", ""))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def post(self, payload=None, raw=None):
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base + "/api/analyze", data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, response.headers, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, error.headers, json.load(error)

    def test_health_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/api/health") as response:
            payload = json.load(response)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["version"], "2.0.0")
            self.assertFalse(payload["professional_apis"])
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])

    def test_dns_rebinding_host_is_rejected(self):
        request = urllib.request.Request(self.base + "/api/health", headers={"Host": "attacker.example"})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 421)

    def _raw_post(self, content_type, headers=None):
        request = urllib.request.Request(
            self.base + "/api/analyze", data=json.dumps({"text": "Pay a deposit to unlock your tasks"}).encode(),
            headers={"Content-Type": content_type, **(headers or {})}, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_cross_site_simple_request_is_rejected(self):
        # Regression: a page on another site can POST text/plain to 127.0.0.1 without a
        # CORS preflight; the server used to accept any Content-Type and any Origin.
        self.assertEqual(self._raw_post("text/plain"), 415)
        self.assertEqual(self._raw_post("application/x-www-form-urlencoded"), 415)

    def test_foreign_origin_is_rejected_and_same_origin_allowed(self):
        self.assertEqual(self._raw_post("application/json", {"Origin": "https://evil.example"}), 403)
        self.assertEqual(self._raw_post("application/json", {"Origin": self.base}), 200)
        self.assertEqual(self._raw_post("application/json"), 200)  # no Origin: curl / scripts

    def test_url_only_analysis(self):
        status, _, payload = self.post({"text": "", "source_url": "hxxps://bonus[.]xyz/login"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["url_analysis"][0]["host"], "bonus.xyz")

    def test_empty_and_bad_json_are_rejected(self):
        self.assertEqual(self.post({"text": "", "source_url": ""})[0], 400)
        self.assertEqual(self.post(raw=b"{bad json")[0], 400)

    def test_html_structure_and_local_assets(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        parser = _StructureParser()
        parser.feed(html)
        self.assertEqual(len(parser.ids), len(set(parser.ids)), "Duplicate HTML id")
        self.assertTrue(set(parser.labels).issubset(set(parser.ids)), "Label points to missing input")
        for asset in parser.assets:
            self.assertTrue((STATIC / asset.lstrip("/")).is_file(), f"Missing asset: {asset}")
        textarea_opening = html.split("<textarea", 1)[1].split(">", 1)[0]
        self.assertNotIn("required", textarea_opening)


if __name__ == "__main__":
    unittest.main()

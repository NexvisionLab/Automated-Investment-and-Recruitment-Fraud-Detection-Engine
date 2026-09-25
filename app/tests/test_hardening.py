# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression tests for the DNS resolver selection, DNS reply validation and OCR argument checks."""
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import domain_intel
import ocr_local


class FakeSocket:
    """Records what is sent and replays a canned DNS answer (A record 93.184.216.34)."""
    sent = []
    reply_from = None

    def __init__(self, *args, **kwargs):
        self.query = b""

    def settimeout(self, value):
        pass

    def sendto(self, packet, address):
        self.query = packet
        FakeSocket.sent.append((packet, address))
        self.address = address

    def recvfrom(self, size):
        ident = self.query[:2]
        question = self.query[12:]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        data = ident + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer
        return data, (FakeSocket.reply_from or self.address[0], 53)

    def close(self):
        pass


class ResolverTests(unittest.TestCase):
    def test_override_wins(self):
        with mock.patch.dict("os.environ", {"NEXVISION_DNS_RESOLVER": "9.9.9.9"}):
            self.assertEqual(domain_intel._resolvers(), ["9.9.9.9"])

    def test_invalid_override_is_ignored(self):
        with mock.patch.dict("os.environ", {"NEXVISION_DNS_RESOLVER": "not-an-ip"}):
            with mock.patch.object(domain_intel.Path, "read_text", side_effect=OSError), \
                    mock.patch.object(domain_intel, "_windows_resolvers", return_value=[]):
                self.assertEqual(domain_intel._resolvers(), ["1.1.1.1"])

    def test_configured_resolvers_are_used_before_any_public_fallback(self):
        # Regression: on Windows there is no /etc/resolv.conf, so the app silently queried
        # Cloudflare (1.1.1.1) instead of the machine's configured resolver.
        with mock.patch.dict("os.environ", {"NEXVISION_DNS_RESOLVER": ""}), \
                mock.patch.object(domain_intel.Path, "read_text", side_effect=OSError), \
                mock.patch.object(domain_intel, "_windows_resolvers", return_value=["10.0.0.2", "10.0.0.3", "10.0.0.2"]):
            self.assertEqual(domain_intel._resolvers(), ["10.0.0.2", "10.0.0.3"])

    def test_resolv_conf_ipv6_entries_are_skipped(self):
        text = "nameserver fe80::1\nnameserver 192.168.1.1\n"
        with mock.patch.dict("os.environ", {"NEXVISION_DNS_RESOLVER": ""}), \
                mock.patch.object(domain_intel.Path, "read_text", return_value=text), \
                mock.patch.object(domain_intel, "_windows_resolvers", return_value=[]):
            self.assertEqual(domain_intel._resolvers(), ["192.168.1.1"])

    def test_query_falls_through_to_the_next_resolver(self):
        calls = []

        def once(resolver, name, qtype, timeout):
            calls.append(resolver)
            return {"ok": resolver == "b", "answers": ["x"] if resolver == "b" else [], "error": "TimeoutError"}
        with mock.patch.object(domain_intel, "_resolvers", return_value=["a", "b", "c"]), \
                mock.patch.object(domain_intel, "_dns_query_once", side_effect=once):
            self.assertTrue(domain_intel.dns_query("example.test", 1)["ok"])
        self.assertEqual(calls, ["a", "b"])


class DnsReplyTests(unittest.TestCase):
    def setUp(self):
        FakeSocket.sent = []
        FakeSocket.reply_from = None

    def query(self):
        with mock.patch.object(domain_intel.socket, "socket", FakeSocket), \
                mock.patch.object(domain_intel, "_resolvers", return_value=["10.0.0.2"]):
            return domain_intel.dns_query("example.test", 1)

    def test_valid_reply_is_parsed(self):
        self.assertEqual(self.query()["answers"], ["93.184.216.34"])

    def test_reply_from_another_address_is_rejected(self):
        # A forged answer arriving from an address other than the resolver must not be trusted.
        FakeSocket.reply_from = "203.0.113.9"
        result = self.query()
        self.assertFalse(result["ok"])
        self.assertEqual(result["answers"], [])

    def test_transaction_id_is_not_constant(self):
        # Regression: the ID was hard-coded to 0x4E58, making off-path spoofing far easier.
        for _ in range(32):
            self.query()
        ids = {packet[:2] for packet, _ in FakeSocket.sent}
        self.assertGreater(len(ids), 1)


class OcrArgumentTests(unittest.TestCase):
    def test_language_argument_cannot_be_a_path_or_option(self):
        for bad in ("../../etc/x", "-l", "--config", "eng;calc", "eng eng", "", "a" * 64):
            with self.assertRaises(ValueError, msg=bad):
                ocr_local.ocr_data_url("data:image/png;base64,AAAA", bad)

    def test_normal_language_codes_are_accepted(self):
        for good in ("eng", "chi_sim", "eng+chi_sim+tam"):
            self.assertTrue(ocr_local.LANGUAGES.fullmatch(good), good)


if __name__ == "__main__":
    unittest.main()

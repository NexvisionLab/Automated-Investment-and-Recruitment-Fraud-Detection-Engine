# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""verification_workflow's country-specific "places to check" list - a listed country gets its own
curated sources plus the global references; an unlisted or unresolved country gets only the global
references, never an empty list or another country's sources."""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from domain_intel import _COUNTRY_SOURCES, _GLOBAL_SOURCES, verification_workflow  # noqa: E402


class VerificationWorkflowCountryTests(unittest.TestCase):
    def test_a_listed_country_gets_its_own_sources_plus_the_global_ones(self):
        result = verification_workflow(country_code="SG")
        self.assertEqual(result["region_label"], "Singapore")
        names = [s["name"] for s in result["official_sources"]]
        self.assertIn("Singapore ScamShield", names)
        for g in _GLOBAL_SOURCES:
            self.assertIn(g, result["official_sources"])

    def test_lowercase_and_whitespace_still_match(self):
        result = verification_workflow(country_code="  sg  ")
        self.assertEqual(result["region_label"], "Singapore")

    def test_an_unlisted_country_gets_only_the_global_sources_not_another_countrys(self):
        # Israel, UAE and Qatar are deliberately not curated yet - no official regulator URL
        # could be confirmed with reasonable confidence for any of them (UAE's regulator was
        # also mid-transition, SCA -> CMA, when this was researched). All three still fall back
        # to the global references, never another country's links.
        for code in ("IL", "AE", "QA"):
            result = verification_workflow(country_code=code)
            self.assertEqual(result["region_label"], "", code)
            self.assertEqual(result["official_sources"], _GLOBAL_SOURCES, code)
            self.assertIn("No country-specific list", result["note"])

    def test_every_major_eu_country_and_china_japan_added_round_2_resolves(self):
        for code, name in (("DE", "Germany"), ("FR", "France"), ("IT", "Italy"), ("ES", "Spain"),
                           ("NL", "Netherlands"), ("CN", "China"), ("JP", "Japan")):
            result = verification_workflow(country_code=code)
            self.assertEqual(result["region_label"], name, code)
            self.assertGreater(len(result["official_sources"]), len(_GLOBAL_SOURCES), code)

    def test_every_country_added_round_3_resolves(self):
        for code, name in (("KR", "South Korea"), ("TH", "Thailand"), ("VN", "Vietnam"), ("NG", "Nigeria"),
                           ("ZA", "South Africa"), ("BR", "Brazil"), ("MX", "Mexico"), ("NZ", "New Zealand"),
                           ("HK", "Hong Kong")):
            result = verification_workflow(country_code=code)
            self.assertEqual(result["region_label"], name, code)
            self.assertGreater(len(result["official_sources"]), len(_GLOBAL_SOURCES), code)

    def test_every_country_added_round_4_resolves(self):
        for code, name in (("SA", "Saudi Arabia"), ("TR", "Turkey"), ("PK", "Pakistan"), ("BD", "Bangladesh"),
                           ("CH", "Switzerland"), ("SE", "Sweden"), ("IE", "Ireland"), ("AR", "Argentina"),
                           ("TW", "Taiwan")):
            result = verification_workflow(country_code=code)
            self.assertEqual(result["region_label"], name, code)
            self.assertGreater(len(result["official_sources"]), len(_GLOBAL_SOURCES), code)

    def test_every_country_added_round_5_resolves(self):
        for code, name in (("PL", "Poland"), ("BE", "Belgium"), ("PT", "Portugal"), ("AT", "Austria"),
                           ("CL", "Chile"), ("CO", "Colombia"), ("KE", "Kenya"), ("EG", "Egypt"), ("RU", "Russia")):
            result = verification_workflow(country_code=code)
            self.assertEqual(result["region_label"], name, code)
            self.assertGreater(len(result["official_sources"]), len(_GLOBAL_SOURCES), code)

    def test_no_country_code_at_all_behaves_the_same_as_unlisted(self):
        result = verification_workflow()
        self.assertEqual(result["region_label"], "")
        self.assertEqual(result["official_sources"], _GLOBAL_SOURCES)

    def test_every_listed_country_has_at_least_one_source_and_a_name(self):
        for code, entry in _COUNTRY_SOURCES.items():
            self.assertTrue(entry.get("name"), code)
            self.assertTrue(entry.get("sources"), code)
            for s in entry["sources"]:
                self.assertTrue(s.get("name"), code)
                self.assertTrue(str(s.get("url", "")).startswith("https://"), (code, s))

    def test_the_sender_checks_are_unaffected_by_country(self):
        result = verification_workflow(claimed_company="Acme Pte Ltd", country_code="US")
        self.assertTrue(any(c["check"].startswith("Confirm the exact legal entity") for c in result["checks"]))


if __name__ == "__main__":
    unittest.main()

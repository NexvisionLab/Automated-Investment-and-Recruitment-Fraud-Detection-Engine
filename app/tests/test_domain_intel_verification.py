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
        result = verification_workflow(country_code="FR")
        self.assertEqual(result["region_label"], "")
        self.assertEqual(result["official_sources"], _GLOBAL_SOURCES)
        self.assertIn("No country-specific list", result["note"])

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

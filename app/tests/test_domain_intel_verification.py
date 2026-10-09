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

    def test_every_country_with_a_confirmed_police_or_cyber_police_source_has_one(self):
        # Ali asked for a police/cyber-police reference alongside the financial-regulator one,
        # wherever an official URL could be confirmed with reasonable confidence. This locks in
        # the set added for that - it is not every covered country (some, like Bangladesh and
        # Egypt, had no confirmable official police URL at research time), but none of these
        # should regress to losing their police source.
        police_keywords = ("police", "polic", "polis", "polizei", "polizia", "polícia", "garda", "bka",
                            "bundeskriminalamt", "fraud centre", "scam response centre", "anti-fraud",
                            "cybercrime", "cyber crime", "efcc", "scamshield", "action fraud", "ic3", "nr3c",
                            "hbarweb", "ncsc", "absher", "12377", "pharos", "reportcyber", "cyber security centre",
                            "public security")
        countries_with_police = ("US", "GB", "AU", "CA", "MY", "IN", "DE", "FR", "IT", "ES", "NL", "CN", "JP",
                                 "TH", "VN", "NG", "ZA", "BR", "NZ", "HK", "SA", "TR", "PK", "CH", "SE", "IE",
                                 "TW", "PL", "BE", "AT", "CL", "CO")
        for code in countries_with_police:
            names = " ".join(s["name"].lower() for s in _COUNTRY_SOURCES[code]["sources"])
            self.assertTrue(any(kw in names for kw in police_keywords), (code, names))

    def test_the_sender_checks_are_unaffected_by_country(self):
        result = verification_workflow(claimed_company="Acme Pte Ltd", country_code="US")
        self.assertTrue(any(c["check"].startswith("Confirm the exact legal entity") for c in result["checks"]))


if __name__ == "__main__":
    unittest.main()

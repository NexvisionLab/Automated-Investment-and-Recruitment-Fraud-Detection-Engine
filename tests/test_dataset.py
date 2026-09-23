# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = [json.loads(line) for line in (ROOT / "data" / "records.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_counts(self):
        self.assertEqual(len(self.rows), 64_000)
        self.assertEqual(Counter(x["domain"] for x in self.rows), {"job": 32_000, "investment": 32_000})
        self.assertEqual(Counter(x["label"] for x in self.rows), {"scam": 32_000, "legitimate": 22_000, "awareness": 6_000, "ambiguous_ood": 4_000})

    def test_leaf_balance(self):
        counts = Counter(x["taxonomy_id"] for x in self.rows if x["label"] == "scam")
        self.assertEqual(len(counts), 32)
        self.assertEqual(set(counts.values()), {1000})

    def test_safety(self):
        self.assertTrue(all(x["synthetic"] and not x["contains_live_indicator"] for x in self.rows))
        self.assertTrue(all(".invalid/" in url or ".example/" in url for x in self.rows for url in __import__("re").findall(r"https?://[^\s]+", x["text"])))

    def test_campaign_isolation(self):
        groups = {}
        for row in self.rows:
            groups.setdefault(row["campaign_group_id"], set()).add(row["split"])
        self.assertTrue(all(len(value) == 1 for value in groups.values()))

    def test_multilingual_leaf_cues_are_metadata_only(self):
        self.assertTrue(all(
            not row.get("scenario_cue_en") or row["scenario_cue_en"] not in row["text"]
            for row in self.rows if row["language"] != "en"
        ))

    def test_ood_is_explicitly_for_abstention(self):
        ood = [row for row in self.rows if row["label"] == "ambiguous_ood"]
        self.assertEqual(len(ood), 4_000)
        self.assertTrue(all(row["ood_reason"] and row["annotation_confidence"] == 0.5 for row in ood))

    def test_required_intelligence_fields(self):
        required = {"text_en", "requested_action", "harm_vector", "severity", "variant_type", "variant_family_id", "review_status"}
        self.assertTrue(all(required.issubset(row) for row in self.rows))


if __name__ == "__main__":
    unittest.main()

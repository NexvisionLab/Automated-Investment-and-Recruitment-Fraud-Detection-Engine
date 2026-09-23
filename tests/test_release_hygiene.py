# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_release import should_include  # noqa: E402
from generate_dataset import content_hash  # noqa: E402
from materialize_splits import materialize  # noqa: E402
from validate_dataset import content_hash_payload, is_reserved_url, is_transient_project_file, normalize_url_obfuscation  # noqa: E402


class ReleaseHygieneTests(unittest.TestCase):
    def test_no_transient_project_files(self):
        transient = [
            path for path in ROOT.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
            and is_transient_project_file(path)
        ]
        self.assertEqual(transient, [])

    def test_repository_metadata_is_allowed_but_secret_dotfiles_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(is_transient_project_file(root / ".gitignore", root))
            self.assertFalse(is_transient_project_file(root / ".gitattributes", root))
            self.assertFalse(is_transient_project_file(root / ".github" / "workflows" / "ci.yml", root))
            self.assertTrue(is_transient_project_file(root / ".env", root))

    def test_split_files_are_not_duplicated_in_release(self):
        for name in ("train.jsonl", "validation.jsonl", "test.jsonl"):
            self.assertFalse(should_include(ROOT / "data" / name))
        self.assertTrue(should_include(ROOT / "data" / "records.jsonl"))

    def test_obfuscated_urls_normalize_for_safety_validation(self):
        self.assertEqual(normalize_url_obfuscation("hxxps：//case[.]invalid/x"), "https://case.invalid/x")
        self.assertTrue(is_reserved_url("https://case.invalid/x"))

    def test_reserved_domain_check_rejects_path_and_suffix_confusion(self):
        self.assertFalse(is_reserved_url("https://attacker.example.org/.invalid/payload"))
        self.assertFalse(is_reserved_url("https://case.invalid.attacker.com/path"))
        self.assertTrue(is_reserved_url("https://case.example/path"))

    def test_release_builder_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "outside.txt"
            target.write_text("not release content", encoding="utf-8")
            link = root / "linked.txt"
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assertFalse(should_include(link, root))

    def test_content_hash_covers_audit_fields(self):
        with (ROOT / "data" / "records.jsonl").open(encoding="utf-8") as handle:
            row = json.loads(next(handle))
        expected = hashlib.sha256(json.dumps(content_hash_payload(row), ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        self.assertEqual(content_hash(row), expected)
        row["text_en"] += " changed"
        self.assertNotEqual(content_hash(row), expected)

    def test_schema_required_fields_match_generated_records(self):
        schema = json.loads((ROOT / "schema" / "record.schema.json").read_text(encoding="utf-8"))
        with (ROOT / "data" / "records.jsonl").open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                row = json.loads(line)
                missing = set(schema["required"]).difference(row)
                self.assertEqual(missing, set(), f"record line {line_number} misses {sorted(missing)}")
                self.assertEqual(row["version"], schema["properties"]["version"]["const"])

    def test_split_materialization_is_complete_and_cleans_temporaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").mkdir()
            records = [
                {"id": "a", "split": "train"},
                {"id": "b", "split": "validation"},
                {"id": "c", "split": "test"},
            ]
            (root / "data" / "records.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in records), encoding="utf-8"
            )
            self.assertEqual(materialize(root), {"train": 1, "validation": 1, "test": 1})
            self.assertEqual(list((root / "data").glob(".*.tmp")), [])
            self.assertEqual(json.loads((root / "data" / "train.jsonl").read_text()), records[0])


if __name__ == "__main__":
    unittest.main()

# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from production_readiness import approved, evaluate  # noqa: E402
from release_manifest import should_include, verify_manifest, write_manifest  # noqa: E402


class ProductionControlTests(unittest.TestCase):
    def test_approval_requires_named_evidence(self):
        self.assertFalse(approved({"status": "approved"}))
        self.assertFalse(approved({"status": "approved", "reviewer": "A", "reviewed_at": "2026-09-23", "evidence": None}))
        self.assertTrue(approved({"status": "approved", "reviewer": "A", "reviewed_at": "2026-09-23", "evidence": "review/123"}))

    def test_current_release_fails_closed_for_production(self):
        write_manifest(ROOT)
        report = evaluate(ROOT)
        self.assertEqual(report["technical_release_status"], "PASS")
        self.assertEqual(report["overall_status"], "NOT_READY_FOR_PRODUCTION")
        self.assertGreater(report["blocked_gate_count"], 0)

    def test_manifest_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "metadata").mkdir()
            evidence = root / "evidence.txt"
            evidence.write_text("original", encoding="utf-8")
            write_manifest(root, version="test")
            self.assertEqual(verify_manifest(root), [])
            evidence.write_text("changed", encoding="utf-8")
            self.assertEqual(verify_manifest(root), ["evidence.txt"])

    def test_release_includes_ci_but_rejects_other_hidden_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("name: test\n", encoding="utf-8")
            secret = root / ".env"
            secret.write_text("SECRET=unsafe\n", encoding="utf-8")
            self.assertTrue(should_include(workflow, root))
            self.assertFalse(should_include(secret, root))


if __name__ == "__main__":
    unittest.main()

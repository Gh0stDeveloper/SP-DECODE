"""C2 run the ORIGINAL file decoder subprocesses against the frozen A.2.3 inputs.

Only synthetic fixtures; outputs are compared to original source golden results.
No bot handlers, live keys or vendor files are used.
"""
from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from cloud.workers.python.engine import DecodeFailure, decode_file, load_file_engines
from tests.golden.a23_export import SUFFIX
from tests.golden.a23_generators import SYNTHETIC_GENERATORS
import json

ROOT = Path(__file__).resolve().parents[1]

class CloudC2GoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "tests/golden/manifest.json").read_text(encoding="utf-8"))
        cls.engines = load_file_engines()

    def test_every_a23_golden_case_executes_through_worker(self):
        cases = self.manifest["fixtureCaseDefinitions"]
        self.assertEqual(len(cases), 60)
        for case in cases:
            name = case["id"]
            with self.subTest(case=name):
                self.assertIn(name, SUFFIX)
                self.assertIn(SUFFIX[name], self.engines)
                raw = SYNTHETIC_GENERATORS[name]()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), case["inputSha256"])
                expected = (ROOT / case["expectedRawText"]).read_text("utf-8")
                self.assertEqual(hashlib.sha256(expected.encode("utf-8")).hexdigest(), case["expectedRawUtf8Sha256"])
                try:
                    result = decode_file(SUFFIX[name], raw)
                except DecodeFailure as error:
                    self.fail("Worker failed fixture " + name + ": " + error.code)
                # The original bot uses stdout.strip(); ensure full *content*
                # equivalence while preserving the complete rawText in the API.
                self.assertEqual(result["rawText"].strip(), expected.strip())
                self.assertEqual(result["status"], "success")
                self.assertFalse(result["decoder"]["exporterCertified"])

if __name__ == "__main__":
    unittest.main()

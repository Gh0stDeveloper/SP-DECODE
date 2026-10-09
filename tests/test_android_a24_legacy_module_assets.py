"""Pin offline Android Node-module assets to the audited canonical source.

This unit test deliberately prints no cryptographic material on failure.
The snapshots are historical decoder constants, not user credentials.
"""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class LegacyModuleAssetsTest(unittest.TestCase):
    def test_module_key_snapshots_match_originals_without_logging_values(self):
        canonical=json.loads((ROOT/"cfg/keyFile.json").read_text("utf-8"))
        copied=json.loads((ROOT/"android/app/src/main/assets/legacy_epro_npv2_keys.json").read_text("utf-8"))
        self.assertEqual(copied.get("source"),"cfg/keyFile.json")
        self.assertTrue(copied.get("eproPasswords")==canonical.get("ePro"),
                        "ePro offline candidate snapshot differs from canonical decoder source")
        self.assertTrue(copied.get("npv2Passwords")==canonical.get("npv2"),
                        "NPV2 offline candidate snapshot differs from canonical decoder source")

    def test_module_language_snapshot_matches_original_labels(self):
        lang=json.loads((ROOT/"cfg/lang/english.lang.json").read_text("utf-8"))
        expected={k:v for k,v in lang.items() if k.startswith("_")}
        copied=json.loads((ROOT/"android/app/src/main/assets/legacy_module_english_labels.json").read_text("utf-8"))
        self.assertTrue(copied==expected,"Android module labels differ from source English layout")

if __name__=="__main__":
    unittest.main()

"""Phase B evidence contract: 81 real source-selected profiles and reference vectors."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.android_b_generic_profiles import (
    PROFILE_ASSET, ROOT, generate, generate_fixtures,
)
from scripts.android_a24_catalog import generate as generate_catalog
from spdecode.registry import DECODER_REGISTRY


class AndroidBGenericParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = generate()
        cls.catalog = generate_catalog()
        cls.row_map = {
            row["suffix"]: row for row in cls.catalog["entries"]
            if row["migrationPhase"] == "B"
        }

    def test_81_canonical_profiles_match_committed_asset(self):
        self.assertEqual(
            json.loads(PROFILE_ASSET.read_text("utf-8")), self.profiles)
        self.assertEqual(len(self.profiles["profiles"]), 81)
        self.assertEqual(self.profiles["aesProfileCount"], 74)
        self.assertEqual(self.profiles["desProfileCount"], 13)
        self.assertEqual(self.profiles["dualProfileCount"], 6)
        self.assertEqual(set(self.row_map),
                         {row["suffix"] for row in self.profiles["profiles"]})
        self.assertEqual(self.catalog["androidExistingSuffixes"], 61)
        self.assertEqual(self.catalog["androidGenericNativeSuffixes"], 81)
        self.assertEqual(self.catalog["androidNativePortSuffixes"], 239)
        self.assertEqual(self.catalog["androidPendingNativeSuffixes"], 0)
        self.assertEqual(self.catalog["androidCertifiedSuffixes"], 0)

    def test_81_synthetic_ports_are_explicitly_selected_without_overrides(self):
        original = json.loads((ROOT / "decoders.json").read_text("utf-8"))["decoders"]
        self.assertEqual(len(original), 61)
        for row in self.profiles["profiles"]:
            suffix = row["suffix"]
            with self.subTest(suffix=suffix):
                self.assertNotIn(suffix, original)
                spec = DECODER_REGISTRY[suffix]
                self.assertEqual(spec.script, self.row_map[suffix]["script"])
                expected = ("experimental_generic_des_ecb_synthetic" if row["desKey"]
                            else "experimental_generic_aes_gcm_synthetic")
                self.assertEqual(self.row_map[suffix]["androidPortStatus"], expected)
                self.assertTrue(self.row_map[suffix]["linuxGoldenSynthetic"])
                self.assertFalse(self.row_map[suffix]["androidVerified"])
        for suffix in ("ost", "fɴ", "sksrv.png", "npvs"):
            self.assertEqual(next(x for x in self.catalog["entries"] if x["suffix"] == suffix)
                             ["migrationPhase"], "legacy")

    def test_seven_ten_format_lots_and_final_eleven_format_lot(self):
        suffixes = [row["suffix"] for row in self.profiles["profiles"]]
        lots = [suffixes[i:i + 10] for i in range(0, 70, 10)] + [suffixes[70:]]
        self.assertEqual([len(lot) for lot in lots], [10]*7 + [11])
        self.assertEqual(set().union(*(set(x) for x in lots)), set(suffixes))
        self.assertEqual(sum(map(len, lots)), 81)

    def test_python_reference_corpus_includes_all_81_and_six_dual_profiles(self):
        refs = generate_fixtures()
        self.assertEqual(refs["schemaVersion"], 1)
        self.assertEqual(refs["profileCount"], 81)
        self.assertEqual(refs["aesVectors"], 74)
        self.assertEqual(refs["desVectors"], 26)
        self.assertEqual(len(refs["vectors"]), 100)
        self.assertEqual({v["suffix"] for v in refs["vectors"]}, set(self.row_map))
        dual = {x["suffix"] for x in self.profiles["profiles"]
                if x["desKey"] and x["aesKeys"]}
        self.assertEqual(dual, {"acm","htp","pin","tut","vmx","xsks"})
        for suffix in dual:
            engines = {x["engine"] for x in refs["vectors"] if x["suffix"] == suffix}
            self.assertEqual(engines, {"aes","des"})

    def test_generated_asset_round_trip_and_cli(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "generic-fixtures.json"
            subprocess.run(
                [sys.executable, "scripts/android_b_generic_profiles.py",
                 "--fixtures", str(file)],
                cwd=ROOT, capture_output=True, text=True, check=True,
                timeout=40,
            )
            ref = json.loads(file.read_text("utf-8"))
            self.assertEqual(ref["profileCount"], 81)
            self.assertEqual(len(ref["vectors"]), 100)
        check = subprocess.run(
            [sys.executable, "scripts/android_b_generic_profiles.py", "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("81 native", check.stdout)


if __name__ == "__main__":
    unittest.main()

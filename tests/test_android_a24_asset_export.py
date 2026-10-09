"""Validate A.2.4 assets before running an Android emulator.

These checks do NOT certify Android runtime parity; only connected Android
instrumentation can do so.
"""
from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path

from scripts.android_a24_prepare import CASES,ROOT,SUFFIX,prepare


class AndroidA24AssetTests(unittest.TestCase):
    def test_asset_export_is_exactly_forty_nine_frozen_synthetic_vectors(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-a24-") as tmp:
            output=Path(tmp)/"assets"
            results=prepare(output)
            self.assertEqual({r["id"] for r in results},set(CASES))
            self.assertEqual(len(list(output.iterdir())),2*len(CASES)+1)
            self.assertEqual(json.loads((output/"checksums.json").read_text()),results)
            for row in results:
                self.assertTrue((output/(row["id"]+"."+SUFFIX[row["id"]])).is_file())
                self.assertEqual((output/(row["id"]+".txt")).is_file(),True)
                reference=(output/(row["id"]+".txt")).read_bytes()
                self.assertTrue(reference.startswith(b"TLS Tunnel") if row["id"]=="tls-aesgcm" else reference.startswith(b"{") if row["id"] in {"batch6-at","batch6-nm"} else reference.startswith("╔".encode()) if row["id"]=="batch7-gold" else reference.lstrip().startswith("┌".encode()) if row["id"] not in {"batch5-tnl"} else reference.startswith(b"{"))

    def test_manifest_still_declares_zero_real_android_certifications(self):
        manifest=json.loads((ROOT/"tests/golden/manifest.json").read_text("utf-8"))
        self.assertEqual(len(manifest["extensions"]),59)
        self.assertTrue(all(x["androidVerification"]=="not_started" for x in manifest["extensions"]))
        self.assertTrue(all(x["androidGolden"]=="not_started" for x in manifest["fixtureCaseDefinitions"]))


if __name__=="__main__":
    unittest.main()

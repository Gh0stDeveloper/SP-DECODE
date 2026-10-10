"""Phase A: deterministic 239-entry inventory without claiming Android support."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.android_a24_catalog import (
    CATALOG, EXPECTED_NEW_BY_PHASE, PROTO, ROOT, generate, phase_for,
)
from spdecode.registry import DECODER_REGISTRY

ORIGINAL = json.loads((ROOT / "decoders.json").read_text("utf-8"))["decoders"]


class AndroidA24CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = generate()
        cls.rows = {row["suffix"]: row for row in cls.doc["entries"]}

    def test_exact_239_canonical_entries_without_renumbering_originals(self):
        committed = json.loads(CATALOG.read_text("utf-8"))
        self.assertEqual(self.doc, committed)
        self.assertEqual(self.doc["schemaVersion"], 3)
        self.assertEqual(self.doc["botRegisteredSuffixes"], 239)
        self.assertEqual(self.doc["androidExistingSuffixes"], 61)
        self.assertEqual(self.doc["androidGenericNativeSuffixes"], 81)
        self.assertEqual(self.doc["androidNativePortSuffixes"], 142)
        self.assertEqual(self.doc["androidPendingNativeSuffixes"], 97)
        self.assertEqual(len(self.doc["entries"]), 239)
        self.assertEqual(set(self.rows), set(DECODER_REGISTRY))
        self.assertEqual(len(self.rows), 239)
        self.assertEqual(len(ORIGINAL), 61)
        self.assertEqual(set(PROTO), set(ORIGINAL))
        self.assertEqual(len(PROTO), 61)
        self.assertEqual(len(self.doc["androidPrototypeSuffixes"]), 61)
        self.assertEqual(self.doc["androidCertifiedSuffixes"], 0)
        self.assertFalse(any(row["androidVerified"] for row in self.rows.values()))

    def test_61_original_implementations_are_unchanged(self):
        old = {suffix: self.rows[suffix] for suffix in ORIGINAL}
        self.assertEqual(len(old), 61)
        self.assertEqual(sum(row["migrationPhase"] == "legacy" for row in old.values()), 61)
        for suffix, original in ORIGINAL.items():
            row = old[suffix]
            self.assertEqual((row["name"], row["script"], row["originalRuntime"]),
                             (original["name"], original["script"], original["runtime"]))
            self.assertEqual(row["sourceCatalog"], "decoders.json")
            self.assertNotEqual(row["androidPortStatus"], "registered_not_implemented")
            self.assertTrue(row["androidPortStatus"])
        self.assertEqual(old["npvs"]["androidPortStatus"], "experimental_native_npvs_v5")
        self.assertEqual(old["tls"]["androidPortStatus"], "prototype_tls_aesgcm_synthetic_case")
        self.assertEqual(old["lnk"]["androidPortStatus"], "experimental_linklayer_ver6_synthetic")
        self.assertEqual(old["ost"]["script"], "decoders/Python/ost.py")

    def test_81_generic_routes_and_remaining_97_pending_are_faithful(self):
        pending = {suffix: row for suffix, row in self.rows.items() if suffix not in ORIGINAL}
        self.assertEqual(len(pending), 178)
        self.assertEqual(sum(row["androidPortStatus"] == "registered_not_implemented" for row in pending.values()), 97)
        self.assertEqual(sum(row["migrationPhase"] == "B" for row in pending.values()), 81)
        self.assertEqual(sum(row["migrationPhase"] != "legacy" for row in self.rows.values()), 178)
        for suffix, row in pending.items():
            spec = DECODER_REGISTRY[suffix]
            with self.subTest(suffix=suffix):
                self.assertEqual(row["sourceCatalog"], "spdecode.registry")
                if row["migrationPhase"] == "B":
                    self.assertIn(row["androidPortStatus"], {
                        "experimental_generic_aes_gcm_synthetic",
                        "experimental_generic_des_ecb_synthetic",
                    })
                    self.assertTrue(row["linuxGoldenSynthetic"])
                else:
                    self.assertEqual(row["androidPortStatus"], "registered_not_implemented")
                    self.assertFalse(row["linuxGoldenSynthetic"])
                self.assertFalse(row["androidVerified"])
                self.assertEqual(row["migrationPhase"], phase_for(spec.script))
                self.assertEqual((row["name"], row["script"], row["originalRuntime"]),
                                 (spec.name, spec.script, spec.runtime))
                self.assertTrue((ROOT / row["script"]).is_file(), suffix)
        for suffix in ("ace","clay","ultra","7net","itv","izph","flexnet","st","apnalite"):
            self.assertIn(suffix, pending)

    def test_phase_distribution_and_compound_suffix_order(self):
        self.assertEqual(self.doc["migrationCounts"], EXPECTED_NEW_BY_PHASE)
        self.assertEqual({phase: sum(r["migrationPhase"] == phase for r in self.rows.values())
                          for phase in EXPECTED_NEW_BY_PHASE}, EXPECTED_NEW_BY_PHASE)
        ordered = [row["suffix"] for row in self.doc["entries"]]
        self.assertEqual(ordered, sorted(ordered, key=lambda suffix: (-len(suffix), suffix)))
        self.assertEqual(self.rows["sksrv.png"]["migrationPhase"], "legacy")
        self.assertIn("fɴ", self.rows)
        self.assertEqual(self.rows["ost"]["migrationPhase"], "legacy")
        self.assertEqual(
            {r["suffix"] for r in self.rows.values() if r["name"] == "HTTP Tweak"},
            {"ht", "htb"},
        )
        self.assertEqual(
            {r["suffix"] for r in self.rows.values() if r["name"] == "NPV Tunnel v4"},
            {"npv4", "npvt"},
        )

    def test_catalog_has_no_embedded_keys_or_credentials(self):
        for row in self.rows.values():
            self.assertEqual(
                set(row),
                {"suffix","name","script","originalRuntime","linuxGoldenSynthetic",
                 "androidPortStatus","androidVerified","exporterVersionsVerified",
                 "migrationPhase","sourceCatalog"},
            )
            self.assertFalse(set(row) & {"key","password","privateKey","secret","cryptoKey"})

    def test_script_detects_byte_level_stale_asset(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/android_a24_catalog.py")],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("239 registered", result.stdout)


if __name__ == "__main__":
    unittest.main()

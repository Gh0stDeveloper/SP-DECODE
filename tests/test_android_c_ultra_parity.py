"""Phase C: canonical Ultra/Sandok inventory and independent reference vectors."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest

from decoders.Python import ultra
from scripts.android_c_ultra_profiles import OUT, ROOT, generate, make_fixtures
from scripts.android_a24_catalog import generate as catalog


class AndroidUltraCParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = generate()
        cls.catalog = catalog()

    def test_41_aliases_and_19_kdf_profiles_are_exactly_source_derived(self):
        self.assertEqual(self.manifest, json.loads(OUT.read_text("utf-8")))
        self.assertEqual(len(self.manifest["aliases"]), 41)
        self.assertEqual(len(self.manifest["profiles"]), 19)
        self.assertEqual(set(x["suffix"] for x in self.manifest["aliases"]),
                         {s.lstrip(".") for s in ultra.ULTRA_EXTS if s != ".ost"})
        self.assertEqual({x["profile"] for x in self.manifest["aliases"]},
                         {ultra.EXT_TO_KEY[s] for s in ultra.ULTRA_EXTS if s != ".ost"})
        self.assertEqual(self.manifest["argonIterations"], 3)
        self.assertEqual(self.manifest["argonLanes"], 1)
        self.assertEqual(self.manifest["argonKeyBytes"], 32)
        self.assertTrue(self.manifest["legacyOstIsolated"])
        self.assertNotIn("ost", {x["suffix"] for x in self.manifest["aliases"]})
        self.assertEqual(len(self.manifest["encryptedFields"]), 11)
        self.assertEqual(len(self.manifest["fallbackProfiles"]), 16)
        self.assertEqual({x["memoryKiB"] for x in self.manifest["profiles"]},
                         {4096, 8192, 16384})
        for item in self.manifest["aliases"]:
            suffix = "." + item["suffix"]
            self.assertEqual(item["profile"], ultra.EXT_TO_KEY[suffix])
            self.assertEqual(item["name"], ultra.ULTRA_NAMES[suffix])

    def test_android_catalog_239_native_and_0_pending_with_legacy_ost(self):
        rows = {x["suffix"]: x for x in self.catalog["entries"]}
        self.assertEqual(self.catalog["botRegisteredSuffixes"], 239)
        self.assertEqual(self.catalog["androidExistingSuffixes"], 61)
        self.assertEqual(self.catalog["androidGenericNativeSuffixes"], 81)
        self.assertEqual(self.catalog["androidUltraNativeSuffixes"], 41)
        self.assertEqual(self.catalog["androidNativePortSuffixes"], 239)
        self.assertEqual(self.catalog["androidPendingNativeSuffixes"], 0)
        self.assertEqual(self.catalog["androidCertifiedSuffixes"], 0)
        self.assertEqual(self.catalog["syntheticLinuxCoveredSuffixes"], 238)
        for alias in self.manifest["aliases"]:
            row = rows[alias["suffix"]]
            self.assertEqual(row["migrationPhase"], "C")
            self.assertEqual(row["androidPortStatus"],
                             "experimental_ultra_sandok_argon2id_synthetic")
            self.assertTrue(row["linuxGoldenSynthetic"])
            self.assertFalse(row["androidVerified"])
        self.assertEqual(rows["ost"]["migrationPhase"], "legacy")
        self.assertEqual(rows["ost"]["script"], "decoders/Python/ost.py")
        self.assertEqual(rows["ost"]["androidPortStatus"], "experimental_batch20_synthetic")
        self.assertEqual(sum(x["androidPortStatus"] == "registered_not_implemented"
                             for x in rows.values()), 0)

    def test_83_source_python_reference_vectors_and_inner_fields(self):
        refs = make_fixtures()
        self.assertEqual(refs["caseCount"], 83)
        self.assertEqual(len(refs["vectors"]), 83)
        self.assertEqual(refs["aadVectors"], 41)
        self.assertEqual(refs["noAadVectors"], 41)
        self.assertEqual(refs["fallbackVectors"], 1)
        # .ost remains one of the 61 legacy registrations, with two
        # additional authenticated Ultra/Sandok fallback envelopes.
        self.assertEqual(refs["legacyOstCaseCount"], 2)
        self.assertEqual(len(refs["legacyOstVectors"]), 2)
        self.assertEqual({x["mode"] for x in refs["legacyOstVectors"]},
                         {"aad", "no_aad"})
        import base64
        for sample in refs["legacyOstVectors"]:
            encoded = base64.b64decode(sample["encodedInput"])
            self.assertEqual(
                json.loads(ultra.run(encoded, ".ost")),
                json.loads(sample["expected"]),
            )
            self.assertEqual(json.loads(sample["expected"])["extension"], ".ost")

        self.assertEqual(
            {x["suffix"] for x in refs["vectors"]},
            {x["suffix"] for x in self.manifest["aliases"]}
        )
        for item in refs["vectors"]:
            payload = json.loads(item["expected"])
            self.assertEqual(payload["extension"], "." + item["suffix"])
            self.assertEqual(payload["config"]["_vpn_key"], item["profile"])
            self.assertEqual(payload["config"]["Enabled"], False)
            if item["mode"] == "aad" and item["suffix"] in ("ultra","mmt","t20","flynet"):
                for field in self.manifest["encryptedFields"]:
                    if field != "Server":
                        self.assertEqual(payload["config"][field], "value-" + field)

    def test_manifest_cli_checks_current_asset(self):
        run = subprocess.run(
            [sys.executable, "scripts/android_c_ultra_profiles.py", "--check"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("41 Ultra/Sandok", run.stdout)


if __name__ == "__main__":
    unittest.main()

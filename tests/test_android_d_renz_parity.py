"""Phase D — verify canonical RENZ inventory and source-generated crypto fixtures."""
from __future__ import annotations
import json
import subprocess
import sys
import unittest

from decoders.Python import renz
from scripts.android_a24_catalog import generate as catalog_generate
from scripts.android_d_renz_profiles import OUT, ROOT, generate, make_fixtures
from spdecode.registry import DECODER_REGISTRY


class AndroidRenzDParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = catalog_generate()
        cls.manifest = generate()

    def test_registry_and_16_source_aliases(self):
        self.assertEqual(json.loads(OUT.read_text("utf-8")),self.manifest)
        self.assertEqual(self.manifest["suffixCount"],16)
        self.assertEqual(self.manifest["profileCount"],14)
        self.assertEqual(len(self.manifest["aliases"]),16)
        self.assertEqual(len(self.manifest["profiles"]),14)
        for alias in self.manifest["aliases"]:
            suffix="."+alias["suffix"]
            self.assertEqual(renz.RENZ_FILE_EXTENSIONS[suffix],alias["profile"])
            self.assertEqual(renz.RENZ_FILE_NAMES[suffix],alias["name"])
            self.assertEqual(DECODER_REGISTRY[alias["suffix"]].script,
                             "decoders/Python/renz.py")
        for p in self.manifest["profiles"]:
            src=renz.RENZ_KEYS[p["key"]]
            for field,source in (("seed","KEY_SEED"),("iv","IV"),("salt","FIXED_SALT")):
                self.assertEqual(p[field],src.get(source,b"").hex())
        self.assertNotIn("vlx",{a["suffix"] for a in self.manifest["aliases"]})
        self.assertNotIn("izph",{a["suffix"] for a in self.manifest["aliases"]})

    def test_239_native_routes_with_13_independent_extensions(self):
        catalog=self.catalog
        self.assertEqual(catalog["botRegisteredSuffixes"],239)
        self.assertEqual(catalog["androidExistingSuffixes"],61)
        self.assertEqual(catalog["androidGenericNativeSuffixes"],81)
        self.assertEqual(catalog["androidUltraNativeSuffixes"],41)
        self.assertEqual(catalog["androidRenzNativeSuffixes"],16)
        self.assertEqual(catalog["androidNativePortSuffixes"],239)
        self.assertEqual(catalog["androidPendingNativeSuffixes"],0)
        self.assertEqual(catalog["androidCertifiedSuffixes"],0)
        rows={x["suffix"]:x for x in catalog["entries"]}
        for alias in self.manifest["aliases"]:
            row=rows[alias["suffix"]]
            self.assertEqual(row["migrationPhase"],"D")
            self.assertEqual(row["androidPortStatus"],
                             "experimental_renz_aes_xxtea_threefish_synthetic")
            self.assertTrue(row["linuxGoldenSynthetic"])
            self.assertFalse(row["androidVerified"])
        self.assertEqual(rows["vlx"]["migrationPhase"],"C")
        self.assertEqual(rows["izph"]["migrationPhase"],"F")

    def test_22_encrypted_reference_results(self):
        corpus=make_fixtures()
        self.assertEqual(corpus["caseCount"],22)
        self.assertEqual(len(corpus["vectors"]),22)
        self.assertEqual({x["mode"] for x in corpus["vectors"]},{
            "outer","nested_host","nested_username","type0","type1","type2","type3"})
        self.assertEqual({x["suffix"] for x in corpus["vectors"] if x["mode"]=="outer"},
                         {x["suffix"] for x in self.manifest["aliases"]})
        self.assertEqual({x["mode"] for x in corpus["vectors"] if x["mode"].startswith("type")},
                         {"type0","type1","type2","type3"})
        for case in corpus["vectors"]:
            output=json.loads(case["expected"])
            self.assertEqual(output["extension"],"."+case["suffix"])
            self.assertIsInstance(output["config"],(dict,list))

    def test_cli_profile_manifest_is_current(self):
        proc=subprocess.run([sys.executable,"scripts/android_d_renz_profiles.py","--check"],
            cwd=ROOT,check=False,capture_output=True,text=True,timeout=30)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertIn("16 RENZ aliases",proc.stdout)


if __name__=="__main__":
    unittest.main()

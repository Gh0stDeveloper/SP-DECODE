"""Exact E.1–E.3 source-fixture and Android catalog gates."""
from __future__ import annotations
import base64
import json
import unittest
from decoders.Python import (sentinel,itv,eut,v2box_export,slipnet,juanscript,wyrlite,
    wyrvpn,intvpn,fthp,ar_pro,ec,xor_family)
from scripts.android_e_special_fixtures import generate
from scripts.android_a24_catalog import generate as catalog_generate
from spdecode.registry import DECODER_REGISTRY

SCRIPTS={x.__name__.split(".")[-1]+".py":x for x in (
    sentinel,itv,eut,v2box_export,slipnet,juanscript,wyrlite,
    wyrvpn,intvpn,fthp,ar_pro,ec,xor_family
)}

class AndroidPhaseETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog=catalog_generate()
        cls.rows={e["suffix"]:e for e in cls.catalog["entries"]}
        cls.fixture=generate()

    def test_source_inventory_exactly_27_and_13_engines(self):
        special={x["suffix"] for x in self.catalog["entries"] if x["migrationPhase"]=="E"}
        self.assertEqual(len(special),27)
        self.assertEqual(self.catalog["androidSpecialNativeSuffixes"],27)
        self.assertEqual(self.catalog["androidNativePortSuffixes"],239)
        self.assertEqual(self.catalog["androidPendingNativeSuffixes"],0)
        self.assertEqual(set(self.fixture["modules"]),set(SCRIPTS))
        self.assertEqual(self.fixture["suffixCount"],27)
        self.assertEqual(self.fixture["caseCount"],31)
        for suffix in special:
            row=self.rows[suffix]
            self.assertEqual(row["androidPortStatus"],"experimental_special_13_engines_synthetic")
            self.assertEqual(row["sourceCatalog"],"spdecode.registry")
            self.assertTrue(row["linuxGoldenSynthetic"])
            self.assertFalse(row["androidVerified"])
            self.assertIn(row["script"].rsplit("/",1)[-1],SCRIPTS)
            self.assertEqual(row["script"],DECODER_REGISTRY[suffix].script)

    def test_all_original_python_results_are_source_exact(self):
        for case in self.fixture["vectors"]:
            with self.subTest(suffix=case["suffix"],mode=case["mode"]):
                module=SCRIPTS[case["module"]]
                raw=base64.b64decode(case["encodedInput"],validate=True)
                self.assertEqual(module.run(raw),case["expected"])

    def test_full_results_and_negative_inputs(self):
        outer=[x for x in self.fixture["vectors"] if x["mode"]=="outer"]
        self.assertEqual(len(outer),27)
        self.assertEqual({x["suffix"] for x in outer},
            {row["suffix"] for row in self.catalog["entries"] if row["migrationPhase"]=="E"})
        extras=[x["mode"] for x in self.fixture["vectors"] if x["mode"]!="outer"]
        self.assertEqual(set(extras),
            {"aes_gcm","optional_header","secondary_key","password_required"})
        self.assertEqual(self.rows["izph"]["migrationPhase"],"F")
        self.assertEqual(self.rows["vlx"]["migrationPhase"],"C")
        self.assertEqual(self.rows["ost"]["migrationPhase"],"legacy")
        self.assertTrue(all(not x["androidVerified"] for x in self.catalog["entries"]))

if __name__=="__main__":
    unittest.main()

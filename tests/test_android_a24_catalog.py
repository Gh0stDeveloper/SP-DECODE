"""Ensure Android registry cannot silently advertise unsupported decoders."""
from __future__ import annotations
import json
import unittest
from scripts.android_a24_catalog import ROOT,CATALOG,generate


class AndroidA24CatalogTests(unittest.TestCase):
    def test_exact_59_entries_and_support_truthfulness(self):
        source=generate()
        committed=json.loads(CATALOG.read_text("utf-8"))
        self.assertEqual(source,committed)
        self.assertEqual(len(source["entries"]),59)
        self.assertEqual(source["androidCertifiedSuffixes"],0)
        self.assertEqual(len(source["androidPrototypeSuffixes"]),52)
        self.assertEqual(len(set(source["androidPrototypeSuffixes"])),52)
        self.assertTrue(all(not r["androidVerified"] and not r["exporterVersionsVerified"] for r in source["entries"]))
        self.assertEqual(sum(r["androidPortStatus"]!="not_implemented" for r in source["entries"]),52)
        self.assertEqual(sum(r["androidPortStatus"]=="not_implemented" for r in source["entries"]),7)
        self.assertEqual(next(r for r in source["entries"] if r["suffix"]=="tls")["androidPortStatus"],"prototype_tls_aesgcm_synthetic_case")

    def test_compound_suffix_and_unicode_names_are_preserved(self):
        bysuffix={x["suffix"]:x for x in generate()["entries"]}
        self.assertIn("sksrv.png",bysuffix)
        self.assertIn("fɴ",bysuffix)
        self.assertEqual(next(x for x in generate()["entries"] if x["suffix"]=="sksrv.png")["androidPortStatus"],"experimental_batch15_synthetic")


if __name__=="__main__":
    unittest.main()

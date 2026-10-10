"""Phase G: verify generated text schemes against the real modular bot decoders."""
from __future__ import annotations
import json,unittest
from pathlib import Path
from scripts.android_g_text_fixtures import build
from decoders.Python import (renz,xor_family,text_legacy_protocols,
    text_structured_protocols,npvt_links,falcon_links)
from spdecode.handlers import config_batch_texts

class AndroidPhaseGTextParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=build()
    def test_23_renz_schemes_and_10_xor_schemes_are_source_exact(self):
        doc=self.data
        self.assertEqual(doc["renzCount"],len(renz.RENZ_TEXT_PROTOCOLS))
        self.assertEqual(doc["renzCount"],23)
        self.assertEqual(doc["xorCount"],len(xor_family.SCHEMES))
        self.assertEqual(doc["xorCount"],10)
        self.assertEqual({e["scheme"] for e in doc["vectors"] if e["group"]=="renz"},
            set(renz.RENZ_TEXT_PROTOCOLS))
        self.assertEqual({e["scheme"] for e in doc["vectors"] if e["group"]=="xor"},
            set(xor_family.SCHEMES))
    def test_source_goldens_have_real_content_and_no_user_secrets(self):
        doc=self.data
        self.assertGreaterEqual(doc["vectorCount"],55)
        self.assertEqual(doc["vectorCount"],len(doc["vectors"]))
        for case in doc["vectors"]:
            with self.subTest(scheme=case["scheme"]):
                self.assertTrue(case["input"])
                self.assertIsInstance(case["expected"],(dict,list))
                self.assertFalse(case["input"].startswith("https://"))
    def test_all_bot_batch_protocols_are_uniquely_accounted_for(self):
        self.assertIn("falcontunnel://import/",config_batch_texts.TEXT_HANDLERS)
        self.assertIn("izphvpnpro://",config_batch_texts.TEXT_HANDLERS)
        self.assertIn("npvs1:",config_batch_texts.TEXT_HANDLERS)
        self.assertIn("slipnet://",config_batch_texts.TEXT_HANDLERS)
        self.assertIn("slipnet://",text_structured_protocols.PREFIXES)
        self.assertIn("mark://",text_legacy_protocols.ALL_PREFIXES)
        self.assertTrue(set(renz.RENZ_TEXT_PROTOCOLS).isdisjoint(set(xor_family.SCHEMES)))
    def test_happ_requires_explicit_user_owned_private_rsa_keys(self):
        self.assertEqual(self.data["unavailableWithoutPrivateKeys"],[
            "happ://crypt/","happ://crypt2/","happ://crypt3/","happ://crypt4/"])
        self.assertTrue(all(not item["scheme"].startswith("happ://") for item in self.data["vectors"]))
    def test_falcon_source_is_base64_json_not_link_to_fetch(self):
        case=next(c for c in self.data["vectors"] if c["scheme"]=="falcontunnel://import/")
        self.assertEqual(json.loads(falcon_links.decode_text(case["input"])),case["expected"])

if __name__=="__main__":unittest.main()

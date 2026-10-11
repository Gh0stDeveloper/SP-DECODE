"""Synthetic parity for the six TLS Tunnel 8.5.0 configuration-key profiles."""
from __future__ import annotations
import base64
import tempfile
import unittest
from pathlib import Path
from decoders.Python import TLS
from scripts.android_tls_850_fixtures import samples, export

class Tls850AndroidFixtureTests(unittest.TestCase):
    def test_all_six_profiles_are_authenticated_and_lossless(self):
        cases=list(samples())
        self.assertEqual(len(cases),6)
        for profile,(_,raw,rendered) in enumerate(cases,1):
            with self.subTest(profile=profile):
                out=TLS.decrypt_tls_payload(raw.decode())
                self.assertTrue(out["_tls"]["authenticated"])
                self.assertEqual(out["_tls"]["key_profile"],profile)
                self.assertEqual(rendered,TLS.run(raw)+"\n")
                self.assertEqual(out["_tls"]["field_count"],len(out["_tls"]["fields"]))
                if profile!=6:
                    self.assertNotIn("nameserver",out)
                    self.assertNotIn("legacy_dns_mode",out)
                else:
                    self.assertIn("legacy_dns_mode",out)
                self.assertIn("node.example.invalid",rendered)
    def test_export_writes_matching_python_golden(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            export(root)
            for name,data,text in samples():
                self.assertEqual((root/(name+".tls")).read_bytes(),data)
                self.assertEqual((root/(name+".txt")).read_text(encoding="utf-8"),text)
    def test_altered_payload_fails_all_profiles(self):
        name,raw,_=next(samples())
        encoded=raw.decode().split(':',1)[0]
        data=bytearray(base64.b64decode(
            TLS.fix_b64_padding(encoded[::-1])))
        data[12]^=0x20
        modified=base64.b64encode(data).decode().rstrip('=')[::-1].encode()
        self.assertIsNone(TLS.run(modified))
        self.assertIsNotNone(TLS.run(raw))

if __name__=="__main__":
    unittest.main()

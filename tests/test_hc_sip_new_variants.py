"""Regression: old and new .hc/.sip engines must coexist without false success.

All fixtures are synthetic and contain public reserved domains, not real user files.
"""
from __future__ import annotations

import base64
import json
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from decoders.Python.HTTPCUSTOM import run as hc_run
from decoders.Python import _hc_hccfg as hc
from decoders.Python.sockip import (
    SIP_AES_KEY, UnsupportedSocksIPVersion, decode_profile, run as sip_run,
)
from tests.golden.hc_sip_new_variants import (
    hccfg_file, sip_ver8_file, sip_file, httpcustom_bytes, S4_SYNTHETIC_PASSWORD,
    hccfg_hwid_file, SYNTHETIC_HWID, hpc1,
)


class HcSipVersionedTests(unittest.TestCase):
    def test_hc_legacy_still_decodes(self):
        text=hc_run(httpcustom_bytes())
        self.assertIsNotNone(text)
        self.assertIn("example.org",text)
        self.assertIn("Config:",text)

    def test_hc_authenticated_hccfg_v1(self):
        decoded=json.loads(hc_run(hccfg_file(1,"n1")))
        self.assertEqual(decoded["app_version"],"7.11.8 (864)")
        self.assertEqual(decoded["config"][0]["host"],"example.org")
        self.assertEqual(decoded["config"][0]["sni"],"example.org")
        self.assertEqual(decoded["protections"]["accessMode"],"free")
        self.assertEqual(decoded["config"][0]["password"],"dummy")

    def test_hc_authenticated_hccfg_new_n7(self):
        decoded=json.loads(hc_run(hccfg_file(7,"n7")))
        self.assertEqual(decoded["config"][0]["port"],443)
        self.assertEqual(decoded["config"][0]["payload"],"GET / HTTP/1.1")

    def test_hccfg_password_lock_requires_explicit_correct_password(self):
        locked=hccfg_file(password=S4_SYNTHETIC_PASSWORD)
        with self.assertRaisesRegex(hc.HCError,"PASSWORD_REQUIRED"):
            hc.decrypt(locked)
        with self.assertRaises(hc.HCError):
            hc.decrypt(locked,password="incorrect-password")
        result=hc.decrypt(locked,password=S4_SYNTHETIC_PASSWORD)
        self.assertEqual(result["config"][0]["host"],"example.org")

    def test_hc_rejects_outer_mac_tampering(self):
        broken=bytearray(hccfg_file())
        broken[-1]^=0x40
        self.assertIsNone(hc_run(bytes(broken)))

    def test_hwid_and_dual_android_fixtures_match_python_crypto(self):
        for password in (None, S4_SYNTHETIC_PASSWORD):
            with self.subTest(dual=password is not None):
                raw=hccfg_hwid_file(password)
                env=hc._open_outer(raw)
                key,aad=hc._derive(env,password,SYNTHETIC_HWID)
                sec=env["j"][0]
                profile=hc._xdec(key,bytes.fromhex(sec["b"]),aad+b"\0s0",
                                 bytes.fromhex(sec["c"]))
                # Verify HPR1 explicitly, without the historical stream fallback.
                self.assertEqual(profile[:4],b"HPR1")
                self.assertEqual(hc._xdec(key,profile[4:28],aad+b"\0s0:r",profile[28:]),hpc1(flags=0xffffffff))
                result=hc.decrypt(raw,password=password,hwid=SYNTHETIC_HWID.lower())
                self.assertEqual(result["app_version"],"build-885")
                self.assertEqual(result["config"][0]["host"],"example.org")
                self.assertEqual(result["config"][0]["custom_payload_sidecar"],
                                 "Synthetic authenticated sidecar")
                for wrong in (None, "B"*32):
                    with self.assertRaises(hc.HCError):
                        hc.decrypt(raw,password=password,hwid=wrong)
                if password is not None:
                    for wrong in (None, "wrong-password"):
                        with self.assertRaises(hc.HCError):
                            hc.decrypt(raw,password=wrong,hwid=SYNTHETIC_HWID)

    def test_protected_android_fixture_rejects_modified_aead_layers(self):
        for layer in ("slot", "main", "profile", "sidecar"):
            with self.subTest(layer=layer), self.assertRaises(hc.HCError):
                hc.decrypt(hccfg_hwid_file(S4_SYNTHETIC_PASSWORD,tamper_layer=layer),
                           password=S4_SYNTHETIC_PASSWORD,hwid=SYNTHETIC_HWID)

    def test_sip_legacy_still_decodes(self):
        self.assertEqual(decode_profile(sip_file())["server"],"example.org")

    def test_sip_ver8_java_aes_gcm(self):
        decoded=decode_profile(sip_ver8_file())
        self.assertEqual(decoded["server"],"example.org")
        self.assertEqual(json.loads(sip_run(sip_ver8_file()))["server"],"example.org")

    def test_sip_ver8_forged_tag_rejected(self):
        raw=base64.b64decode(sip_ver8_file())
        outer=bytearray(unpad(AES.new(SIP_AES_KEY,AES.MODE_ECB).decrypt(raw),16))
        outer[-1]^=0x01
        broken=base64.b64encode(AES.new(SIP_AES_KEY,AES.MODE_ECB)
            .encrypt(pad(bytes(outer),16)))
        with self.assertRaisesRegex(ValueError,"authentication"):
            decode_profile(broken)

    def test_sip_old_unknown_ver7_stays_unimplemented(self):
        raw=base64.b64encode(AES.new(SIP_AES_KEY,AES.MODE_ECB)
            .encrypt(pad(b"VER7unsupported",16)))
        with self.assertRaises(UnsupportedSocksIPVersion):
            decode_profile(raw)


if __name__=="__main__":
    unittest.main()

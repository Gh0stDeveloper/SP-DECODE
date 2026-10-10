"""Positive synthetic cryptographic vectors for added VPN text protocols."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decoders.Python import text_legacy_protocols as legacy


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class LegacyTextProtocolTests(unittest.TestCase):
    def test_all_netmod_schemes_all_historical_aes_keys(self):
        config={"sshServer":"nm.example","sshPort":22,"Username":"ghost",
                "Password":"fixture-secret","enable":False}
        data=json.dumps(config).encode()
        for prefix in legacy.NM_PREFIXES:
            for key_idx,key in enumerate(legacy._NM_KEYS):
                with self.subTest(prefix=prefix,key_idx=key_idx):
                    encrypted=AES.new(key,AES.MODE_ECB).encrypt(pad(data,16))
                    output=legacy.decode_text(prefix+b64(encrypted))
                    self.assertIsNotNone(output)
                    self.assertEqual(json.loads(output),config)

    def test_ar_all_schemes_aes_ecb_and_query_formats(self):
        config={"SSH":"ar.example:22","Profile":{"Name":"example"},"allowedit":False}
        cipher=AES.new(legacy._AR_KEY,AES.MODE_ECB)
        token=b64(cipher.encrypt(pad(json.dumps(config).encode(),16)))
        query_token=b64(cipher.encrypt(pad(b"payload=HELLO&profile=test&ssh=user:pass@ar.example:22",16)))
        for prefix in legacy.AR_PREFIXES:
            with self.subTest(prefix=prefix):
                decoded=legacy.decode_text(prefix+token)
                self.assertEqual(json.loads(decoded),config)
                self.assertEqual(legacy.decode_text(prefix+query_token),
                                 "payload=HELLO&profile=test&ssh=user:pass@ar.example:22")

    def test_pb_all_schemes_null_padding_and_vmess_base64(self):
        base={"server":"pb.example","port":443,"enabled":True}
        for prefix in legacy.PB_PREFIXES:
            with self.subTest(prefix=prefix):
                plain=json.dumps(base).encode()
                if prefix=="pb-vmess://":
                    plain=b64(plain).encode()
                clear=plain+b"\0"*(-len(plain)%16)
                encrypted=AES.new(legacy._PB_KEY,AES.MODE_CBC,legacy._PB_IV).encrypt(clear)
                actual=legacy.decode_text(prefix+b64(encrypted))
                self.assertIsNotNone(actual)
                self.assertEqual(json.loads(actual),base)

    def test_howdy_mark_n7pr_outer_json_and_inner_encrypted_fields(self):
        config={"username":"ghost","password":"fixture","port":443,
                "server":"howdy.example","sni":"sni.example","type":"ssh",
                "Note":"Full complete metadata","isEnabled":False}
        sealed=dict(config)
        for key in ("server","sni"):
            cipher=AES.new(legacy._HOWDY_KEY,AES.MODE_CBC,legacy._HOWDY_IV)
            sealed[key]=b64(cipher.encrypt(pad(config[key].encode(),16)))
        payload=b64(json.dumps(sealed).encode())
        for prefix in legacy.HOWDY_PREFIXES:
            with self.subTest(prefix=prefix):
                decoded=legacy.decode_text(prefix+payload)
                self.assertEqual(json.loads(decoded),config)
                decoded2=legacy.decode_text(prefix.upper()+payload)
                self.assertEqual(json.loads(decoded2),config)

    def test_howdy_full_aes_cbc_json_variant(self):
        config={"host":"howdy-full.example","port":22}
        clear=json.dumps(config).encode()
        ciphertext=AES.new(legacy._HOWDY_KEY,AES.MODE_CBC,legacy._HOWDY_IV).encrypt(pad(clear,16))
        actual=legacy.decode_text("mark://"+b64(ciphertext))
        self.assertEqual(json.loads(actual),config)

    def test_zivpn_sha256_password_aes_cbc_and_xml_fields(self):
        clear='<entry key="Host">ziv.example</entry>\n<entry key="Port">443</entry>'
        key=hashlib.sha256(legacy._ZIV_PASSWORD.encode()).digest()
        cipher=AES.new(key,AES.MODE_CBC,bytes(16))
        encrypted=cipher.encrypt(pad(clear.encode(),16))
        self.assertEqual(legacy.decode_text("zivpn://"+b64(encrypted)),clear)

    def test_reject_wrong_key_wrong_prefix_invalid_input_and_oversized(self):
        self.assertIsNone(legacy.decode_text("nm-ssh://not-base64!"))
        self.assertIsNone(legacy.decode_text("ar-ssh://bad."))
        self.assertIsNone(legacy.decode_text("pb-ssh://notbase64!"))
        self.assertIsNone(legacy.decode_text("n7pr://!!"))
        self.assertIsNone(legacy.decode_text("zivpn://!!"))
        self.assertIsNone(legacy.decode_text("unsupported://AAAA"))
        self.assertIsNone(legacy.decode_text("nm-ssh://"+("x"*(2*1024*1024+1))))
        ciphertext=AES.new(legacy._NM_KEYS[0],AES.MODE_ECB).encrypt(pad(b'{"User":"ghost"}',16))
        corrupted=bytearray(ciphertext)
        corrupted[-1]^=1
        self.assertIsNone(legacy.decode_netmod("nm-ssh://"+b64(bytes(corrupted))))


if __name__=="__main__":
    unittest.main()

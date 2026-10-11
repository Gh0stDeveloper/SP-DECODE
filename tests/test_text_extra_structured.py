"""Positive and negative tests for structured text links reused from file engines."""
from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES
from decoders.Python import text_structured_protocols as structured
from decoders.Python.v2box_export import V2BOX_KEY
from tests.test_independent_batch_crypto_a import flex_fixture


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class StructuredTextProtocolsTests(unittest.TestCase):
    def test_flex_and_flexnet_use_existing_authenticated_file_engine(self):
        data=flex_fixture(3,28,{"sshServer":"flex.example","sshUser":"ghost",
                                "sshPort":"22","file.msg":"Complete fields"})
        for prefix in ("flex://","flexnet://"):
            with self.subTest(prefix=prefix):
                output=structured.decode_text(prefix+b64(data))
                self.assertIsNotNone(output)
                actual=json.loads(output)
                self.assertEqual(actual["rawProperties"]["file.msg"],"Complete fields")
                self.assertEqual(actual["rawProperties"]["sshUser"],"ghost")
        damaged=bytearray(data)
        damaged[-1]^=1
        self.assertIsNone(structured.decode_text("flex://"+b64(damaged)))

    def test_slipnet_plain_base64_is_distinct_from_slipnet_enc(self):
        config="payload=GET / HTTP/1.1\nHost: slip.example\nuser=ghost"
        output=structured.decode_text("slipnet://"+b64(config.encode()))
        self.assertEqual(json.loads(output),{"data":config})
        data={"name":"slipnet","full":"multiline\nvalue","enabled":False}
        self.assertEqual(json.loads(structured.decode_text("slipnet://"+b64(json.dumps(data).encode()))),data)
        self.assertIsNone(structured.decode_text("slipnet://wrong!"))

    def test_vmess_base64_json(self):
        data={"v":"2","ps":"full profile","add":"vmess.example","port":"443",
              "id":"test-uuid","aid":"0","net":"ws","tls":"tls"}
        token=b64(json.dumps(data).encode())
        self.assertEqual(json.loads(structured.decode_text("vmess://"+token)),data)
        self.assertIsNone(structured.decode_text("vmess://not-valid!"))

    def test_v2box_locked_base64_url_preserves_all_query_parameters(self):
        url=("https://v2box.example/import?host=one.example&host=two.example"
             "&password=fixture-secret&empty=#Full%20Name")
        output=structured.decode_text("v2box://locked="+b64(url.encode()))
        config=json.loads(output)
        self.assertEqual(config["url"],url)
        self.assertEqual(config["parameters"]["host"],["one.example","two.example"])
        self.assertEqual(config["parameters"]["password"],["fixture-secret"])
        self.assertEqual(config["parameters"]["empty"],[""])
        self.assertEqual(config["notes"],"Full Name")

    def test_v2box_export_nonpassword_and_password_protected(self):
        data={"server":"secure.v2box.example","port":443,"enabled":True}
        nonce=bytes(range(12))
        enc=AES.new(V2BOX_KEY,AES.MODE_GCM,nonce=nonce)
        ciphertext,tag=enc.encrypt_and_digest(json.dumps(data).encode())
        payload={"magic":"v2box_export","nonce":b64(nonce),"tag":b64(tag),
                 "ciphertext":b64(ciphertext),"isPasswordProtected":False}
        link="v2box://"+b64(json.dumps(payload).encode())
        self.assertEqual(json.loads(structured.decode_text(link)),data)
        payload["isPasswordProtected"]=True
        self.assertEqual(structured.decode_text(
            "v2box://"+b64(json.dumps(payload).encode())),
            {"__need_password__":True})

    def test_creeb_bundle_full_metadata_and_all_extracted_links(self):
        doc={
            "type":"creeb_profile_bundle","version":7,
            "message":"Do not truncate\nmultiline information",
            "security":{"requiresPassword":False,"blockHwid":True},
            "profiles":[
                {"name":"Server A","hostPort":"a.example:443","tunnelType":"xray",
                 "prefs":{"primary":"vless://uuid@a.example:443?security=tls",
                          "backup":"trojan://token@b.example:443",
                          "dupe":"vless://uuid@a.example:443?security=tls"},
                 "customField":"unrecognized but preserved"},
                {"name":"Server B","hostPort":"b.example:80","tunnelType":"ssh",
                 "prefs":{"vmess":"vmess://e30=","other":"ss://abc@server:443"}}
            ],"customMetadata":{"keep":"everything"}}
        encoded=json.dumps(doc,ensure_ascii=False)
        self.assertTrue(structured.is_creeb(encoded))
        actual=json.loads(structured.decode_text(encoded))
        self.assertEqual(actual["original_bundle"],doc)
        self.assertEqual(actual["security"],doc["security"])
        self.assertEqual(actual["profiles"][0]["links"],
                         ["vless://uuid@a.example:443?security=tls",
                          "trojan://token@b.example:443"])
        self.assertEqual(len(actual["profiles"][1]["links"]),2)
        self.assertFalse(structured.is_creeb('{"type":"other","field":"creeb_profile_bundle"}'))

    def test_npvs_v5_offline_authenticator_reused_with_both_schemes(self):
        # Actual v5 signature/metadata/AEAD are tested by test_npvs_v5.py.
        # Here we test only the Base64 adapter; no fake decryption.
        raw=b"NPVS"+bytes(90)
        data={"metadata":{"creator":"fixture"},"document":{"configs":[{"sshHost":"npvs.example"}]}}
        with patch("decoders.Python.npvs.decode_npvs_complete",return_value=data) as dec:
            for scheme in ("npvs://","vpvs://"):
                output=structured.decode_text(scheme+b64(raw))
                self.assertEqual(json.loads(output),data)
                dec.assert_called_with(raw)
        self.assertIsNone(structured.decode_text("npvs://invalid!"))
        self.assertIsNone(structured.decode_text("vpvs://"+b64(b"not-NPVS")))

    def test_kivuvpn_uses_the_darktunnel_engine(self):
        with patch("decoders.Python.DARKTUNNEL.run",return_value='{"host":"kivu.example"}') as run:
            result=structured.decode_text("kivuvpn://synthetic-payload")
            self.assertEqual(json.loads(result)["host"],"kivu.example")
            run.assert_called_once_with(b"kivuvpn://synthetic-payload")

    def test_unknown_and_oversized_are_rejected(self):
        self.assertIsNone(structured.decode_text("other://something"))
        self.assertIsNone(structured.decode_text("vmess://"+("x"*(2*1024*1024+1))))
        self.assertIsNone(structured.decode_text("v2box://locked=bad%%"))
        self.assertIsNone(structured.decode_text("flex://INVALID"))


if __name__=="__main__":
    unittest.main()

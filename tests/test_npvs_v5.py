"""Native white-box vectors and optional authorized real-file regression tests.

SPDECODE_NPVS_REAL_FILE points to the private fixture; its contents are not
included in the repository or printed by these tests.
"""
import hashlib
import base64
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

SCRIPT = Path(__file__).resolve().parents[1] / "decoders/Python/npvs.py"
spec = importlib.util.spec_from_file_location("npvs_decoder", SCRIPT)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


class PrimitiveTests(unittest.TestCase):
    def test_secret_strings_in_nested_objects_and_lists(self):
        def wrapped(text):
            return "npvs1:" + base64.b64encode(text.encode("utf-8")).decode("ascii")

        original = {"configs": [{"sshConfig": {
            "sshConfigType": "npvs1:U1NILVRMUw==", "sshHost": wrapped("example.invalid"),
            "sshPort": 443, "sshUsername": wrapped("synthetic-user"),
            "sshPassword": wrapped("synthetic-password"), "sni": wrapped("sni.invalid"),
        }, "others": [wrapped("Prueba 日本語\r\n"), True, 0, None, "U1NILVRMUw=="]}],
                    "npvs1:a2V5": "plain"}
        result = decoder.decode_secret_strings(original)
        self.assertEqual(result["configs"][0]["sshConfig"], {
            "sshConfigType": "SSH-TLS", "sshHost": "example.invalid", "sshPort": 443,
            "sshUsername": "synthetic-user", "sshPassword": "synthetic-password",
            "sni": "sni.invalid"})
        self.assertEqual(result["configs"][0]["others"],
                         ["Prueba 日本語\r\n", True, 0, None, "U1NILVRMUw=="])
        self.assertEqual(result["npvs1:a2V5"], "plain")
        self.assertTrue(original["configs"][0]["sshConfig"]["sshHost"].startswith("npvs1:"))

    def test_secret_strings_one_layer_empty_and_base64_newlines(self):
        self.assertEqual(decoder.decode_secret_strings("npvs1:"), "")
        self.assertEqual(decoder.decode_secret_strings("npvs1:U1NI\r\nLVRMUw=="), "SSH-TLS")
        self.assertEqual(decoder.decode_secret_strings("npvs1:bnB2czE6WTI5dWRHVnVkQT09"),
                         "npvs1:Y29udGVudA==")
        for plain in ("", "not npvs1:U1NILVRMUw==", "NPVS1:U1NILVRMUw=="):
            self.assertEqual(decoder.decode_secret_strings(plain), plain)

    def test_secret_strings_reject_invalid_encoding(self):
        for text in ("npvs1:%%%", "npvs1:YQ", "npvs1:/w==", "npvs1:é"):
            with self.subTest(text=text), self.assertRaisesRegex(decoder.DecodeError, "npvs1"):
                decoder.decode_secret_strings(text)

    def test_native_whitebox_vectors(self):
        # Independently obtained by running the APK's ARM64 white-box routine.
        vectors = {
            "00000000000000000000000000000000": "4878126b14231f6f522f310686001524",
            "000102030405060708090a0b0c0d0e0f": "f659c73d8c0fa5150e3254dfe0a1106d",
            "ffffffffffffffffffffffffffffffff": "65c2e1759568da2929e357d637c33664",
        }
        for source, expected in vectors.items():
            with self.subTest(source=source):
                self.assertEqual(decoder._whitebox_block(bytes.fromhex(source)).hex(), expected)
        with self.assertRaises(decoder.DecodeError):
            decoder._whitebox_block(bytes(15))

    def test_json_and_go_string_canonicalization(self):
        self.assertEqual(decoder._canonical({"x": "<>&\u2028\u2029"}),
                         b'{"x":"\\u003c\\u003e\\u0026\\u2028\\u2029"}')
        for data in (b'{"x":1,"x":2}', b'NaN', b'Infinity', b'"\xff"', b'{'):
            with self.subTest(data=data), self.assertRaises(decoder.DecodeError):
                decoder._json_load(data)

    def test_invalid_input(self):
        for data in (b"", b"NPVS", bytes(100), b"NPVS\x06" + bytes(100),
                     b"NPVS\x05" + b"\xff" * 100):
            with self.assertRaises(decoder.DecodeError):
                decoder.decode_npvs(data)


@unittest.skipUnless(os.environ.get("SPDECODE_NPVS_REAL_FILE"),
                     "private real fixture not supplied")
class RealFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(os.environ["SPDECODE_NPVS_REAL_FILE"])
        cls.data = cls.source.read_bytes()
        if hashlib.sha256(cls.data).hexdigest() != REAL_FILE_SHA256:
            raise AssertionError("Wrong private regression fixture")
        cls.result = decoder.decode_npvs(cls.data)
        hlen = int.from_bytes(cls.data[5:9], "big")
        cls.header = cls.data[9:9 + hlen]
        cls.end = 9 + hlen
        cls.nonce = cls.data[cls.end:cls.end + 12]
        count = int.from_bytes(cls.header[51:53], "big")
        offset = 53 + count * 125
        cls.salt = cls.header[offset + 2:offset + 18]
        cls.wrapped = cls.header[offset + 18:offset + 78]
        cls.prefix = offset + 78
        cls.kdk = hashlib.sha256(b"npvtunnel/appkey/v2 "
                                + decoder._whitebox_block(cls.salt)
                                + cls.header[1:17]).digest()
        cls.dek = decoder._open(cls.kdk, cls.wrapped[:12], cls.wrapped[12:],
                                cls.salt, "document key")
        cls.body = cls.data[cls.end + 16:-64]
        cls.context = cls.body[4:36]

    def test_complete_document_and_entry_point(self):
        doc = self.result["document"]
        canonical = json.dumps(doc, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), REAL_DOCUMENT_SHA256)
        # Keep the authenticated wire representation as a separate regression anchor.
        raw = decoder._document(self.body, self.dek, self.context)
        raw_canonical = json.dumps(raw, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(raw_canonical).hexdigest(), REAL_RAW_DOCUMENT_SHA256)
        self.assertEqual(decoder.decode_secret_strings(raw), doc)

        def markers(value):
            if isinstance(value, dict):
                return sum(markers(v) for v in value.values())
            if isinstance(value, list):
                return sum(markers(v) for v in value)
            return int(isinstance(value, str) and value.startswith("npvs1:"))

        self.assertEqual(markers(raw), 3)
        self.assertEqual(markers(doc), 0)
        self.assertEqual(len(doc["configs"]), 1)

        def leaves(value):
            if isinstance(value, dict):
                return sum(leaves(v) for v in value.values())
            if isinstance(value, list):
                return sum(leaves(v) for v in value)
            return 1

        self.assertEqual(leaves(doc), 106)
        self.assertEqual(int.from_bytes(self.body[36:38], "big"), 107)
        self.assertEqual(json.loads(decoder.run(self.data)), self.result)

    def test_every_truncated_prefix_and_trailing_byte(self):
        for length in range(len(self.data)):
            with self.subTest(length=length), self.assertRaises(decoder.DecodeError):
                decoder.decode_npvs(self.data[:length])
        with self.assertRaises(decoder.DecodeError):
            decoder.decode_npvs(self.data + b"\x00")

    def test_signature_rejects_header_nonce_body_and_signature_changes(self):
        for position in (10, 70, self.end, self.end + 60, len(self.data) - 1):
            changed = bytearray(self.data)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(
                    decoder.DecodeError, "ECDSA"):
                decoder.decode_npvs(bytes(changed))

    def test_document_key_and_metadata_authentication(self):
        changed = self.wrapped[12:-1] + bytes([self.wrapped[-1] ^ 1])
        with self.assertRaisesRegex(decoder.DecodeError, "Authentication failed"):
            decoder._open(self.kdk, self.wrapped[:12], changed, self.salt, "document key")
        mkey = HKDF(self.dek, 32, self.nonce, SHA256, context=b"NPVS-v5/metadata")
        metadata = self.header[self.prefix + 4:]
        changed = metadata[:-1] + bytes([metadata[-1] ^ 1])
        with self.assertRaisesRegex(decoder.DecodeError, "Authentication failed"):
            decoder._open(mkey, self.nonce, changed, self.header[:self.prefix], "metadata")

    def test_metadata_binding_and_inventory_authentication(self):
        with self.assertRaisesRegex(decoder.DecodeError, "metadata binding"):
            decoder._document(self.body, self.dek, bytes(32))
        changed = self.body[:-1] + bytes([self.body[-1] ^ 1])
        with self.assertRaisesRegex(decoder.DecodeError, "inventory HMAC"):
            decoder._document(changed, self.dek, self.context)

    def test_each_field_authentication_independent_of_inventory(self):
        pos = 38
        for _ in range(int.from_bytes(self.body[36:38], "big")):
            field_id = int.from_bytes(self.body[pos:pos + 2], "big")
            length = int.from_bytes(self.body[pos + 2:pos + 6], "big")
            changed = bytearray(self.body)
            changed[pos + 6 + length - 1] ^= 1
            # Re-authenticate inventory to reach the changed field's AEAD check.
            changed[-32:] = hmac.new(
                decoder._field_key(self.dek, self.context, b"inventory", 0),
                changed[:-32], hashlib.sha256).digest()
            with self.subTest(field=field_id), self.assertRaisesRegex(
                    decoder.DecodeError, f"Authentication failed: field {field_id}$"):
                decoder._document(bytes(changed), self.dek, self.context)
            pos += 6 + length

    def test_cli_output_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decoded.json"
            good = subprocess.run([sys.executable, str(SCRIPT), str(self.source),
                                   "-o", str(output)], capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout, "")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), self.result)
            bad_input = Path(directory) / "invalid.npvs"
            bad_input.write_bytes(self.data[:-1])
            bad = subprocess.run([sys.executable, str(SCRIPT), str(bad_input)],
                                 capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1)
            self.assertEqual(bad.stdout, "")
            self.assertIn("Error:", bad.stderr)


# Digests only; no private fixture, plaintext credentials, or per-file keys.
REAL_FILE_SHA256 = "2e321bb8c506dbac8a1b2848ff8a05fb4f811df34536853b2a965d6dfd197867"
REAL_RAW_DOCUMENT_SHA256 = "eaa7e033fa9c5677d605628a4bbc32961c1b61c44e0e329393fe8776eaa47bfb"
REAL_DOCUMENT_SHA256 = "efd51583558b21c2683a242fa0583f45afc0c2044108d50b549247755883bbde"

if __name__ == "__main__":
    unittest.main()

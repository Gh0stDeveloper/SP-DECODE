"""Real recipient regression. Private files/keys are supplied only via env vars.

SPDECODE_NPVS_V6_REAL_FILE and SPDECODE_NPVS_V6_PRIVATE_KEY select the
authorized export and its PEM/DER/key JSON. Neither is committed or printed.
"""
import base64
import hashlib
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
from Crypto.PublicKey import ECC

SCRIPT = Path(__file__).resolve().parents[1] / "decoders/Python/npvs.py"
spec = importlib.util.spec_from_file_location("npvs_recipient_decoder", SCRIPT)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


class PrivateKeyTests(unittest.TestCase):
    def test_import_formats_and_reject_public_key_or_hwid(self):
        key = ECC.construct(curve="P-256", d=1)  # Synthetic test key only.
        pem = key.export_key(format="PEM", use_pkcs8=True)
        for value in (key, pem, pem.encode(), key.export_key(format="DER"),
                      {"private_key_pkcs8_pem": pem},
                      json.dumps({"private_key_pkcs8_pem": pem}).encode()):
            self.assertEqual(decoder._private_key(value).d, key.d)
        for value in (key.public_key(), key.public_key().export_key(format="PEM"),
                      "h" + "ab" * 16,
                      base64.urlsafe_b64encode(key.public_key().export_key(
                          format="SEC1", compress=True)).decode().rstrip("="),
                      ECC.construct(curve="P-384", d=1), {}, None):
            with self.subTest(kind=type(value).__name__), self.assertRaises(decoder.DecodeError):
                decoder._private_key(value)


@unittest.skipUnless(os.environ.get("SPDECODE_NPVS_V6_REAL_FILE")
                     and os.environ.get("SPDECODE_NPVS_V6_PRIVATE_KEY"),
                     "private real recipient fixture/key not supplied")
class RealRecipientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(os.environ["SPDECODE_NPVS_V6_REAL_FILE"])
        cls.keyfile = Path(os.environ["SPDECODE_NPVS_V6_PRIVATE_KEY"])
        cls.data = cls.source.read_bytes()
        cls.key = decoder._private_key(cls.keyfile.read_bytes())
        if hashlib.sha256(cls.data).hexdigest() != REAL_FILE_SHA256:
            raise AssertionError("Wrong private recipient regression fixture")
        cls.result = decoder.decode_npvs(cls.data, cls.key)
        cls.header = cls.data[9:9 + int.from_bytes(cls.data[5:9], "big")]
        cls.end = 9 + len(cls.header)
        cls.nonce = cls.data[cls.end:cls.end + 12]
        count = int.from_bytes(cls.header[51:53], "big")
        cls.recipients = [(cls.header[53 + i * 125:85 + i * 125],
                           cls.header[85 + i * 125:178 + i * 125]) for i in range(count)]
        cls.config_id = cls.header[1:17]
        cls.prefix = 53 + count * 125 + 16
        cls.salt = cls.header[cls.prefix - 16:cls.prefix]
        cls.masked = decoder._unwrap_recipient(cls.config_id, cls.recipients, cls.key)
        kdk = hashlib.sha256(b"npvtunnel/appkey/v2 "
                             + decoder._whitebox_block(cls.salt) + cls.config_id).digest()
        pad = HKDF(kdk, 32, cls.salt, SHA256,
                   context=b"NPVS-v6/recipient-binding" + cls.config_id)
        cls.dek = bytes(a ^ b for a, b in zip(cls.masked, pad))
        cls.body = cls.data[cls.end + 16:-64]

    def test_complete_json_and_api(self):
        canonical = json.dumps(self.result["document"], ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), REAL_DOCUMENT_SHA256)
        self.assertEqual(len(self.recipients), 2)
        self.assertEqual(int.from_bytes(self.body[36:38], "big"), 8)
        self.assertEqual(json.loads(decoder.run(self.data, self.keyfile.read_bytes())), self.result)
        self.assertEqual(decoder.decode_npvs(self.data, self.key.export_key(format="DER")), self.result)

    def test_missing_wrong_and_public_keys_fail(self):
        with self.assertRaisesRegex(decoder.DecodeError, "requires"):
            decoder.decode_npvs(self.data)
        with self.assertRaisesRegex(decoder.DecodeError, "does not match"):
            decoder.decode_npvs(self.data, ECC.construct(curve="P-256", d=1))
        with self.assertRaisesRegex(decoder.DecodeError, "private key"):
            decoder.decode_npvs(self.data, self.key.public_key())

    def test_each_truncated_prefix_and_trailing_bytes(self):
        for length in range(len(self.data)):
            with self.subTest(length=length), self.assertRaises(decoder.DecodeError):
                decoder.decode_npvs(self.data[:length], self.key)
        with self.assertRaises(decoder.DecodeError):
            decoder.decode_npvs(self.data + b"\x00", self.key)

    def test_signature_rejects_all_layers(self):
        for position in (10, 100, self.prefix + 8, self.end, self.end + 60, len(self.data) - 1):
            changed = bytearray(self.data)
            changed[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(decoder.DecodeError, "ECDSA"):
                decoder.decode_npvs(bytes(changed), self.key)

    def test_recipient_gcm_tag_and_config_id_binding(self):
        fp = hashlib.sha256(self.key.public_key().export_key(format="SEC1", compress=True)).digest()
        wrap = next(w for f, w in self.recipients if f == fp)
        damaged = wrap[:-1] + bytes([wrap[-1] ^ 1])
        for config_id, recipients in ((self.config_id, [(fp, damaged)]),
                                       (bytes(16), [(fp, wrap)])):
            with self.assertRaisesRegex(decoder.DecodeError, "recipient document key"):
                decoder._unwrap_recipient(config_id, recipients, self.key)

    def test_binding_pad_and_metadata_aead(self):
        meta = self.header[self.prefix + 4:]
        # A successful recipient unwrap alone is insufficient: v6 requires the pad.
        for wrong_key in (self.masked, bytes(32)):
            mkey = HKDF(wrong_key, 32, self.nonce, SHA256, context=b"NPVS-v5/metadata")
            with self.assertRaisesRegex(decoder.DecodeError, "Authentication failed"):
                decoder._open(mkey, self.nonce, meta, self.header[:self.prefix], "metadata")
        mkey = HKDF(self.dek, 32, self.nonce, SHA256, context=b"NPVS-v5/metadata")
        self.assertEqual(decoder._json_load(decoder._open(
            mkey, self.nonce, meta, self.header[:self.prefix], "metadata")), self.result["metadata"])
        damaged = meta[:-1] + bytes([meta[-1] ^ 1])
        with self.assertRaisesRegex(decoder.DecodeError, "Authentication failed"):
            decoder._open(mkey, self.nonce, damaged, self.header[:self.prefix], "metadata")

    def test_cli_success_and_no_output_on_missing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decoded.json"
            good = subprocess.run([sys.executable, str(SCRIPT), str(self.source),
                                   "--private-key", str(self.keyfile), "-o", str(output)],
                                  capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(json.loads(output.read_text()), self.result)
            output.unlink()
            bad = subprocess.run([sys.executable, str(SCRIPT), str(self.source), "-o", str(output)],
                                 capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1)
            self.assertEqual(bad.stdout, "")
            self.assertFalse(output.exists())


REAL_FILE_SHA256 = "53736090f3b86b465be39793257f664b6af0a155027e804cfb671c6f06931fae"
REAL_DOCUMENT_SHA256 = "1eb7c5628bb64fb8fc2f04c18db20967baa8aa33816f6972af6e318cfff73d9f"

if __name__ == "__main__":
    unittest.main()

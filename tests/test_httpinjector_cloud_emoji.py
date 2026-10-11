"""Fixtures sintéticas públicas; pruebas reales opcionales mediante variables de entorno."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "decoders" / "Python"))
import HTTPINJECTOR_CLOUD as cloud
import HTTPINJECTOR_EMOJI as emoji
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def envelope(imported=None, compressed=None):
    if compressed is None:
        compressed = zlib.compress(json.dumps(imported).encode("utf-8"))
    iv = bytes(range(16))
    ciphertext = AES.new(cloud.API_KEY, AES.MODE_CBC, iv).encrypt(pad(compressed, 16))
    tag = hmac.new(cloud.API_KEY, ciphertext, hashlib.sha256).digest()
    return {"code": 200, "data": base64.b64encode(iv + tag + ciphertext).decode("ascii")}


class CloudTests(unittest.TestCase):
    def test_reference_and_no_other_hosts(self):
        self.assertEqual(cloud.parse_reference(b"https://ehi.link/TEST1234\n"), "TEST1234")
        self.assertEqual(cloud.parse_reference("ehi://ehi.link/TEST1234"), "TEST1234")
        for bad in ("https://ehi.link.evil/TEST1234", "https://user@ehi.link/TEST1234",
                    "http://ehi.link/TEST1234", "https://ehi.link/TEST1234?q=x", "../key"):
            with self.subTest(bad=bad), self.assertRaises(cloud.CloudError):
                cloud.parse_reference(bad)

    def test_java_urlencoder_and_fixed_signature(self):
        self.assertEqual(cloud.java_urlencode("a b+~*/="), "a%2Bb%2B%7E*%2F%3D")
        body, headers = cloud.build_request("TEST1234", timestamp=1700000000,
            nonce="11111111-2222-3333-4444-555555555555", identity="SP-DECODE-test")
        self.assertEqual(body, b"config_key=TEST1234")
        self.assertEqual(headers["x-signature"], "nmBQPYrP05rkKDv3NDH%2FIZlOa48%3D")

    def test_transport_crypto_roundtrip(self):
        expected = {"status": "success", "config_data": "", "achilles": "test"}
        audit = {}
        self.assertEqual(cloud.decrypt_api_response(envelope(expected), audit), expected)
        self.assertTrue(audit["api_hmac_verified"])

    def test_modified_tag_or_ciphertext_rejected(self):
        good = envelope({"status": "success"})
        raw = base64.b64decode(good["data"])
        for offset in (16, 48, len(raw) - 1):
            changed = bytearray(raw); changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaisesRegex(cloud.CloudError, "HMAC"):
                cloud.decrypt_api_response({"code": 200, "data": base64.b64encode(changed).decode()})

    def test_app_does_not_mac_iv_but_invalid_zlib_is_rejected(self):
        raw = bytearray(base64.b64decode(envelope({"status": "success"})["data"]))
        raw[0] ^= 1
        with self.assertRaisesRegex(cloud.CloudError, "zlib"):
            cloud.decrypt_api_response({"code": 200, "data": base64.b64encode(raw).decode()})

    def test_server_errors_and_malformed_envelopes(self):
        invalid = [b"not json", [], {"code": 401}, {"code": 200, "data": "?"},
                   {"code": 200, "data": base64.b64encode(b"short").decode()},
                   envelope({"status": "error", "message": "Expired"})]
        for value in invalid:
            with self.subTest(value_type=type(value)), self.assertRaises(cloud.CloudError):
                cloud.decrypt_api_response(value)

    def test_bounded_and_truncated_zlib(self):
        compressed = zlib.compress(b"a" * 2048)
        with mock.patch.object(cloud, "MAX_INFLATED_BYTES", 1024):
            with self.assertRaisesRegex(cloud.CloudError, "límite"):
                cloud.decrypt_api_response(envelope(compressed=compressed))
        for bad in (compressed[:-1], compressed + b"extra"):
            with self.assertRaises(cloud.CloudError):
                cloud.decrypt_api_response(envelope(compressed=bad))

    @unittest.skipUnless(os.environ.get("EHI_CLOUD_RESPONSE"), "respuesta real privada no disponible")
    def test_real_cloud_response_and_emoji_dispatch(self):
        response = Path(os.environ["EHI_CLOUD_RESPONSE"]).read_bytes()
        audit = {}
        document = cloud.decode_response(response, audit)
        self.assertEqual(len(document), 48)
        self.assertTrue(audit["api_hmac_verified"])
        self.assertTrue(audit["ehi"]["authenticated"])
        self.assertEqual(audit["ehi"]["profile"], "standard-2")
        self.assertEqual(audit["ehi"]["transformed_fields"],
                         ["/configMessage", "/sniHostname", "/tlsVersion"])
        self.assertNotIn("input_sha256", audit["ehi"])
        if os.environ.get("EHI_CLOUD_EXPECTED"):
            self.assertEqual(document, json.loads(Path(os.environ["EHI_CLOUD_EXPECTED"]).read_text()))
        # La referencia de esta prueba es sintética; el ciphertext sí es real.
        with mock.patch.object(cloud, "fetch_response", return_value=response) as fetch:
            emoji_audit = {}
            self.assertEqual(emoji.decode_emoji("💉😩😘😩😧😩😗😘🙌😠🙍😤😐🚀", emoji_audit), document)
            fetch.assert_called_once_with("TEST1234", 20)
            self.assertEqual(emoji_audit["transport"], "http-injector-emoji")


class EmojiTests(unittest.TestCase):
    def test_known_unicode_vector(self):
        token = "💉😩😘😩😧😩😗😘🙌😠🙍😤😐🚀"  # VEVTVDEyMzQ= -> TEST1234
        self.assertEqual(emoji.decode_emoji_key(token), "TEST1234")
        self.assertEqual(emoji.encode_emoji_key("TEST1234"), token)
        self.assertEqual(emoji.decode_emoji_key((token + "\n").encode()), "TEST1234")

    def test_malformed_symbols_base64_and_utf8(self):
        token = emoji.encode_emoji_key("TEST1234")
        # Base64 jg== codifica 0x8E; no convertirlo silenciosamente a U+FFFD.
        bad_utf8 = "💉" + "".join(chr(128467 + ord(c)) for c in "jg==") + "🚀"
        with self.assertRaisesRegex(emoji.EmojiError, "UTF-8 inválido en el byte 0"):
            emoji.decode_emoji_key(bad_utf8)
        for bad in ("", token[1:], token[:-1], "💉😩\uFE0F🚀", "💉a🚀", "💉😩🚀",
                    "💉" + "".join(chr(128467 + ord(c)) for c in "VEVTVDEyMzR=") + "🚀"):
            with self.subTest(bad=bad), self.assertRaises(emoji.EmojiError):
                emoji.decode_emoji_key(bad)

    def test_emoji_contains_reference_not_offline_configuration(self):
        token = emoji.encode_emoji_key("TEST1234")
        with mock.patch.object(cloud, "fetch_response", side_effect=cloud.CloudError("sin red")):
            with self.assertRaisesRegex(cloud.CloudError, "sin red"):
                emoji.decode_emoji(token)


if __name__ == "__main__":
    unittest.main()

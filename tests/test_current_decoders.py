from __future__ import annotations

import base64
import json
import unittest

from decoders.Python.EV2RAY import DELIMITER, run as decode_ev2ray
from decoders.Python.TLS import AES_KEY, run as decode_tls

try:
    from Crypto.Cipher import AES as _CryptoAES
except ImportError:
    _CryptoAES = None


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _aes_gcm_encrypt(nonce: bytes, plaintext: bytes) -> bytes:
    if _CryptoAES is not None:
        cipher = _CryptoAES.new(AES_KEY, _CryptoAES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext + tag

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(AES_KEY).encrypt(nonce, plaintext, None)


def _tls_fixture() -> bytes:
    parts = [""] * 28
    parts[0] = "7"
    parts[1] = "1"
    parts[2] = "443"
    parts[3] = "true"
    parts[4] = _b64("ghost")
    parts[5] = _b64("secret")
    parts[6] = _b64("ssh.example.com")
    parts[7] = _b64("443")
    parts[9] = _b64("22")
    parts[10] = "2"
    parts[11] = "true"
    parts[12] = _b64("GET / HTTP/1.1")
    parts[13] = "true"
    parts[14] = _b64("sni.example.com")
    parts[25] = "false"
    parts[27] = _b64("Perfil de prueba")
    plaintext = ":".join(parts).encode("utf-8")
    if len(plaintext) % 2:
        plaintext += b":"

    nonce = bytes(range(36))
    encrypted = _aes_gcm_encrypt(nonce, plaintext)
    half = len(encrypted) // 2
    raw = (
        b"\x00" * 12
        + encrypted[:half][::-1]
        + nonce[:18][::-1]
        + encrypted[half:][::-1]
        + nonce[18:][::-1]
        + b"\x00" * 84
    )
    return base64.b64encode(raw)[::-1]


class CurrentDecoderTests(unittest.TestCase):
    def test_tls_current_aes_gcm_container(self):
        output = decode_tls(b"tls://" + _tls_fixture())
        self.assertIsNotNone(output)
        self.assertIn('"sshuser": "ghost"', output)
        self.assertIn('"sshhost": "ssh.example.com"', output)
        self.assertIn('"snihost": "sni.example.com"', output)

    def test_ev2ray_current_profile_layers(self):
        v2ray_config = {
            "v": "2",
            "ps": "SP-DECODE test",
            "add": "v2.example.com",
            "port": "443",
        }
        plaintext = DELIMITER.join(
            (
                _b64("Perfil e-V2Ray"),
                _b64(json.dumps(v2ray_config, separators=(",", ":"))),
                "true",
            )
        ).encode("utf-8")
        output = decode_ev2ray(plaintext)
        self.assertIsNotNone(output)
        self.assertIn("Perfil e-V2Ray", output)
        self.assertIn('"add":"v2.example.com"', output)


if __name__ == "__main__":
    unittest.main()

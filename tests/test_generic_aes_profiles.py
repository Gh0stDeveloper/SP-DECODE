"""Source-compatible AES-GCM/PBKDF2 synthetic positive and negative fixtures."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

from decoders.Python.generic_aes import (
    AES_PROFILES, decrypt_with_extension, render_plaintext, run as aes_run,
)
from decoders.Python.generic_profiles import generic_specs

ROOT = Path(__file__).resolve().parents[1]


def encrypt_aes_profile(plaintext: str, password: bytes, salt=None, nonce=None) -> bytes:
    salt = bytes(range(16)) if salt is None else salt
    nonce = bytes(range(12)) if nonce is None else nonce
    key = PBKDF2(password, salt, dkLen=16, count=1000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return b".".join(base64.b64encode(piece) for piece in (
        salt, nonce, ciphertext + tag,
    ))


class GenericAESGoldenTests(unittest.TestCase):
    def test_every_unclaimed_aes_profile_decrypts_independently(self):
        specs = generic_specs(set())
        all_candidates = {
            ext for ext in specs if ext in AES_PROFILES
        }
        # Profiles also present in the DES table are deliberately tested here.
        self.assertEqual(len(all_candidates), 94)
        for ext in sorted(all_candidates):
            profile = AES_PROFILES[ext]
            with self.subTest(extension=ext):
                config = {"app": "Generic VPN", "extension": ext,
                          "sshServer": "synthetic.example",
                          "sshPass": "test-only-password",
                          "port": 443, "enabled": False,
                          "nested": {"sni": "sni.example"},
                          "notes": "Prueba 日本語"}
                plain = json.dumps(config, ensure_ascii=False)
                payload = encrypt_aes_profile(plain, profile[0])
                output = aes_run(payload, ext)
                self.assertIsNotNone(output)
                self.assertEqual(json.loads(output), config)
                # A bad authentication tag must never generate plaintext.
                parts = payload.split(b".")
                sealed = bytearray(base64.b64decode(parts[2]))
                sealed[-1] ^= 1  # Change an actual authenticated tag byte.
                altered = b".".join((
                    parts[0], parts[1], base64.b64encode(sealed),
                ))
                self.assertIsNone(aes_run(altered, ext))

    def test_multiple_historical_keys_preserve_order_and_fallback(self):
        for ext in (".ziv", ".tnl", ".pb", ".cks"):
            for index, password in enumerate(AES_PROFILES[ext]):
                with self.subTest(ext=ext, profile=index):
                    content = json.dumps({"extension": ext, "profile": index})
                    encrypted = encrypt_aes_profile(content, password)
                    self.assertEqual(json.loads(aes_run(encrypted, ext)),
                                     json.loads(content))

    def test_profile_selection_does_not_bruteforce_other_extensions(self):
        packet = encrypt_aes_profile('{"sshServer":"test.invalid"}', AES_PROFILES[".ace"][0])
        self.assertIsNotNone(aes_run(packet, ".ace"))
        self.assertIsNone(aes_run(packet, ".cks"))

    def test_complete_xml_and_empty_entries_are_preserved(self):
        original = (
            '<entry key="sshServer">test.invalid</entry>\n'
            '<entry key="sshUser">Ghost</entry>\n'
            '<entry key="sshPass">temporary &amp; only</entry>\n'
            '<entry key="Empty"/>\n'
            '<entry key="sshPass">second value</entry>'
        )
        cipher = encrypt_aes_profile(original, AES_PROFILES[".ace"][0])
        output = json.loads(aes_run(cipher, ".ace"))
        self.assertEqual(output["raw_xml"], original)
        self.assertEqual(len(output["entries"]), 5)
        self.assertEqual(output["entries"][2]["value"], "temporary &amp; only")
        self.assertEqual(output["entries"][3]["value"], "")
        self.assertEqual(output["entries"][4]["value"], "second value")

    def test_non_json_authenticated_content_kept_as_text(self):
        clear = "server=test.invalid\nport=443\nuser=ghost"
        packet = encrypt_aes_profile(clear, AES_PROFILES[".ace"][0])
        self.assertEqual(aes_run(packet, ".ace"), clear)

    def test_malformed_and_oversized_fail_closed(self):
        for packet in (
            b"", b"not.a.base64.config", b"only.two",
            b"!!!.!!!.!!!", b"A" * (2 * 1024 * 1024 + 1)
        ):
            with self.subTest(packet=packet[:12]):
                self.assertIsNone(aes_run(packet, ".ace"))

    def test_cli_positive_invalid_and_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "export.ace"
            content = {"Host": "ace.example", "SSH": "ghost"}
            packet = encrypt_aes_profile(json.dumps(content), AES_PROFILES[".ace"][0])
            file.write_bytes(packet)
            command = [sys.executable, str(ROOT / "decoders/Python/generic_aes.py"), str(file)]
            good = subprocess.run(command, capture_output=True, text=True,
                                  cwd=ROOT, timeout=30)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(json.loads(good.stdout), content)
            file.write_bytes(b"garbage")
            bad = subprocess.run(command, capture_output=True, text=True,
                                 cwd=ROOT, timeout=30)
            self.assertEqual(bad.returncode, 1)
            self.assertFalse(bad.stdout.strip())


if __name__ == "__main__":
    unittest.main()

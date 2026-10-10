"""DES-ECB profile positive vectors, AES collision fallbacks, CLI and tampering."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import DES

from decoders.Python.generic_aes import AES_PROFILES
from decoders.Python.generic_des import (
    DES_PROFILES, decrypt_des_with_extension, run as des_run,
)
from decoders.Python.generic_profiles import generic_specs
from tests.test_generic_aes_profiles import encrypt_aes_profile

ROOT = Path(__file__).resolve().parents[1]
SHARED = {".acm", ".htp", ".pin", ".tut", ".vmx", ".xsks"}


def encrypt_des_profile(plain: str, password: bytes) -> bytes:
    # 66.py pads the encryption key to 8 bytes with NULs, truncating any
    # original password longer than 8; plaintext uses space padding.
    key = password[:8].ljust(8, b"\0")
    raw = plain.encode("utf-8")
    raw += b" " * (-len(raw) % 8)
    return DES.new(key, DES.MODE_ECB).encrypt(raw)


class GenericDESGoldenTests(unittest.TestCase):
    def test_all_21_historical_des_profiles(self):
        self.assertEqual(len(DES_PROFILES), 21)
        for ext, password in DES_PROFILES.items():
            with self.subTest(extension=ext):
                xml = (
                    f'<entry key="ext">{ext}</entry>\n'
                    '<entry key="Host">synthetic.example</entry>\n'
                    '<entry key="User">ghost</entry>\n'
                    '<entry key="Password">fixture-only-password</entry>\n'
                    '<entry key="Empty"/>'
                )
                payload = encrypt_des_profile(xml, password)
                result = des_run(payload, ext)
                self.assertIsNotNone(result)
                decoded = json.loads(result)
                self.assertEqual(decoded["entries"][0]["value"], ext)
                self.assertEqual(decoded["entries"][3]["value"], "fixture-only-password")
                self.assertIn('key="Empty"', decoded["raw_xml"])
                self.assertEqual(decrypt_des_with_extension(payload, ext).strip(), xml)

    def test_13_new_des_registrations_and_6_collisions(self):
        new_des = [
            ext for ext, (label, script) in generic_specs(set()).items()
            if script == "decoders/Python/generic_des.py"
        ]
        self.assertEqual(len(new_des), 21)
        new_des_only = sorted(set(new_des) - {".ost", ".fɴ", ".cly", ".jvi", ".jvc", ".v2i", ".sbr", ".itv"})
        self.assertEqual(len(new_des_only), 13)
        for ext in new_des_only:
            with self.subTest(ext=ext):
                profile = DES_PROFILES[ext]
                xml = '<entry key="Host">des.example</entry>'
                output = des_run(encrypt_des_profile(xml, profile), ext)
                self.assertEqual(json.loads(output)["entries"][0]["value"], "des.example")
        self.assertEqual(set(new_des_only) & set(AES_PROFILES), SHARED)

    def test_aes_authenticated_fallback_on_all_six_ambiguous_suffixes(self):
        for ext in sorted(SHARED):
            with self.subTest(extension=ext):
                config = {"extension": ext, "Host": "gcm.example", "Port": 443}
                packet = encrypt_aes_profile(json.dumps(config), AES_PROFILES[ext][0])
                result = des_run(packet, ext)
                self.assertIsNotNone(result)
                self.assertEqual(json.loads(result), config)

    def test_des_base64_wrap_not_confused_with_gcm_envelope(self):
        xml = '<entry key="sshServer">des.example</entry>'
        raw = encrypt_des_profile(xml, DES_PROFILES[".clay"])
        self.assertEqual(json.loads(des_run(base64.b64encode(raw), ".clay"))["entries"][0]["value"],
                         "des.example")
        self.assertIsNone(des_run(b"A.B.C", ".clay"))

    def test_no_false_positive_for_random_bytes(self):
        for ext in (".clay", ".vpc", ".acm"):
            for payload in (b"", b"garbage\x00", b"\0" * 64, b"\xff" * 32,
                            b"0" * (2 * 1024 * 1024 + 1)):
                with self.subTest(ext=ext, size=len(payload)):
                    self.assertIsNone(des_run(payload, ext))

    def test_cli_positive_and_negative(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "file.clay"
            path.write_bytes(encrypt_des_profile(
                '<entry key="Server">cli.example</entry>', DES_PROFILES[".clay"]))
            command = [sys.executable, str(ROOT / "decoders/Python/generic_des.py"), str(path)]
            ok = subprocess.run(command, cwd=ROOT, capture_output=True,
                                text=True, timeout=30)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(json.loads(ok.stdout)["entries"][0]["value"], "cli.example")
            path.write_bytes(b"not valid")
            bad = subprocess.run(command, cwd=ROOT, capture_output=True,
                                 text=True, timeout=30)
            self.assertEqual(bad.returncode, 1)
            self.assertFalse(bad.stdout.strip())


if __name__ == "__main__":
    unittest.main()

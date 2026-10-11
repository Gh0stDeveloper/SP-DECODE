"""Fixtures sintéticas independientes; muestras comerciales sólo vía entorno."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from Crypto.Cipher import ChaCha20_Poly1305
from argon2.low_level import hash_secret_raw, Type

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "decoders" / "Python"))
import HTTPCUSTOM_AUTH as hc

TEST_PASSWORD = "demo password "
TEST_HWID = "h" + "1" * 31


def seal(key, aad, data, nonce):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext + tag


def hkdf(ikm, salt, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def fixture(password=None, hwids=(), outer_v3=False, bad_hpr=False):
    """Writer de prueba; no llama a _derive, _transcript ni _pw_kdf del decoder."""
    env = {"a": "HCCFG", "b": 7, "c": "s1", "d": "h1", "e": "n8" if hwids else "n7",
           "f": ["ssh", "profiles"], "g": bytes(range(32)).hex(), "h": int(password is not None),
           "n": 885}
    ekey = bytes(range(32)); package = b"xyz.easypro.httpcustom"
    aad_protection = b"|0"
    password_key = b""
    if password is not None:
        env.update(k="a1", l=1, m=8192)
        password_key = hash_secret_raw(password.encode(), ekey[:16], time_cost=1,
            memory_cost=8, parallelism=1, hash_len=32, type=Type.ID, version=19)
        aad_protection = b"|1|ARGON2ID13|1|8192"
    aad = (b"HCCFG|7|XCHACHA20P1305|NATIVE-HKDF-SHA256|" + env["e"].encode()
           + b"|" + package + b"|1|ssh,profiles" + aad_protection + b"|885")

    def wrapping_key(hwid=None):
        normalized = hwid.strip().upper().encode() if hwid is not None else None
        transcript = b"HCCFG\0" + package + b"\0" + b"1\0ssh,profiles\0" + b"885\0"
        if normalized is not None:
            transcript += b"hwid\0" + normalized + b"\0"
        transcript += ekey
        material = hmac.new(hc.N7_HMAC_KEY, b"\xd3" + hc.C0_PREFIX[:32] + transcript,
                            hashlib.sha256).digest() + password_key
        info = b"app-config|" + env["e"].encode() + b"|" + package + b"|1|ssh,profiles|885"
        if normalized is not None:
            info += b"|hwid|" + normalized
        return hkdf(material, ekey, info)

    key = b"\xa5" * 32 if hwids else wrapping_key()
    if hwids:
        env["o"] = []
        for i, hwid in enumerate(hwids):
            nonce = bytes([10 + i]) * 24
            env["o"].append({"a": nonce.hex(), "b": seal(wrapping_key(hwid), aad + b"\0w", key, nonce).hex()})
    main = {"g": {"a": "test", "f": bool(hwids)}, "unknown": {"array": [False, None, 42]}}
    main_nonce = bytes([2]) * 24
    env["i"] = {"a": "main", "b": main_nonce.hex(),
                "c": seal(key, aad + b"\0main", json.dumps(main).encode(), main_nonce).hex()}
    text = lambda s: struct.pack(">I", len(s.encode())) + s.encode()
    opts = {"sni": "example.org", "nested": {"enabled": True, "ports": [443, 80]}}
    profile = (b"HPC1" + struct.pack(">I", 11) + text("Prueba 🧪") + text("ssh") + text("example.org")
               + struct.pack(">I", 443) + text("dummy-user") + text("dummy-password")
               + text("GET / HTTP/1.1\r\n\r\n") + text(json.dumps(opts))
               + struct.pack(">I", 7) + struct.pack(">Q", 1700000000000) + text("ssh_tls"))
    hpr_nonce = bytes([3]) * 24
    hpr = b"HPR1" + hpr_nonce + seal(key, aad + b"\0s0:r", profile, hpr_nonce)
    if bad_hpr:
        hpr = hpr[:-1] + bytes([hpr[-1] ^ 1])
    sec_nonce = bytes([4]) * 24
    env["j"] = [{"a": "s0", "b": sec_nonce.hex(),
                 "c": seal(key, aad + b"\0s0", hpr, sec_nonce).hex(),
                 "d": {"a": (bytes([5])*24).hex(),
                       "b": seal(key, aad + b"\0s0:x", b"sidecar\r\n", bytes([5])*24).hex()}}]
    return pack(env, outer_v3), env, main


def pack(env, v3=False):
    plaintext = json.dumps(env, separators=(",", ":"), ensure_ascii=False).encode()
    nonce = bytes([6]) * 24
    if v3:
        # App stream-v3 reserva 16 bytes finales; no se afirma que sean MAC.
        from Crypto.Cipher import ChaCha20
        cipher = ChaCha20.new(key=hc.OUTER_KEY_V3, nonce=nonce); cipher.seek(64)
        logical = nonce + cipher.encrypt(plaintext) + bytes(16)
    else:
        seed = hashlib.sha256(hc.C0_PREFIX + hc.OUTER_SEED).digest()
        logical = nonce + seal(hkdf(seed, hc.OUTER_SALT, hc.OUTER_INFO), hc.OUTER_AAD, plaintext, nonce)
    return logical.decode("latin1").encode("utf-8")


class AuthTests(unittest.TestCase):
    def test_unlocked_preserves_every_hpc_field_and_main_metadata(self):
        data, _, main = fixture()
        result = hc.decode(data)
        self.assertEqual(result["main_config"], main)
        profile = result["config"][0]
        self.assertEqual(profile["name"], "Prueba 🧪")
        self.assertEqual(profile["flags"], 7)
        self.assertEqual(profile["updated_at_ms"], 1700000000000)
        self.assertEqual(profile["label"], "s0")
        self.assertEqual(profile["payload"], "GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(profile["custom_payload_sidecar"], "sidecar\r\n")
        self.assertEqual(profile["options"]["nested"]["ports"], [443, 80])

    def test_password_is_exact_and_required(self):
        data, _, _ = fixture(password=TEST_PASSWORD)
        with self.assertRaises(hc.HCError) as error: hc.decode(data)
        self.assertEqual(error.exception.code, "PASSWORD_REQUIRED")
        self.assertEqual(error.exception.required, ["password"])
        hc.decode(data, password=TEST_PASSWORD)
        for bad in (TEST_PASSWORD.strip(), TEST_PASSWORD.upper(), "wrong"):
            with self.assertRaises(hc.HCError) as error: hc.decode(data, password=bad)
            self.assertEqual(error.exception.code, "AUTH_FAILED")

    def test_hwid_normalization_and_multiple_slots(self):
        data, _, _ = fixture(hwids=("h" + "2" * 31, TEST_HWID))
        with self.assertRaises(hc.HCError) as error: hc.decode(data)
        self.assertEqual(error.exception.code, "HWID_REQUIRED")
        result = hc.decode(data, hwid="  " + TEST_HWID.upper() + "  ")
        self.assertEqual(result["config"][0]["host"], "example.org")
        with self.assertRaises(hc.HCError) as error: hc.decode(data, hwid="h" + "3" * 31)
        self.assertEqual(error.exception.code, "AUTH_FAILED")
        with self.assertRaises(hc.HCError) as error: hc.decode(data, hwid="invalid")
        self.assertEqual(error.exception.code, "INVALID_HWID")

    def test_both_locks_require_both_and_authenticate(self):
        data, _, _ = fixture(password=TEST_PASSWORD, hwids=(TEST_HWID,), outer_v3=True)
        self.assertTrue(hc.inspect_requirements(data)["password_required"])
        self.assertTrue(hc.inspect_requirements(data)["hwid_required"])
        for creds, required, code in (({}, ["password", "hwid"], "CREDENTIALS_REQUIRED"),
                ({"password": TEST_PASSWORD}, ["hwid"], "HWID_REQUIRED"),
                ({"hwid": TEST_HWID}, ["password"], "PASSWORD_REQUIRED")):
            with self.subTest(code=code), self.assertRaises(hc.HCError) as error: hc.decode(data, **creds)
            self.assertEqual(error.exception.code, code)
            self.assertEqual(error.exception.required, required)
        for pw, hwid in (("wrong", TEST_HWID), (TEST_PASSWORD, "h" + "2" * 31)):
            with self.assertRaises(hc.HCError) as error: hc.decode(data, password=pw, hwid=hwid)
            self.assertEqual(error.exception.code, "AUTH_FAILED")
        audit = {}
        doc = hc.decode(data, password=TEST_PASSWORD, hwid=TEST_HWID, audit=audit)
        self.assertEqual(doc["config"][0]["host"], "example.org")
        self.assertFalse(audit["outer_authenticated"])
        self.assertTrue(audit["all_sections_authenticated"])
        self.assertEqual(audit["hpr1_authenticated"], 1)

    def test_no_hpr1_authentication_bypass(self):
        data, _, _ = fixture(bad_hpr=True)
        with self.assertRaises(hc.HCError) as error: hc.decode(data)
        self.assertEqual(error.exception.code, "AUTH_FAILED")

    def test_broken_main_or_profile_or_slot_is_rejected(self):
        _, env, _ = fixture(hwids=(TEST_HWID,))
        for section, field in ((env["i"], "c"), (env["j"][0], "c"), (env["o"][0], "b")):
            original = section[field]
            section[field] = original[:-2] + ("00" if original[-2:] != "00" else "01")
            with self.assertRaises(hc.HCError) as error: hc.decode(pack(env), hwid=TEST_HWID)
            self.assertEqual(error.exception.code, "AUTH_FAILED")
            section[field] = original

    def test_resource_limit_before_argon_and_empty_or_unknown_files(self):
        _, env, _ = fixture(password=TEST_PASSWORD)
        env["m"] = 2**40
        with mock.patch.object(hc, "_argon2id") as argon:
            with self.assertRaises(hc.HCError) as error: hc.decode(pack(env), password=TEST_PASSWORD)
            self.assertEqual(error.exception.code, "RESOURCE_LIMIT"); argon.assert_not_called()
        for data in (b"", b"not-hccfg"):
            with self.assertRaises(hc.HCError): hc.decode(data)

    def test_pure_xchacha_backend_and_inspection_do_not_run_argon(self):
        data, _, _ = fixture(password=TEST_PASSWORD)
        with mock.patch.object(hc, "_argon2id") as argon:
            self.assertTrue(hc.inspect_requirements(data)["password_required"])
            argon.assert_not_called()
        with mock.patch.object(hc, "_xdec", side_effect=hc._xdec_pure):
            self.assertEqual(hc.decode(data, password=TEST_PASSWORD)["config"][0]["port"], 443)

    def test_cli_success_structured_error_and_no_overwrite(self):
        data, _, _ = fixture(password=TEST_PASSWORD, hwids=(TEST_HWID,))
        script = ROOT / "decoders" / "Python" / "HTTPCUSTOM_AUTH.py"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.hc"; path.write_bytes(data)
            base = [sys.executable, str(script), str(path)]
            missing = subprocess.run(base, text=True, capture_output=True)
            self.assertEqual(missing.returncode, 1)
            self.assertEqual(missing.stdout, "")
            self.assertEqual(json.loads(missing.stderr)["error"]["required"], ["password", "hwid"])
            okay = subprocess.run(base + ["--password", TEST_PASSWORD, "--hwid", TEST_HWID],
                                  text=True, capture_output=True)
            self.assertEqual(okay.returncode, 0, okay.stderr)
            self.assertEqual(json.loads(okay.stdout)["config"][0]["host"], "example.org")
            conflict = subprocess.run(base + ["--inspect", "-o", str(path)], text=True, capture_output=True)
            self.assertEqual(conflict.returncode, 1)
            self.assertEqual(json.loads(conflict.stderr)["error"]["code"], "INVALID_OUTPUT")
            self.assertEqual(path.read_bytes(), data)

    @unittest.skipUnless(os.environ.get("HC_REAL_DIR"), "muestras privadas no disponibles")
    def test_three_real_exports(self):
        directory = Path(os.environ["HC_REAL_DIR"])
        cases = [("Test4.hc", None, None),
                 ("Test4 password.hc", os.environ["HC_REAL_PASSWORD"], None),
                 ("Test4 HWID.hc", None, os.environ["HC_REAL_HWID"])]
        for name, password, hwid in cases:
            with self.subTest(file=name):
                data = (directory / name).read_bytes(); audit = {}
                doc = hc.decode(data, password, hwid, audit)
                self.assertEqual(doc["app_version"], "7.11.19 (885)")
                self.assertEqual(len(doc["config"]), 2)
                self.assertEqual(audit["sections_authenticated"], 3)
                self.assertEqual(audit["hpr1_authenticated"], 2)
                self.assertTrue(audit["all_sections_authenticated"])
                if password is not None:
                    with self.assertRaises(hc.HCError) as error: hc.decode(data, password="wrong-password")
                    self.assertEqual(error.exception.code, "AUTH_FAILED")
                if hwid is not None:
                    with self.assertRaises(hc.HCError) as error: hc.decode(data, hwid="h" + "2" * 31)
                    self.assertEqual(error.exception.code, "AUTH_FAILED")


if __name__ == "__main__":
    unittest.main()

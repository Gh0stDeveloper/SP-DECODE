"""Positive independent fixtures for KTR, Zoba, LTM, DEV and VN7."""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import unittest

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

from decoders.Python import dev, ktr, ltm, vn7, zoba


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


def java_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x74" + struct.pack(">H", len(encoded)) + encoded


def zoba_encrypt(clear: bytes) -> bytes:
    """The inverse of source 66.py's signed, custom-delta XXTEA."""
    v = zoba._f0(clear, incl_len=True)
    k = zoba._f0(zoba.KEY)
    n = len(v)
    total = 0
    z = v[n - 1]
    for _ in range(52 // n + 6):
        total = zoba._java_int(total + zoba.DELTA)
        e = ((total & 0xFFFFFFFF) >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = zoba._java_int(v[p] + zoba._mx(z, y, total, p, e, k))
            z = v[p]
        v[n - 1] = zoba._java_int(
            v[n - 1] + zoba._mx(z, v[0], total, n - 1, e, k)
        )
        z = v[n - 1]
    return zoba._e0(v, trim=False)


def skycrypt_encrypt(clear: bytes) -> bytes:
    """Inverse of DEV SkyCrypt custom XXTEA with length trailer."""
    password = dev.DEV_SKY_KEY.encode("utf-8")[:16].ljust(16, b"\x00")
    mask = 0xFFFFFFFF
    n = (len(clear) + 3) // 4
    content = clear + bytes(n * 4 - len(clear)) + struct.pack("<I", len(clear))
    v = list(struct.unpack("<%dI" % (n + 1), content))
    k = struct.unpack("<4I", password)
    last = len(v) - 1
    total = 0
    z = v[last]
    for _ in range(6 + 52 // len(v)):
        total = (total + 0x9A7393B4) & mask
        e = (total >> 2) & 3
        for p in range(last):
            y = v[p + 1]
            mx = (((total ^ y) + (k[(p & 3) ^ e] ^ z)) ^
                  (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & mask
            v[p] = (v[p] + mx) & mask
            z = v[p]
        y = v[0]
        mx = (((total ^ y) + (k[(last & 3) ^ e] ^ z)) ^
              (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & mask
        v[last] = (v[last] + mx) & mask
        z = v[last]
    return struct.pack("<%dI" % len(v), *v)


class IndependentSecondFiveTests(unittest.TestCase):
    def test_ktr_java_tc_strings_aes_cbc(self):
        doc = {"HOST": "ktr.example", "PORT": "443",
               "USERNAME": "ghost"}
        entries = []
        for field, value in doc.items():
            encrypted = AES.new(ktr.KTR_KEY, AES.MODE_CBC, ktr.KTR_IV).encrypt(
                pad(value.encode("utf-8"), AES.block_size))
            entries.extend((java_string(field),
                            java_string(b64(encrypted).decode("ascii"))))
        payload = ktr.KTR_JAVA_MAGIC + b"".join(entries)
        result = ktr.run(payload)
        self.assertIsNotNone(result)
        actual = json.loads(result)
        self.assertEqual(actual["mode"], "java")
        self.assertEqual(actual["count"], len(doc))
        self.assertEqual(actual["data"], doc)

    def test_zoba_custom_signed_xxtea(self):
        source = {"Server": "zoba.example", "Port": 443, "Enabled": True}
        sealed = b64(zoba_encrypt(json.dumps(source).encode("utf-8")))
        result = zoba.run(sealed)
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result), source)

    def test_ltm_pbkdf2_aes_gcm_both_suffixes_and_xml(self):
        doc = {"host": "ltm.example", "port": "443", "user": "ghost"}
        xml = "<properties>" + "".join(
            f'<entry key="{k}">{v}</entry>' for k, v in doc.items()
        ) + "</properties>"
        salt = bytes(range(16))
        iv = bytes(range(12))
        key = PBKDF2(ltm.LTM_PASSWORD, salt, dkLen=ltm.LTM_KEY_LENGTH,
                     count=ltm.LTM_ITERATIONS, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(xml.encode("utf-8"))
        sealed = b".".join(map(b64, (salt, iv, ciphertext + tag)))
        for ext in (".lt", ".ltm"):
            with self.subTest(extension=ext):
                result = ltm.run(sealed)
                self.assertIsNotNone(result)
                self.assertEqual(json.loads(result), doc)
        tampered = sealed[:-2] + b"AA"
        self.assertIsNone(ltm.run(tampered))

    def test_dev_skycrypt_all_fields(self):
        original = {"Server": "dev.example", "Port": 443,
                    "Notes": "Prueba", "Enabled": False,
                    "List": ["vless", "trojan"]}
        encrypted = b64(skycrypt_encrypt(
            json.dumps(original, ensure_ascii=False).encode("utf-8")))
        output = dev.run(encrypted)
        self.assertIsNotNone(output)
        self.assertEqual(json.loads(output), original)


    def test_dev_nested_field_aes256_cbc(self):
        """Verify the complete DEV SkyCrypt → AES field decryption pipeline."""
        password = dev.DEV_AES_KEY
        pass_hex = password.encode("utf-8").hex().upper()
        inner_key = hashlib.sha256(pass_hex.encode("utf-8")).digest()
        inner = AES.new(inner_key, AES.MODE_CBC, bytes(16)).encrypt(
            pad(b"nested.dev.example", 16))
        doc = {"Server": b64(inner).decode("ascii"), "Port": 443}
        ciphertext = b64(skycrypt_encrypt(json.dumps(doc).encode("utf-8")))
        result = dev.run(ciphertext)
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result)["Server"], "nested.dev.example")

    def test_vn7_two_key_materials_aes_gcm_authentication(self):
        original = {"Server": "vn7.example", "Port": 443, "TLS": True}
        salt = bytes(range(16))
        nonce = bytes(range(12))
        for password in vn7.VN7_KEYS:
            with self.subTest(password_index=vn7.VN7_KEYS.index(password)):
                key = PBKDF2(password, salt, hmac_hash_module=SHA256)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext, tag = cipher.encrypt_and_digest(
                    json.dumps(original).encode("utf-8"))
                encrypted = b".".join(map(b64, (salt, nonce, ciphertext + tag)))
                result = vn7.run(encrypted)
                self.assertIsNotNone(result)
                self.assertEqual(json.loads(result), original)
                corrupted = bytearray(ciphertext + tag)
                corrupted[-1] ^= 1
                bad = b".".join(map(b64, (salt, nonce, bytes(corrupted))))
                self.assertIsNone(vn7.run(bad))


if __name__ == "__main__":
    unittest.main()

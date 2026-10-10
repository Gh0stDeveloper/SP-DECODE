"""Positive vectors for the RENZ/7NET legacy type0/type1/type2 routes."""
import base64
import json
import struct
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python import renz

from tests.test_renz_family import threefish_encrypt256_block


def legacy_encrypt(data, key):
    words = renz.renz_xxtea_to_uint32(data, True)
    kw = renz.renz_xxtea_to_uint32(key[:16].ljust(16, b"\0"), False)
    n = len(words)
    total = 0
    mask = 0xffffffff
    for _ in range(6 + 52 // n):
        total = (total + renz.RENZ_DELTA) & mask
        e = (total >> 2) & 3
        z = words[-1]
        for p in range(n):
            y = words[(p + 1) % n]
            mx = (((z >> 5) ^ ((y << 2) & mask)) +
                  ((y >> 3) ^ ((z << 4) & mask))) ^ (
                  (total ^ y) + (kw[(p & 3) ^ e] ^ z))
            words[p] = (words[p] + mx) & mask
            z = words[p]
    return struct.pack("<%dI" % n, *words)


class RenzLegacyTypedTests(unittest.TestCase):
    def test_types_0_1_2(self):
        doc = {"Host": "source.example", "Mode": 2, "Enabled": False}
        clear = json.dumps(doc).encode("utf-8")
        key0 = renz.RENZ_SHA256_KEY_16
        ct0 = AES.new(key0, AES.MODE_CBC, renz.RENZ_FIXED_IV).encrypt(
            pad(legacy_encrypt(bytes((x + 2) & 255 for x in clear), key0), 16))
        self.assertEqual(renz.renz_decrypt_type0(ct0), clear)
        self.assertEqual(json.loads(renz.decode_file(base64.b64encode(ct0),
                                                    ".7net"))["config"], doc)

        key1a = renz.renz_get_hkdf_key_16()
        key1b = renz.renz_get_hkdf_key()
        stage = AES.new(key1a, AES.MODE_CBC, renz.RENZ_FIXED_IV).encrypt(pad(clear, 16))
        stage += bytes(-len(stage) % 32)
        ciphertext = b"".join(
            threefish_encrypt256_block(key1b, (i // 32, 0), stage[i:i+32])
            for i in range(0, len(stage), 32)
        )
        ct1 = base64.b64encode(ciphertext)
        self.assertEqual(renz.renz_decrypt_type1(ct1), clear)
        self.assertEqual(json.loads(renz.decode_file(ct1, ".7net"))["config"], doc)

        key2 = renz.renz_get_pbkdf2_key()
        iv = bytes(range(16))
        stage2 = iv + AES.new(key2, AES.MODE_CBC, iv).encrypt(pad(clear, 16))
        ct2 = base64.b64encode(legacy_encrypt(stage2, key2[:16]))
        self.assertEqual(renz.renz_decrypt_type2(ct2), clear)
        self.assertEqual(json.loads(renz.decode_file(ct2, ".7net"))["config"], doc)


if __name__ == "__main__":
    unittest.main()

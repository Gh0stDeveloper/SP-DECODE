"""Synthetic IZPH kind-2 regression (PBKDF2, custom XXTEA, AES-CBC)."""
import base64
import json
import unittest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python import izph
from tests.test_independent_batch_crypto_a import izph_xxtea_encrypt


class IzphKind2Tests(unittest.TestCase):
    def test_kind2_in_outer_profile(self):
        clear = json.dumps({"port": 22, "test": True}).encode()
        key = izph.izph_get_pbkdf2_key()
        iv = bytes(range(16))
        aes = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(clear, 16))
        encoded = base64.b64encode(izph_xxtea_encrypt(iv + aes, key[:16]))
        result = izph.run(encoded)
        self.assertIsNotNone(result)
        self.assertEqual(json.loads(result), json.loads(clear))


if __name__ == "__main__":
    unittest.main()

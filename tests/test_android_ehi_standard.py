"""Differential contract: synthetic standard-IV HTTP Injector profile matches bot."""
import tempfile
import unittest
from pathlib import Path
from decoders.Python.HTTPINJECTOR import run
from scripts.android_ehi_standard_fixture import make, write


class EhiStandardTests(unittest.TestCase):
    def test_standard_argon2_xchacha_roundtrip_against_bot(self):
        raw, expected = make()
        self.assertGreater(len(raw), 100)
        self.assertEqual(run(raw).encode("utf-8"), expected)
        self.assertIn(b"example.org", expected)
        self.assertIn(b"Synthetic EHI standard variant", expected)
        with tempfile.TemporaryDirectory() as folder:
            write(Path(folder))
            self.assertEqual((Path(folder)/"ehi-standard-id.ehi").read_bytes(),raw)
            self.assertEqual((Path(folder)/"ehi-standard-id.txt").read_bytes(),expected)

    def test_ciphertext_tampering_does_not_produce_success(self):
        raw, _ = make()
        tampered = bytearray(raw)
        tampered[-20] ^= 0x40
        self.assertIsNone(run(bytes(tampered)))


if __name__ == "__main__":
    unittest.main()

"""NPVS v5 native Android data is frozen to the original Python algorithm."""
from __future__ import annotations
import base64
import hashlib
import unittest
import zlib
from pathlib import Path
from decoders.Python import npvs

ROOT=Path(__file__).resolve().parents[1]
ASSET=ROOT/"android/app/src/main/assets/npvs_v5_tables.b85"
SHA="35717e8267a115fbf474e3cd622066783feea21305457c840cabd57a73086f7d"

class NpvsNativeAssetParity(unittest.TestCase):
    def test_base85_asset_is_exact_original_whitebox_data(self):
        source=npvs._TABLE_DATA
        self.assertEqual(ASSET.read_text("ascii").strip().encode("ascii"),source)
        table=zlib.decompress(base64.b85decode(source))
        self.assertEqual(len(table),749569)
        self.assertEqual(hashlib.sha256(table).hexdigest(),SHA)

    def test_reference_vectors_unchanged(self):
        cases=[
            ("00000000000000000000000000000000","4878126b14231f6f522f310686001524"),
            ("000102030405060708090a0b0c0d0e0f","f659c73d8c0fa5150e3254dfe0a1106d"),
            ("00112233445566778899aabbccddeeff","47e6155a8b2588d855972b60d123ce94"),
            ("ffffffffffffffffffffffffffffffff","65c2e1759568da2929e357d637c33664"),
        ]
        for source,expected in cases:
            self.assertEqual(npvs._whitebox_block(bytes.fromhex(source)).hex(),expected)

if __name__=="__main__":
    unittest.main()

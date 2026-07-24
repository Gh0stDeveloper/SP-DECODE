from __future__ import annotations

import base64
import json
import unittest
import zlib

from decoders.Python.sockip import AES_KEY, UnsupportedSocksIPVersion
from decoders.Python.sockip_ver7 import (
    decode_ver7_hex_xor_layer,
    decode_ver7_xor_profile,
    inspect_ver7_xor,
    xor_repeating,
)


def build_ver7(next_layer: bytes) -> bytes:
    encrypted = xor_repeating(next_layer, AES_KEY)
    return b"VER7" + encrypted.hex().encode("ascii")


class SocksIPVer7XorTests(unittest.TestCase):
    def test_repeating_xor_is_reversible(self) -> None:
        value = b"SocksIP VER7 test payload longer than one key block"
        self.assertEqual(xor_repeating(xor_repeating(value)), value)

    def test_hex_xor_json_profile(self) -> None:
        expected = {"server": "example.com", "port": 443, "mode": "ssl"}
        inner = json.dumps(expected, separators=(",", ":")).encode("utf-8")
        plaintext = build_ver7(inner)

        self.assertEqual(decode_ver7_hex_xor_layer(plaintext), inner)
        parsed, route = decode_ver7_xor_profile(plaintext)
        self.assertEqual(parsed, expected)
        self.assertEqual(route, "VER7->hex->xor-known-key")

    def test_four_stage_path_after_xor_is_bounded_and_resolved(self) -> None:
        expected = {"payload": "CONNECT [host_port] HTTP/1.1", "enabled": True}
        json_bytes = json.dumps(expected, separators=(",", ":")).encode("utf-8")
        # Post-XOR route: Base64 -> hex -> Base64 -> ZLIB -> JSON.
        stage_1 = zlib.compress(json_bytes)
        stage_2 = base64.b64encode(stage_1)
        stage_3 = stage_2.hex().encode("ascii")
        stage_4 = base64.b64encode(stage_3)
        plaintext = build_ver7(stage_4)

        parsed, route = decode_ver7_xor_profile(plaintext)
        self.assertEqual(parsed, expected)
        self.assertIn("base64", route)
        self.assertIn("hex", route)
        self.assertIn("zlib", route)

    def test_non_hex_ver7_payload_is_rejected(self) -> None:
        with self.assertRaises(UnsupportedSocksIPVersion):
            decode_ver7_hex_xor_layer(b"VER7this-is-not-hex")

    def test_inspection_does_not_claim_success_without_valid_root(self) -> None:
        plaintext = build_ver7(b"\x01\x02\x03\x04\x05")
        report = inspect_ver7_xor(plaintext)
        self.assertTrue(report["hex_valid"])
        self.assertFalse(report["verified"])
        self.assertIsNone(report["resolved_route"])


if __name__ == "__main__":
    unittest.main()

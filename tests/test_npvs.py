from __future__ import annotations

import struct
import unittest

from decoders.Python.NPVS import NPVSFormatError, describe, inspect


def frame(header: bytes = b"\x01" + b"h" * 32, body: bytes = b"NPF\x01" + b"b" * 20) -> bytes:
    return (
        b"NPVS\x05"
        + struct.pack(">I", len(header))
        + header
        + b"n" * 12
        + struct.pack(">I", len(body))
        + body
        + b"s" * 64
    )


class NPVSInspectTests(unittest.TestCase):
    def test_v5_frame_reports_encrypted_status_without_body(self):
        result = inspect(frame())
        self.assertEqual((result.version, result.header_length, result.body_length), (5, 33, 24))
        self.assertEqual(result.body_marker, "NPF1")
        output = describe(result)
        self.assertIn("contenido cifrado", output)
        self.assertNotIn("bbbb", output)

    def test_rejects_trailing_data_and_truncation(self):
        for data in (frame() + b"x", frame()[:-1], frame()[:17]):
            with self.subTest(size=len(data)), self.assertRaises(NPVSFormatError):
                inspect(data)

    def test_rejects_wrong_magic_and_version(self):
        for data in (b"NOPE" + frame()[4:], frame()[:4] + b"\x06" + frame()[5:]):
            with self.subTest(version=data[4]), self.assertRaises(NPVSFormatError):
                inspect(data)

    def test_rejects_forged_length_without_allocating(self):
        data = bytearray(frame())
        data[5:9] = struct.pack(">I", 0xFFFFFFFF)
        with self.assertRaises(NPVSFormatError):
            inspect(bytes(data))


if __name__ == "__main__":
    unittest.main()

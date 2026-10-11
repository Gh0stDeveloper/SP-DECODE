"""NPVS v5 complete JSON export: authenticated, recursive npvs1 decoding."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from decoders.Python import npvs


def encoded(text: str) -> str:
    return "npvs1:" + base64.urlsafe_b64encode(
        text.encode("utf-8")
    ).decode("ascii").rstrip("=")


class NPVSCompleteJSONTests(unittest.TestCase):
    def test_recursive_ssh_strings_and_nested_json(self):
        source = {
            "metadata": {"issuedAt": "2026-10-10"},
            "document": {"configs": [{
                "sshConfig": {
                    "sshHost": encoded("test.example"),
                    "sshPort": 443,
                    "sshUsername": encoded(encoded("user-test")),
                    "payload": encoded("CONNECT / HTTP/1.1\nHost: test.example"),
                    "extra": encoded(json.dumps({
                        "nested": encoded("日本語 / español"), "enabled": True
                    }, ensure_ascii=False)),
                    "opaque": "dGVzdA==",
                }
            }]}
        }
        with patch.object(npvs, "decode_npvs", return_value=source) as mocked:
            output = npvs.run(b"authenticated-synthetic-placeholder")
            result = json.loads(output)
            mocked.assert_called_once_with(b"authenticated-synthetic-placeholder")
        config = result["document"]["configs"][0]["sshConfig"]
        self.assertEqual(config["sshHost"], "test.example")
        self.assertEqual(config["sshPort"], 443)
        self.assertEqual(config["sshUsername"], "user-test")
        self.assertEqual(config["payload"], "CONNECT / HTTP/1.1\nHost: test.example")
        self.assertEqual(config["extra"], {"nested": "日本語 / español", "enabled": True})
        # Base64-looking opaque values without the encoding marker are literal data.
        self.assertEqual(config["opaque"], "dGVzdA==")
        self.assertNotIn("npvs1:", output)
        # No mutation of the authenticated source object.
        self.assertTrue(source["document"]["configs"][0]["sshConfig"]["sshHost"].startswith("npvs1:"))

    def test_malformed_npvs1_is_rejected_not_returned_as_partial_json(self):
        for value in ("npvs1:", "npvs1:!", "npvs1:/w==", "npvs1:///////"):
            with self.subTest(value=value), self.assertRaises(npvs.DecodeError):
                npvs._decode_embedded_npvs1(value)

    def test_explicit_marker_only_and_non_ascii(self):
        self.assertEqual(npvs._decode_embedded_npvs1(encoded("áé日本語")), "áé日本語")
        self.assertEqual(npvs._decode_embedded_npvs1("dGVzdA=="), "dGVzdA==")

    def test_signed_v5_fixture_preserves_authenticated_document(self):
        from scripts.android_npvs_fixture_export import export

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            export(folder)
            file_bytes = (folder / "npvs-v5-appkey.npvs").read_bytes()
            expected = json.loads((folder / "npvs-v5-appkey.json").read_text(encoding="utf-8"))
            self.assertEqual(npvs.decode_npvs(file_bytes), expected)
            self.assertEqual(npvs.decode_npvs_complete(file_bytes), expected)
            self.assertEqual(json.loads(npvs.run(file_bytes)), expected)
            altered = bytearray(file_bytes)
            altered[-1] ^= 1
            with self.assertRaises(npvs.DecodeError):
                npvs.run(bytes(altered))


    def test_signed_android_embedded_fixture_matches_python_complete_json(self):
        from scripts.android_npvs_fixture_export import export

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            export(folder)
            raw = (folder / "npvs-v5-appkey-embedded.npvs").read_bytes()
            expected = json.loads((folder / "npvs-v5-appkey-embedded.json")
                                  .read_text(encoding="utf-8"))
            raw_document = npvs.decode_npvs(raw)
            self.assertTrue(raw_document["document"]["configs"][0]
                            ["sshConfig"]["sshHost"].startswith("npvs1:"))
            self.assertEqual(npvs.decode_npvs_complete(raw), expected)
            self.assertEqual(json.loads(npvs.run(raw)), expected)
            self.assertNotIn("npvs1:", npvs.run(raw))
            fields = expected["document"]["configs"][0]["sshConfig"]
            self.assertEqual(fields["sshUsername"], "cybertunnel-fidelson015")
            self.assertEqual(fields["opaque"], "dGVzdA==")
            self.assertEqual(fields["extra"]["region"], "El Salvador")
            self.assertIn("\n", fields["payload"])
            corrupted = bytearray(raw)
            corrupted[-1] ^= 1
            with self.assertRaises(npvs.DecodeError):
                npvs.run(bytes(corrupted))


if __name__ == "__main__":
    unittest.main()

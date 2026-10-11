"""Phase S: source classification, synthetic APK leakage and fail-closed regression."""
from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.android_s_vault_audit import (
    ALL, REQUIRED, check_apk, check_source, manifest,
)


class AndroidPhaseSVaultAuditTests(unittest.TestCase):
    def test_source_catalog_and_loaders_cover_all_protected_material(self):
        check_source()
        items = manifest()
        self.assertTrue(set(REQUIRED).issubset(items))
        self.assertEqual(len(ALL), len(set(ALL)))
        self.assertTrue(all(len(d["sha256"]) == 64 and d["bytes"] > 0
                            for d in items.values()))

    def test_synthetic_apk_requires_ciphertext_and_never_raw_asset(self):
        expected = {"generic_b_profiles.json": {"sha256": "0" * 64, "bytes": 2}}
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "smoke.apk"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("assets/decoder_catalog.json", "{}")
                z.writestr("assets/generic_b_profiles.json.spv", b"SPV1" + b"n" * 12 + b"x" * 17)
            self.assertEqual(1, len(check_apk(archive, expected)))
            with zipfile.ZipFile(archive, "a") as z:
                z.writestr("assets/generic_b_profiles.json", "{}")
            with self.assertRaisesRegex(ValueError, "PLAINTEXT"):
                check_apk(archive, expected)

    def test_synthetic_apk_rejects_invalid_or_missing_vault_blob(self):
        expected = {"generic_b_profiles.json": {"sha256": "0" * 64, "bytes": 2}}
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "missing.apk"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("assets/decoder_catalog.json", "{}")
            with self.assertRaisesRegex(ValueError, "missing"):
                check_apk(archive, expected)
            with zipfile.ZipFile(archive, "a") as z:
                z.writestr("assets/generic_b_profiles.json.spv", b"plain text secrets")
            with self.assertRaisesRegex(ValueError, "Malformed"):
                check_apk(archive, expected)


if __name__ == "__main__":
    unittest.main()

"""S.2 DEX regression: material parity, literal exposure and fail-closed APK audit."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.android_s2_dex_audit import check_apk, check_source, fixture, forbidden_literals, materials


class S2DexAuditTest(unittest.TestCase):
    def test_all_six_materials_classified_and_hashed(self):
        result = check_source()
        self.assertEqual(5, len(result["migratedPorts"]))
        self.assertEqual(6, result["migratedMaterialCount"])
        self.assertGreater(result["scannedKotlinFiles"], 50)
        digest = fixture()
        self.assertEqual(6, len(digest["materials"]))
        for name, item in digest["materials"].items():
            self.assertEqual(64, len(item["sha256"]), name)
            self.assertGreater(item["bytes"], 0)

    def test_migrated_ports_have_no_original_embedded_literals(self):
        candidates = forbidden_literals()
        self.assertEqual(5, len(candidates))
        for file, strings in candidates.items():
            source = (Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity") / file).read_text("utf-8")
            self.assertTrue(strings)
            self.assertTrue(all(item not in source for item in strings if len(item) >= 8))

    def test_synthetic_apk_scans_dex_and_rejects_readable_key(self):
        import json
        profile = json.loads(Path("android/app/src/main/assets/embedded_kotlin_profiles.json").read_text("utf-8"))
        value = profile["hat"]["aesKeyB64"]
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "test.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("classes.dex", b"dex\\n035\\x00SAFE-SYNTHETIC")
                z.writestr("assets/embedded_kotlin_profiles.json.spv", b"SPV1" + b"x" * 32)
            self.assertEqual(1, check_apk(apk)["dexFilesChecked"])
            with zipfile.ZipFile(apk, "a") as z:
                z.writestr("classes2.dex", b"dex\\n035\\x00" + value.encode("utf-8"))
            with self.assertRaisesRegex(ValueError, "Readable migrated"):
                check_apk(apk)

    def test_synthetic_apk_missing_protected_material_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "test.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("classes.dex", b"dex\\n035\\x00")
            with self.assertRaisesRegex(ValueError, "missing"):
                check_apk(apk)


if __name__ == "__main__":
    unittest.main()

"""S.2 native E1/E2/F2 source and APK regression tests."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from scripts.android_s2_family_audit import (
    check_source, check_apk, fixture, materials, candidates,
)


class PhaseS2FamilyAuditTests(unittest.TestCase):
    def test_all_thirty_source_materials_and_kotlin_loaders(self):
        result=check_source()
        self.assertEqual(3,len(result["migratedPorts"]))
        self.assertEqual(30,result["materialCount"])
        self.assertEqual(30,len(materials()))
        for name,description in fixture()["materials"].items():
            self.assertEqual(64,len(description["sha256"]),name)
            self.assertGreater(description["bytes"],0)

    def test_original_decoder_literals_not_in_source(self):
        for file,strings in candidates().items():
            content=Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity",file).read_text("utf-8")
            self.assertIn("PhaseS2FamilyMaterials.",content)
            self.assertTrue(all(value not in content for value in strings),file)

    def test_synthetic_dex_rejects_migrated_profile_material(self):
        encoded=candidates()["SpecialE1Port.kt"][0].encode("utf-8")
        with tempfile.TemporaryDirectory() as root:
            apk=Path(root)/"sample.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",b"SAFE")
                z.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"x"*50)
            self.assertEqual(1,check_apk(apk)["dexFilesChecked"])
            with zipfile.ZipFile(apk,"a") as z:
                z.writestr("classes4.dex",b"DEX"+encoded)
            with self.assertRaisesRegex(ValueError,"literal found in DEX"):
                check_apk(apk)

    def test_plaintext_or_missing_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            apk=Path(root)/"sample.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",b"safe")
            with self.assertRaisesRegex(ValueError,"asset absent"):
                check_apk(apk)
            with zipfile.ZipFile(apk,"a") as z:
                z.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"x"*50)
                z.writestr("assets/embedded_kotlin_profiles.json",b"{}")
            with self.assertRaisesRegex(ValueError,"Unencrypted"):
                check_apk(apk)


if __name__=="__main__":
    unittest.main()

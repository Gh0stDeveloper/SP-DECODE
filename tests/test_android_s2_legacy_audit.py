"""S.2 legacy bundle source inventory and fail-closed multidex APK checks."""
import tempfile
import unittest
import zipfile
from pathlib import Path
from scripts.android_s2_legacy_audit import check_source, check_apk, fixture, _forbidden


class LegacyS2AuditTest(unittest.TestCase):
    def test_registered_engines_and_source_hashes(self):
        audit=check_source()
        self.assertEqual(6,len(audit["migratedPorts"]))
        self.assertEqual(11,audit["parityMaterials"])
        result=fixture()
        self.assertEqual(11,len(result["materials"]))
        for item in result["materials"].values():
            self.assertEqual(64,len(item["sha256"]))
            self.assertGreater(item["bytes"],0)

    def test_all_original_literals_removed_from_six_port_sources(self):
        for name, secrets in _forbidden().items():
            content=Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity",name).read_text("utf-8")
            self.assertIn("LegacyBatch2Materials.",content)
            self.assertTrue(all(secret not in content for secret in secrets))

    def test_test_apk_rejects_multidex_secrets(self):
        sentinel=_forbidden()["CloudyPort.kt"][0].encode("utf-8")
        with tempfile.TemporaryDirectory() as path:
            apk=Path(path)/"synthetic.apk"
            with zipfile.ZipFile(apk,"w") as archive:
                archive.writestr("classes.dex",b"safe")
                archive.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"x"*33)
            self.assertEqual(1,check_apk(apk)["dexFilesChecked"])
            with zipfile.ZipFile(apk,"a") as archive:
                archive.writestr("classes3.dex",b"known-secret:"+sentinel)
            with self.assertRaisesRegex(ValueError,"plaintext key"):
                check_apk(apk)

    def test_test_apk_requires_nonplaintext_vault_resource(self):
        with tempfile.TemporaryDirectory() as path:
            apk=Path(path)/"synthetic.apk"
            with zipfile.ZipFile(apk,"w") as archive:
                archive.writestr("classes.dex",b"safe")
            with self.assertRaisesRegex(ValueError,"missing"):
                check_apk(apk)
            with zipfile.ZipFile(apk,"a") as archive:
                archive.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"x"*33)
                archive.writestr("assets/embedded_kotlin_profiles.json",b"{}")
            with self.assertRaisesRegex(ValueError,"Plaintext"):
                check_apk(apk)


if __name__=="__main__":
    unittest.main()

"""S.4 regression tests: do not ship or export user private credentials."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from scripts.android_s4_provisioning_audit import source, apk


class S4SecurityPolicyTest(unittest.TestCase):
    def test_keystore_and_ui_contracts(self):
        report=source()
        self.assertEqual("PASS",report["status"],report["violations"])
        self.assertGreaterEqual(report["controls"],18)
        self.assertFalse(report["secretsReported"])
        self.assertFalse(report["devicePrivateKeyInApk"])

    def test_synthetic_apk_accepts_legitimate_offline_assets(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"app.apk"
            with zipfile.ZipFile(path,"w") as archive:
                archive.writestr("classes.dex",b"safe")
                archive.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"x"*16)
            result=apk(path)
            self.assertEqual("PASS",result["status"])
            self.assertEqual(1,result["dexFilesChecked"])

    def test_reject_private_record_or_keystore_packaged_in_apk(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"app.apk"
            with zipfile.ZipFile(path,"w") as archive:
                archive.writestr("classes.dex",b"safe")
                archive.writestr("assets/private-credentials/sample.s4k",b"synthetic")
                archive.writestr("assets/device-signing.jks",b"synthetic")
            result=apk(path)
            self.assertEqual("FAIL",result["status"])
            self.assertIn("private-record-packaged",result["violations"])
            self.assertIn("private-key-file-packaged",result["violations"])
            self.assertFalse(result["credentialsReported"])

    def test_reject_public_resource_s1_regression(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"app.apk"
            with zipfile.ZipFile(path,"w") as archive:
                archive.writestr("classes2.dex",b"safe")
                archive.writestr("assets/embedded_kotlin_profiles.json",b"{}")
            self.assertIn("s1-plaintext-resource-packaged",apk(path)["violations"])


if __name__=="__main__":
    unittest.main()

"""Additional S.2 source and APK guards for TLS, EHI and Dark Tunnel."""
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.android_s2_extra_audit import check_apk, check_sources, fixture, literals, materials


class S2ExtraTest(unittest.TestCase):
    def test_materials_sha_provenance_and_no_embedded_source_keys(self):
        report = check_sources()
        self.assertEqual(3, len(report["migratedPorts"]))
        self.assertEqual(18, report["validatedMaterialCount"])
        expected = fixture()["materials"]
        self.assertEqual(18, len(expected))
        for label, record in expected.items():
            self.assertEqual(64, len(record["sha256"]), label)
            self.assertGreater(record["bytes"], 0)

    def test_legacy_kotlin_source_does_not_regain_crypto_literals(self):
        for name, strings in literals().items():
            body = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity", name).read_text("utf-8")
            self.assertNotIn(strings[0], body)
            self.assertTrue(all(value not in body for value in strings))

    def test_synthetic_dex_detects_known_tls_profile(self):
        source = literals()["TlsReferencePort.kt"][0].encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            apk = Path(d)/"test.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",b"dex-safe")
                z.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"a"*50)
            self.assertFalse(check_apk(apk)["plaintextLiteralsFound"])
            with zipfile.ZipFile(apk,"a") as z:
                z.writestr("classes2.dex",b"DEX"+source)
            with self.assertRaisesRegex(ValueError,"literal present"):
                check_apk(apk)

    def test_missing_ciphertext_and_plaintext_source_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            apk=Path(d)/"test.apk"
            with zipfile.ZipFile(apk,"w") as z:
                z.writestr("classes.dex",b"dex-safe")
            with self.assertRaisesRegex(ValueError,"missing"):
                check_apk(apk)
            with zipfile.ZipFile(apk,"a") as z:
                z.writestr("assets/embedded_kotlin_profiles.json","{}")
                z.writestr("assets/embedded_kotlin_profiles.json.spv",b"SPV1"+b"a"*50)
            with self.assertRaisesRegex(ValueError,"Plaintext"):
                check_apk(apk)


if __name__ == "__main__":
    unittest.main()

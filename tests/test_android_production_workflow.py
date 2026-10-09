"""Regression tests for the permanent-key, automatic Android production pipeline.

These assertions guard release automation invariants, not device certification.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/android-signed-release.yml"
GRADLE = ROOT / "android/app/build.gradle.kts"


class AndroidProductionWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.gradle = GRADLE.read_text(encoding="utf-8")

    def test_automatic_only_after_successful_main_push(self):
        w = self.workflow
        self.assertIn("workflow_run:", w)
        self.assertIn('workflows: ["Validate SP-DECODE"]', w)
        self.assertIn("types: [completed]", w)
        self.assertIn("branches: [main]", w)
        self.assertIn("github.event.workflow_run.event == 'push'", w)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", w)
        self.assertIn("github.event.workflow_run.head_repository.full_name == github.repository", w)
        self.assertIn("git ls-remote origin refs/heads/main", w)
        self.assertIn('SOURCE_SHA', w)

    def test_never_signs_debug_or_with_generated_key(self):
        w = self.workflow
        self.assertIn(":app:assembleRelease", w)
        self.assertNotIn(":app:assembleDebug", w)
        self.assertNotIn("keytool -genkey", w)
        self.assertNotIn("keytool -genkeypair", w)
        self.assertIn("base64 --decode", w)
        self.assertIn("SPDECODE_SIGNING_KEYSTORE_BASE64", w)
        self.assertIn("SPDECODE_SIGNING_STORE_PASSWORD", w)
        self.assertIn("SPDECODE_SIGNING_KEY_ALIAS", w)
        self.assertIn("SPDECODE_SIGNING_KEY_PASSWORD", w)
        self.assertIn("signingConfig=signingConfigs.findByName(\"production\")", self.gradle)
        for scheme in ("v1", "v2", "v3"):
            self.assertIn(f'enable{scheme.upper()}Signing=true', self.gradle)
            self.assertIn(f"--{scheme}-signing-enabled true", w)
        # Verify every scheme explicitly; any missing signature fails closed.
        self.assertIn("for scheme in v1 v2 v3; do", w)
        self.assertIn('grep -Eiq "^Verified using $scheme scheme .*: true$"', w)
        self.assertIn('echo "::error::APK $scheme signature was not verified"', w)
        self.assertIn("zipalign", w)
        self.assertIn("SHA256SUMS.txt", w)
        self.assertIn("production-signed.apk", w)

    def test_stable_identity_and_publication_are_separate(self):
        self.assertRegex(self.gradle, r'versionName\s*=\s*"1\.0\.0"')
        self.assertRegex(self.gradle, r'versionCode\s*=\s*11\b')
        w = self.workflow
        self.assertIn("publication-gate:", w)
        self.assertIn("python scripts/android_release_gate.py --mode stable", w)
        self.assertIn("needs['publication-gate'].outputs.approved == 'true'", w)
        self.assertIn("gh release create", w)
        self.assertIn("already exists; no tag/asset will be overwritten", w)


if __name__ == "__main__":
    unittest.main()

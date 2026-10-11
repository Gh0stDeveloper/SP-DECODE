"""S.3 security regression: real source contracts and synthetic secret leaks."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.android_s3_security_audit import (
    ANDROID_BAD_LOGGING, WORKFLOW_BAD_LOGGING, audit,
    find_tokens, private_filename, scan_apk, scan_tracked,
    android_guards, workflow_guards,
)


class PhaseS3SecurityAuditTest(unittest.TestCase):
    def test_no_sensitive_diagnostic_output_in_android_source(self):
        self.assertEqual([], android_guards())
        self.assertEqual([], workflow_guards())
        code = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/SafeDecodeDiagnostics.kt").read_text("utf-8")
        self.assertIn("AtomicIntegerArray", code)
        self.assertIn("fun record(event: Event)", code)
        self.assertNotIn("record(exception:", code)
        self.assertNotIn("Log.", code)

    def test_detects_private_credentials_without_returning_matched_values(self):
        synthetic = (
            b"-----BEGIN " + b"PRIVATE KEY-----\n"
            + b"ghp_" + b"A" * 32 + b"\n"
            + b"AKIA" + b"Q" * 16 + b"\n"
        )
        ids = find_tokens(synthetic)
        self.assertIn("private-key-pem", ids)
        self.assertIn("github-access-token", ids)
        self.assertIn("aws-access-id", ids)
        for finding in ids:
            self.assertNotIn("ghp_", finding)
            self.assertNotIn("AKIA", finding)
            self.assertNotIn("PRIVATE KEY", finding)

    def test_detects_tracked_private_file_and_missed_telemetry_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [Path(".env.production"), Path("notes.py")]
            (root / names[0]).write_text("SAMPLE_ONLY=1\n", "utf-8")
            (root / names[1]).write_text("api = 'test'\n", "utf-8")
            findings = scan_tracked(root, names)
            self.assertEqual(1, len(findings))
            self.assertEqual("tracked-private-file", findings[0]["rule"])
            self.assertEqual(".env.production", findings[0]["path"])
        self.assertFalse(private_filename(Path(".env.example")))
        self.assertTrue(private_filename(Path("android/app/.env")))
        self.assertTrue(private_filename(Path("release-store.p12")))
        self.assertTrue(ANDROID_BAD_LOGGING["stacktrace-export"].search("failure.printStackTrace()"))
        self.assertTrue(ANDROID_BAD_LOGGING["android-logcat"].search('Log.e("x", content)'))
        self.assertTrue(WORKFLOW_BAD_LOGGING["shell-command-tracing"].search("set -x\n"))

    def test_rejects_secret_embedded_in_otherwise_valid_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.apk"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("classes.dex", b"clean-dex")
                zf.writestr("assets/embedded_kotlin_profiles.json.spv", b"SPV1" + b"x" * 32)
            self.assertEqual([], scan_apk(path))
            with zipfile.ZipFile(path, "a") as zf:
                zf.writestr("assets/credentials.json", b"-----BEGIN " + b"RSA PRIVATE KEY-----")
            findings = scan_apk(path)
            self.assertEqual(1, len(findings))
            self.assertEqual("apk-private-key-pem", findings[0]["rule"])
            self.assertNotIn("RSA PRIVATE KEY", repr(findings))

    def test_scan_report_is_safe_to_upload(self):
        result = audit()
        self.assertFalse(result["secretValuesReported"])
        self.assertEqual("PASS", result["status"], result["findings"])
        self.assertEqual([], result["findings"])


if __name__ == "__main__":
    unittest.main()

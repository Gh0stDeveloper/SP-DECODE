"""Stable release cannot be unlocked by synthetic tests or alpha version."""
import copy
import unittest
from scripts.android_release_gate import REQUIRED, check

BASE = {
    "schemaVersion": 1, "candidateVersion": "0.3.5-alpha",
    "stableVersion": None, "decision": "NO-GO", "ownerApproval": False,
    "evidence": {key: {"status": "pending", "report": ""} for key in REQUIRED},
}


class AndroidReleaseGateTest(unittest.TestCase):
    def test_candidate_allowed_only_for_matching_prerelease(self):
        self.assertEqual([], check(BASE, "candidate", "0.3.5-alpha"))
        self.assertTrue(check(BASE, "candidate", "1.0.0"))
        self.assertTrue(check(BASE, "candidate", "0.3.4-alpha"))

    def test_stable_always_blocked_until_all_evidence_and_owner(self):
        errors = check(BASE, "stable", "1.0.0")
        self.assertGreaterEqual(len(errors), len(REQUIRED))
        ready = copy.deepcopy(BASE)
        ready["stableVersion"] = "1.0.0"
        ready["decision"] = "GO"
        ready["ownerApproval"] = True
        self.assertTrue(check(ready, "stable", "1.0.0"))
        for key in REQUIRED:
            ready["evidence"][key] = {
                "status": "verified",
                "report": f"https://example.org/authorized-evidence/{key}",
            }
        self.assertEqual([], check(ready, "stable", "1.0.0"))
        ready["evidence"]["arm64Physical"]["report"] = ""
        self.assertTrue(check(ready, "stable", "1.0.0"))

    def test_public_preview_needs_explicit_owner_approval_and_no_go(self):
        data = copy.deepcopy(BASE)
        data["stableVersion"] = "1.0.0"
        self.assertTrue(check(data, "public-preview", "1.0.0"))
        data["ownerApproval"] = True
        self.assertTrue(check(data, "public-preview", "1.0.0"))
        data["publicPreviewApproval"] = True
        self.assertEqual([], check(data, "public-preview", "1.0.0"))
        self.assertTrue(check(data, "public-preview", "1.0.1"))
        self.assertTrue(check(data, "public-preview", "1.0.0-alpha"))
        data["decision"] = "GO"
        self.assertTrue(check(data, "public-preview", "1.0.0"))
        # Publishing a preview never unlocks stable without eight verified reports.
        self.assertTrue(check(data, "stable", "1.0.0"))

    def test_explicit_version_scoped_owner_stable_approval_without_false_audit(self):
        # The owner may distribute a stable APK using manual QA acceptance,
        # but pending independent checks remain pending and are never relabeled.
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            # The gate permits only documented repo-local reports.
            report = "docs/android/USER_MANUAL_VALIDATION_2026-10-09.md"
            assert Path(report).is_file()
            owner = copy.deepcopy(BASE)
            owner["decision"] = "OWNER-GO"
            owner["stableVersion"] = "1.0.4"
            owner["ownerApproval"] = True
            owner["ownerStableAcceptance"] = {
                "approved": True, "version": "1.0.4", "report": report,
            }
            self.assertEqual([], check(owner, "stable", "1.0.4"))
            self.assertTrue(check(owner, "stable", "1.0.5"))
            self.assertTrue(check(owner, "stable", "1.0.4-rc.1"))
            self.assertEqual("pending", owner["evidence"]["signingInstallUpgrade"]["status"])
            owner["ownerStableAcceptance"]["approved"] = False
            self.assertTrue(check(owner, "stable", "1.0.4"))
            owner["ownerStableAcceptance"]["approved"] = True
            owner["ownerStableAcceptance"]["version"] = "1.0.3"
            self.assertTrue(check(owner, "stable", "1.0.4"))
            owner["ownerStableAcceptance"]["version"] = "1.0.4"
            owner["ownerStableAcceptance"]["report"] = "docs/android/missing-report.md"
            self.assertTrue(check(owner, "stable", "1.0.4"))
            owner["ownerStableAcceptance"]["report"] = report
            owner["ownerApproval"] = False
            self.assertTrue(check(owner, "stable", "1.0.4"))
            owner["ownerApproval"] = True
            self.assertTrue(check(owner, "public-preview", "1.0.4"))

    def test_tampered_evidence_schema_is_rejected(self):
        broken=copy.deepcopy(BASE)
        broken["schemaVersion"]=99
        self.assertTrue(check(broken,"candidate","0.3.5-alpha"))


if __name__ == "__main__":
    unittest.main()

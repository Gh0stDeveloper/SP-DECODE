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

    def test_tampered_evidence_schema_is_rejected(self):
        broken=copy.deepcopy(BASE)
        broken["schemaVersion"]=99
        self.assertTrue(check(broken,"candidate","0.3.5-alpha"))


if __name__ == "__main__":
    unittest.main()

"""SP-DECODE Phase H audit tests; no false real-device or public-release claims."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from scripts.android_h_production_audit import inspect
from scripts.android_release_gate import check

ROOT = Path(__file__).resolve().parents[1]


class PhaseHProductionAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = inspect("1.0.6", 17)

    def test_source_inventory_still_exactly_239(self):
        self.assertEqual(self.data["sourceGate"], "PASS",
                         {k:v for k,v in self.data["sourceChecks"].items() if not v["pass"]})
        catalog=self.data["catalog"]
        self.assertEqual(catalog["suffixes"], 239)
        self.assertEqual(catalog["nativePortRoutes"], 239)
        self.assertEqual(catalog["certifiedCurrentExporterSuffixes"], 0)
        self.assertEqual(catalog["byPhase"],
             {"legacy":61,"B":81,"C":41,"D":16,"E":27,"F":13})

    def test_offline_and_signing_are_explicitly_enforced(self):
        checks=self.data["sourceChecks"]
        for name in ("source_manifest_offline","history_backup_disabled",
            "permanent_signing_only","release_sha_and_main_only",
            "v1v2v3_and_alignment","all_golden_generators_ci"):
            with self.subTest(check=name):self.assertTrue(checks[name]["pass"])

    def test_no_unverified_real_exporter_is_claimed_certified(self):
        self.assertTrue(self.data["assertions"]["no_real_vendor_exporters_claimed"])
        self.assertEqual(self.data["productionGate"],"NO-GO")
        self.assertGreaterEqual(len(self.data["pendingEvidence"]),8)
        flags={row["gate"] for row in self.data["pendingEvidence"]}
        self.assertIn("realExporterFormats",flags)
        self.assertIn("signingInstallUpgrade",flags)
        self.assertIn("real_text_protocol_version_matrix",flags)

    def test_new_release_cannot_be_public_or_stable_before_gates(self):
        readiness=json.loads((ROOT/"release/android-readiness.json").read_text("utf-8"))
        self.assertEqual(readiness["stableVersion"],"1.0.6")
        self.assertEqual(readiness["decision"],"NO-GO")
        self.assertFalse(readiness["publicPreviewApproval"])
        self.assertFalse(readiness["ownerStableAcceptance"]["approved"])
        self.assertTrue(check(readiness,"stable","1.0.6"))
        self.assertTrue(check(readiness,"public-preview","1.0.6"))
        tampered=copy.deepcopy(readiness)
        tampered["stableVersion"]="1.0.7"
        self.assertTrue(check(tampered,"stable","1.0.7"))
        self.assertTrue(check(tampered,"public-preview","1.0.7"))

    def test_whatsnew_and_catalog_status_all_four_locales(self):
        for folder in ("values","values-es","values-pt-rBR","values-ar"):
            with self.subTest(locale=folder):
                path=ROOT/"android/app/src/main/res"/folder/"strings.xml"
                content=path.read_text("utf-8")
                self.assertIn("1.0.6",content)
                self.assertIn("239",content)
                self.assertNotIn("183 native",content)
                self.assertNotIn("56 pending",content)


if __name__ == "__main__":
    unittest.main()

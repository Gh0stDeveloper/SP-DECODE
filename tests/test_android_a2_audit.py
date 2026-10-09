from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "docs" / "android" / "audit_decoders.py"
spec = importlib.util.spec_from_file_location("android_a2_audit", PATH)
assert spec is not None and spec.loader is not None
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AndroidA2AuditTests(unittest.TestCase):
    def test_current_registry_inventory_and_all_source_paths(self):
        report = audit.analyze(ROOT)
        counts = report["counts"]
        self.assertEqual(counts["registeredSuffixes"], 60)
        self.assertEqual(counts["distinctScripts"], 49)
        self.assertEqual(counts["pythonSuffixes"], 49)
        self.assertEqual(counts["nodeSuffixes"], 8)
        self.assertEqual(counts["phpSuffixes"], 3)
        self.assertEqual(len(report["scripts"]), 49)
        self.assertEqual(report["errors"], [])
        self.assertEqual(
            {x["suffix"] for x in report["registeredExtensions"]},
            set(json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]),
        )

    def test_known_portability_flags_are_reported_without_executing(self):
        rows = {x["script"]: x for x in audit.analyze(ROOT)["scripts"]}
        self.assertTrue(rows["decoders/Python/NPVTUNNEL.py"]["flags"]["uses_pickle"])
        self.assertFalse(rows["decoders/Python/gold.py"]["flags"]["imports_network_facility"])
        self.assertFalse(rows["decoders/Python/gold.py"]["flags"]["invokes_network_api"])
        self.assertTrue(rows["decoders/Python/TLS.py"]["flags"]["declares_run"])
        self.assertTrue(rows["decoders/JavaScript/modulepro.js"]["flags"]["writes_files"])
        self.assertTrue(rows["decoders/JavaScript/hat.js"]["knownResources"])
        self.assertTrue(rows["decoders/Python/maya.py"]["knownResources"])

    def test_reports_do_not_include_raw_secret_strings(self):
        report = audit.analyze(ROOT)
        self.assertEqual(report["resultVerification"], "not_performed")
        self.assertEqual(report["androidExecutionVerification"], "not_performed")
        text = audit.format_md(report)
        self.assertIn("Not verified", text)
        self.assertNotIn("client_secret=", text)
        self.assertNotIn("BEGIN PRIVATE KEY", text)

    def test_scanner_never_imports_or_executes_fixture_decoder(self):
        original_root = audit.ROOT
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                decoder = root / "decoders" / "Python" / "safe.py"
                decoder.parent.mkdir(parents=True)
                marker = root / "MUST_NOT_EXIST"
                decoder.write_text(
                    f"from pathlib import Path\n"
                    f"Path({str(marker)!r}).write_text('executed')\n"
                    "def run(file_bytes):\n    return 'ok'\n",
                    encoding="utf-8",
                )
                (root / "decoders.json").write_text(json.dumps({
                    "decoders": {"test": {"name": "Test", "script": "decoders/Python/safe.py", "runtime": "python"}}
                }), encoding="utf-8")
                report = audit.analyze(root)
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["counts"]["distinctScripts"], 1)
                self.assertFalse(marker.exists())
        finally:
            audit.ROOT = original_root

    def test_registry_does_not_allow_parent_directory_traversal(self):
        original_root = audit.ROOT
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "decoders.json").write_text(json.dumps({
                    "decoders": {"bad": {"name": "Bad", "script": "../escape.py", "runtime": "python"}}
                }), encoding="utf-8")
                report = audit.analyze(root)
                self.assertIn("unsafe_script_path:bad", report["errors"])
        finally:
            audit.ROOT = original_root


if __name__ == "__main__":
    unittest.main()

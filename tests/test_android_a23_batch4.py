"""Exact synthetic Linux CLI stdout golden checks — batch four (10 suffixes).

Never execute untrusted inputs, never connect to Internet. Validates original
scripts using fake profiles only, preserving every byte of original output.
Linux success does NOT certify current external app exports or Android runtime.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spdecode.registry import get_supported_extension
from tests.golden.a23_batch4 import (
    BATCH4_GENERATORS, BATCH4_CASE_SUFFIXES,
    BATCH4_SCRIPTS, BATCH4_CLI_RUNTIMES,
)
ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "tests/golden/expected"
MANIFEST = ROOT / "tests/golden/manifest.json"


def execute_cli(case_id: str, contents: bytes, folder: Path):
    suffix = BATCH4_CASE_SUFFIXES[case_id]
    file_path = folder / ("synthetic-b4." + suffix)
    file_path.write_bytes(contents)
    exe = {"python": sys.executable, "node": "node", "php": "php"}[
        BATCH4_CLI_RUNTIMES[case_id]
    ]
    args = [exe, str(ROOT / BATCH4_SCRIPTS[suffix]), str(file_path)]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["TZ"] = "UTC"
    return subprocess.run(
        args, cwd=ROOT, env=environment, capture_output=True,
        check=False, timeout=25,
    )


class A23Batch4GoldenTests(unittest.TestCase):
    def test_01_ten_full_cli_stdout_snapshots(self):
        with tempfile.TemporaryDirectory(prefix="a23-batch4-") as folder_name:
            folder = Path(folder_name)
            for case_id, generator in BATCH4_GENERATORS.items():
                with self.subTest(case=case_id):
                    actual = execute_cli(case_id, generator(), folder)
                    golden = (EXPECTED / (case_id + ".txt")).read_bytes()
                    self.assertEqual(actual.returncode, 0, f"{case_id}: {actual.stderr!r}")
                    self.assertEqual(actual.stderr, b"", f"{case_id}: {actual.stderr!r}")
                    self.assertEqual(actual.stdout, golden,
                        f"{case_id} actual={actual.stdout!r}; expected={golden!r}")
                    self.assertIn(b"example.org" if case_id != "batch4-hat" else b"A23 synthetic", actual.stdout)
                    self.assertEqual(get_supported_extension(
                        "test." + BATCH4_CASE_SUFFIXES[case_id]
                    ), BATCH4_CASE_SUFFIXES[case_id])

    def test_02_generators_deterministic_and_manifest_integrity(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        registry = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]
        cases = {x["id"]: x for x in manifest["fixtureCaseDefinitions"]}
        ext = {x["suffix"]: x for x in manifest["extensions"]}
        self.assertEqual(len(BATCH4_GENERATORS), 10)
        self.assertEqual(len(set(BATCH4_CASE_SUFFIXES.values())), 10)
        for case_id, generate in BATCH4_GENERATORS.items():
            suffix = BATCH4_CASE_SUFFIXES[case_id]
            with self.subTest(case=case_id):
                self.assertEqual(generate(), generate())
                self.assertEqual(registry[suffix]["script"], BATCH4_SCRIPTS[suffix])
                self.assertEqual(ext[suffix]["caseIds"], [case_id])
                self.assertEqual(cases[case_id]["androidGolden"], "not_started")
                self.assertEqual(cases[case_id]["goldenOutputKind"], "cli_stdout_exact")
                self.assertIn(cases[case_id]["linuxGolden"],
                    {"pending_ci", "verified_linux_ci"})
        self.assertEqual(len([x for x in manifest["extensions"] if not x["caseIds"]]), 11)

    def test_03_negative_corrupt_files_never_create_profile(self):
        with tempfile.TemporaryDirectory(prefix="a23-batch4-bad-") as folder_name:
            for case_id in BATCH4_GENERATORS:
                with self.subTest(case=case_id):
                    cp = execute_cli(case_id, b"not-a-valid-encrypted-config", Path(folder_name))
                    self.assertNotIn(b"example.org", cp.stdout)
                    self.assertNotIn(b"A23 synthetic", cp.stdout)
                    self.assertLess(len(cp.stdout), 16000)
                    self.assertLess(len(cp.stderr), 16000)

    def test_04_all_final_goldens_have_frozen_sha256(self):
        cases = {
            item["id"]: item
            for item in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]
        }
        for case_id, generate in BATCH4_GENERATORS.items():
            with self.subTest(case=case_id):
                row = cases[case_id]
                self.assertEqual(row["linuxGolden"], "verified_linux_ci")
                self.assertEqual(hashlib.sha256(generate()).hexdigest(), row["inputSha256"])
                golden = (EXPECTED / (case_id + ".txt")).read_bytes()
                self.assertEqual(hashlib.sha256(golden).hexdigest(), row["expectedRawUtf8Sha256"])


if __name__ == "__main__":
    unittest.main()

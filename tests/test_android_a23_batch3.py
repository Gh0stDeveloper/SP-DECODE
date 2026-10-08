"""A.2.3 batch #3: exact CLI golden proof for 10 additional file suffixes.

Only reproducible, user-independent synthetic data are included. Native Android
execution and compatibility with third-party exporter versions are NOT tested.
These legacy decoders have CLI side effects and must NOT be imported to run.
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
from tests.golden.a23_batch3 import (
    BATCH3_CASE_SUFFIXES, BATCH3_GENERATORS, SOURCE_SCRIPTS,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests/golden"
MANIFEST = GOLDEN / "manifest.json"


def cli_execute(script: str, suffix: str, contents: bytes, folder: Path) -> subprocess.CompletedProcess[bytes]:
    input_path = folder / ("synthetic-batch3." + suffix)
    input_path.write_bytes(contents)
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, str(ROOT / script), str(input_path)],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        timeout=20,
        check=False,
    )


class A23Batch3TenSuffixGoldenTests(unittest.TestCase):
    def test_01_all_ten_suffixes_have_exact_full_cli_stdout(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-b3-") as tmp:
            folder = Path(tmp)
            for case_id, generator in BATCH3_GENERATORS.items():
                suffix = BATCH3_CASE_SUFFIXES[case_id]
                with self.subTest(suffix=suffix, case_id=case_id):
                    raw = generator()
                    actual = cli_execute(SOURCE_SCRIPTS[suffix], suffix, raw, folder)
                    expected = (GOLDEN / "expected" / (case_id + ".txt")).read_bytes()
                    self.assertEqual(actual.returncode, 0, (case_id, actual.stderr))
                    self.assertEqual(actual.stderr, b"", (case_id, actual.stderr))
                    self.assertEqual(actual.stdout, expected, f"Raw output changed for {case_id}")
                    # A positive test must decode substantive example data;
                    # this prevents false passes from an empty CLI exit code.
                    self.assertIn(b"example.org", actual.stdout)
                    self.assertIn(b"443", actual.stdout)
                    self.assertIn("𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘", actual.stdout.decode("utf-8"))
                    self.assertEqual(get_supported_extension("config." + suffix), suffix)

    def test_02_generators_are_deterministic_and_match_registered_paths(self):
        registry = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        records = {r["suffix"]: r for r in manifest["extensions"]}
        self.assertEqual(len(BATCH3_GENERATORS), 10)
        self.assertEqual(len(set(BATCH3_CASE_SUFFIXES.values())), 10)
        for case_id, generate in BATCH3_GENERATORS.items():
            suffix = BATCH3_CASE_SUFFIXES[case_id]
            with self.subTest(suffix=suffix):
                self.assertEqual(generate(), generate())
                self.assertEqual(registry[suffix]["script"], SOURCE_SCRIPTS[suffix])
                self.assertEqual(records[suffix]["caseIds"], [case_id])
                self.assertIn(records[suffix]["fixtureStatus"], {
                    "synthetic_positive_planned_ci",
                    "synthetic_linux_golden_verified",
                })
        self.assertEqual(len([r for r in manifest["extensions"] if not r["caseIds"]]), 21)

    def test_03_bad_files_do_not_produce_successful_profile_output(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-b3-bad-") as tmp:
            folder = Path(tmp)
            for suffix in ("agn", "sksrv", "sksrv.png", "xscks", "aro"):
                with self.subTest(suffix=suffix):
                    bad = cli_execute(SOURCE_SCRIPTS[suffix], suffix, b"invalid-bad-fixture", folder)
                    self.assertNotIn(b"example.org", bad.stdout)
                    self.assertNotIn(b"Host: example.org", bad.stdout)
                    self.assertLess(len(bad.stdout), 8192)
                    self.assertLess(len(bad.stderr), 8192)

    def test_04_frozen_input_output_hashes_after_ci(self):
        cases = {
            r["id"]: r
            for r in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]
        }
        for case_id, generator in BATCH3_GENERATORS.items():
            with self.subTest(case_id=case_id):
                record = cases[case_id]
                self.assertEqual(record["goldenOutputKind"], "cli_stdout_exact")
                self.assertEqual(record["androidGolden"], "not_started")
                self.assertEqual(record["linuxGolden"], "verified_linux_ci")
                self.assertEqual(
                    hashlib.sha256(generator()).hexdigest(), record["inputSha256"]
                )
                self.assertEqual(
                    hashlib.sha256(
                        (GOLDEN / "expected" / (case_id + ".txt")).read_bytes()
                    ).hexdigest(), record["expectedRawUtf8Sha256"]
                )


if __name__ == "__main__":
    unittest.main()

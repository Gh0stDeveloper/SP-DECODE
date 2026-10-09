"""A.2.3 final SSH golden, 59/59 synthetic Linux suffixes, NOT Android.

Use SPDECODE_SSH_GOLDEN_TEST=1 solely to stabilize randomly selected
decoration. Normal decoder behavior remains random. Raw output stays intact.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad
from decoders.Python import ssh as ssh_decoder
from spdecode.registry import get_supported_extension
from tests.golden.a23_batch8_ssh import (
    ROOT, SCRIPT, CASE_ID, SUFFIX, GOLDEN_ENV, GOLDEN_VALUE,
    PAYLOAD, _audited_function_literals, ssh_bytes,
)

EXPECTED = ROOT / "tests/golden/expected/batch8-ssh.txt"
MANIFEST = ROOT / "tests/golden/manifest.json"


def run_cli(file_path: Path, golden: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TZ="UTC")
    if golden:
        env[GOLDEN_ENV] = GOLDEN_VALUE
    else:
        env.pop(GOLDEN_ENV, None)
    return subprocess.run(
        [sys.executable, str(ROOT / SCRIPT), str(file_path)],
        cwd=ROOT, env=env, capture_output=True, timeout=15, check=False,
    )


class SSHFinalGoldenTests(unittest.TestCase):
    def test_01_byte_exact_full_original_cli_output_repeatable(self):
        with tempfile.TemporaryDirectory(prefix="a23-ssh-positive-") as tmp:
            path = Path(tmp) / "synthetic.ssh"
            path.write_bytes(ssh_bytes())
            first, second = run_cli(path), run_cli(path)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(first.stderr, b"")
            self.assertEqual(second.stderr, b"")
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(first.stdout, EXPECTED.read_bytes())
            for term in (b"example.org", b"443", b"A23 synthetic"):
                self.assertIn(term, first.stdout)
            self.assertNotIn(b"decode error", first.stdout.lower())

    def test_02_59_of_59_linux_only_complete(self):
        registry = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        rows = {r["suffix"]: r for r in manifest["extensions"]}
        cases = {c["id"]: c for c in manifest["fixtureCaseDefinitions"]}
        self.assertEqual(len(rows), 59)
        self.assertEqual(len(cases), 60)
        self.assertEqual({r["suffix"] for r in manifest["extensions"]}, set(registry) - {"lnk"})
        self.assertIn("lnk",registry)
        self.assertEqual(sum(not r["caseIds"] for r in rows.values()), 0)
        self.assertEqual(registry[SUFFIX]["script"], SCRIPT)
        self.assertEqual(get_supported_extension("synthetic.ssh"), SUFFIX)
        self.assertEqual(rows[SUFFIX]["caseIds"], [CASE_ID])
        self.assertEqual(rows[SUFFIX]["fixtureStatus"], "synthetic_linux_golden_verified")
        self.assertEqual(cases[CASE_ID]["linuxGolden"], "verified_linux_ci")
        self.assertEqual(cases[CASE_ID]["androidGolden"], "not_started")
        self.assertEqual(cases[CASE_ID]["sourceKind"], "synthetic")
        self.assertEqual(cases[CASE_ID]["exporterVersion"], "not_verified")
        self.assertTrue(all(r["androidVerification"] == "not_started" for r in rows.values()))

    def test_03_pinned_input_and_expected_sha256(self):
        case = next(c for c in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]
                    if c["id"] == CASE_ID)
        self.assertEqual(ssh_bytes(), ssh_bytes())
        self.assertEqual(hashlib.sha256(ssh_bytes()).hexdigest(), case["inputSha256"])
        self.assertEqual(hashlib.sha256(EXPECTED.read_bytes()).hexdigest(), case["expectedRawUtf8Sha256"])
        self.assertEqual(case["expectedRawText"], "tests/golden/expected/batch8-ssh.txt")
        self.assertEqual(case["goldenOutputKind"], "cli_stdout_exact")

    def test_04_corrupt_and_nonprofile_file_fail_closed(self):
        key, iv = _audited_function_literals()
        nonprofile = base64.b64encode(Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(
            pad(b"not a usable profile", Blowfish.block_size)))
        with tempfile.TemporaryDirectory(prefix="a23-ssh-invalid-") as tmp:
            path = Path(tmp) / "broken.ssh"
            for bad in (b"garbage-text", b"", b"AAAA", nonprofile):
                with self.subTest(raw=bad[:10]):
                    path.write_bytes(bad)
                    result = run_cli(path)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"decode error", result.stderr.lower())
                    self.assertNotIn(b"Traceback", result.stderr)

    def test_05_regular_mode_does_not_force_emoji(self):
        with tempfile.TemporaryDirectory(prefix="a23-ssh-normal-") as tmp:
            path = Path(tmp) / "synthetic.ssh"
            path.write_bytes(ssh_bytes())
            with mock.patch.dict(os.environ, {GOLDEN_ENV: "0"}):
                with mock.patch.object(ssh_decoder.random, "choice", return_value="X") as picker:
                    raw = ssh_decoder.ssh_injector(path)
                    picker.assert_called_once()
            self.assertIn("Host : example.org", raw)
            self.assertIn("│[X] Host : example.org", raw)


if __name__ == "__main__":
    unittest.main()

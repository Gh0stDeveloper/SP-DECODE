"""A.2.3 complete-stdout golden tests for explicitly synthetic configs.

Linux reference execution only. These tests DO NOT certify Android or the
versions of third-party exporter applications. Raw text must not be translated.
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

from decoders.Python.DARKTUNNEL import run as decode_dark
from decoders.Python.EV2RAY import run as decode_ev2ray
from decoders.Python.SSCCUSTOM import run as decode_ssc
from decoders.Python.TLS import run as decode_tls
from decoders.Python.HTTPINJECTORLITE import run as decode_ehil
from decoders.Python.HTTPCUSTOM import run as decode_hc
from decoders.Python.HTTPTWEAK import run as decode_ht, decode_profile as decode_ht_profile
from spdecode.registry import get_supported_extension
from tests.golden.a23_generators import SYNTHETIC_GENERATORS, TWEAK_PROFILE

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"
MANIFEST = GOLDEN / "manifest.json"
REFERENCE_FUNCTIONS = {
    "tls-aesgcm": decode_tls,
    "httptweak-v1-ht": decode_ht,
    "httptweak-v2-htb": decode_ht,
    "httpcustom-chacha-rst": decode_hc,
    "ehil-aescbc-double": decode_ehil,
    "ev2ray-plain": decode_ev2ray,
    "ev2ray-aes128": decode_ev2ray,
    "ssc-chacha20": decode_ssc,
    "dark-aescfb-msgpack": decode_dark,
}
CLI_SCRIPTS = {
    "tls-aesgcm": "decoders/Python/TLS.py",
    "httptweak-v1-ht": "decoders/Python/HTTPTWEAK.py",
    "httptweak-v2-htb": "decoders/Python/HTTPTWEAK.py",
    "httpcustom-chacha-rst": "decoders/Python/HTTPCUSTOM.py",
    "ehil-aescbc-double": "decoders/Python/HTTPINJECTORLITE.py",
    "ev2ray-plain": "decoders/Python/EV2RAY.py",
    "ev2ray-aes128": "decoders/Python/EV2RAY.py",
    "ssc-chacha20": "decoders/Python/SSCCUSTOM.py",
    "dark-aescfb-msgpack": "decoders/Python/DARKTUNNEL.py",
}
CASE_SUFFIXES = {
    "tls-aesgcm": "tls",
    "httptweak-v1-ht": "ht",
    "httptweak-v2-htb": "htb",
    "httpcustom-chacha-rst": "hc",
    "ehil-aescbc-double": "ehil",
    "ev2ray-plain": "v2",
    "ev2ray-aes128": "v2",
    "ssc-chacha20": "ssc",
    "dark-aescfb-msgpack": "dark",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_case_records() -> list[dict[str, object]]:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    return data["fixtureCaseDefinitions"]


class A23GoldenFixtureTests(unittest.TestCase):
    """Exact comparisons to stored, human-reviewable golden reference files."""

    def test_01_registry_coverage_and_honest_missing_states(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        registered = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]
        entries = manifest["extensions"]
        self.assertEqual(len(entries), 59)
        self.assertEqual(len({x["suffix"] for x in entries}), 59)
        self.assertEqual({x["suffix"] for x in entries}, set(registered))
        for row in entries:
            suffix = row["suffix"]
            self.assertEqual(row["script"], registered[suffix]["script"])
            self.assertEqual(row["runtime"], registered[suffix]["runtime"])
            self.assertEqual(row["androidVerification"], "not_started")
            if row["caseIds"]:
                self.assertEqual(row["fixtureStatus"], "synthetic_linux_golden_verified")
            else:
                self.assertEqual(row["fixtureStatus"], "fixture_missing")
        cases = manifest["fixtureCaseDefinitions"]
        self.assertEqual({x["id"] for x in cases}, set(SYNTHETIC_GENERATORS))
        self.assertTrue(set(REFERENCE_FUNCTIONS).issubset(set(SYNTHETIC_GENERATORS)))
        for row in cases:
            self.assertEqual(row["sourceKind"], "synthetic")
            self.assertEqual(row["linuxGolden"], "verified_linux_ci")
            self.assertEqual(row["androidGolden"], "not_started")

    def test_02_exact_golden_raw_output(self):
        for case_id in REFERENCE_FUNCTIONS:
            generator = SYNTHETIC_GENERATORS[case_id]
            with self.subTest(case_id=case_id):
                data = generator()
                self.assertIsInstance(data, bytes)
                self.assertTrue(data)
                expected = (GOLDEN / "expected" / f"{case_id}.txt").read_text(encoding="utf-8")
                actual = REFERENCE_FUNCTIONS[case_id](data)
                self.assertIsNotNone(actual, f"Decoder returned None for {case_id}")
                self.assertEqual(actual, expected, f"Golden output drift: {case_id}")
                self.assertEqual(actual.encode("utf-8"), expected.encode("utf-8"))
                frozen = next(c for c in fixture_case_records() if c["id"] == case_id)
                self.assertEqual(sha256_bytes(data), frozen["inputSha256"])
                self.assertEqual(
                    sha256_bytes(expected.encode("utf-8")),
                    frozen["expectedRawUtf8Sha256"],
                )

    def test_03_synthetic_inputs_are_deterministic(self):
        for case_id, generator in SYNTHETIC_GENERATORS.items():
            with self.subTest(case_id=case_id):
                first = generator()
                second = generator()
                self.assertEqual(first, second, f"Input bytes not reproducible: {case_id}")

    def test_04_python_cli_stdout_parity_no_format_translation(self):
        """CLI stdout exactly equals golden + print() LF, with no stderr."""
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-") as tmp:
            for case_id in REFERENCE_FUNCTIONS:
                generator = SYNTHETIC_GENERATORS[case_id]
                with self.subTest(case_id=case_id):
                    input_path = Path(tmp) / f"synthetic-{case_id}.{CASE_SUFFIXES[case_id]}"
                    input_path.write_bytes(generator())
                    env = os.environ.copy()
                    env["PYTHONDONTWRITEBYTECODE"] = "1"
                    completed = subprocess.run(
                        [sys.executable, str(ROOT / CLI_SCRIPTS[case_id]), str(input_path)],
                        cwd=str(ROOT), check=False, capture_output=True,
                        env=env, timeout=20,
                    )
                    expected = (GOLDEN / "expected" / f"{case_id}.txt").read_bytes()
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
                    self.assertEqual(completed.stderr, b"")
                    if case_id.startswith("httptweak-"):
                        self.assertEqual(completed.stdout, (json.dumps(TWEAK_PROFILE, indent=4, ensure_ascii=False) + "\n").encode("utf-8"))
                        self.assertEqual(decode_ht_profile(generator()), TWEAK_PROFILE)
                    else:
                        self.assertEqual(completed.stdout, expected + b"\n")

    def test_05_corrupt_inputs_fail_safely(self):
        """Negative fixture corpus verifies no false 'success' for malformed input."""
        cases = [
            ("tls-empty", decode_tls, b""),
            ("hc-empty", decode_hc, b""),
            ("hc-malformed", decode_hc, b"not a http custom config"),
            ("ht-empty", decode_ht, b""),
            ("ht-unknown-variant", decode_ht, base64.b64encode(b"\xff" + bytes(48))),
            ("ehil-empty", decode_ehil, b""),
            ("ehil-wrong-magic", decode_ehil, b"\x00\x04invalid"),
            ("tls-malformed", decode_tls, b"tls://!invalid??"),
            ("ev2ray-empty", decode_ev2ray, b""),
            ("ev2ray-truncated", decode_ev2ray, b"incorrect-profile"),
            ("ssc-empty", decode_ssc, b""),
            ("ssc-odd-hex", decode_ssc, b"123"),
            ("dark-empty", decode_dark, b""),
            ("dark-invalid-outer", decode_dark, b"dark://e30="),  # {}
        ]
        for name, decoder, payload in cases:
            with self.subTest(case=name):
                self.assertIsNone(decoder(payload))

    def test_06_tls_aead_tag_tampering_is_rejected(self):
        """Mutation occurs on a synthetic AES-GCM ciphertext fragment."""
        synthetic = SYNTHETIC_GENERATORS["tls-aesgcm"]()
        outer = synthetic.removeprefix(b"tls://")
        raw = bytearray(base64.b64decode(outer[::-1]))
        self.assertGreater(len(raw), 148)
        raw[12] ^= 0x01
        modified = b"tls://" + base64.b64encode(raw)[::-1]
        self.assertIsNone(decode_tls(modified))

    def test_07_unsupported_aliases_are_not_marked_verified(self):
        cases = {
            "config.sksrv.png": "sksrv.png",
            "config.SKsRv.PnG": "sksrv.png",
            "config.fɴ": "fɴ",
            "config.HTB": "htb",
            "config.npvt": "npvt",
            "no_extension": None,
        }
        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                self.assertEqual(get_supported_extension(filename), expected)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        unresolved = [r for r in manifest["extensions"] if not r["caseIds"]]
        self.assertEqual(len(unresolved), 0)

    def test_08_snapshot_paths_are_only_repo_owned(self):
        for record in fixture_case_records():
            case_id = record["id"]
            self.assertEqual(record["expectedRawText"], f"tests/golden/expected/{case_id}.txt")
            expected = (ROOT / record["expectedRawText"]).resolve()
            self.assertTrue(expected.is_relative_to(GOLDEN))
            self.assertTrue(expected.is_file())
            self.assertLess(expected.stat().st_size, 16384)


if __name__ == "__main__":
    unittest.main()

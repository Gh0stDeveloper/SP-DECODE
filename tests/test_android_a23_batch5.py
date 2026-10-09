"""A.2.3 batch 5: synthetic cross-runtime CLI parity (10 new suffixes).

No network and no customer data. This suite checks exact raw output ONLY when
the authoritative Linux CLI snapshot has been reviewed and SHA-256 pinned.
Historical REZ uses a self-roundtrip cipher as documented.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from spdecode.registry import get_supported_extension
from tests.golden.a23_batch5 import GENERATORS, CASE_SUFFIXES, RUNTIMES, SCRIPTS

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/"tests/golden/manifest.json"
GOLDENS=ROOT/"tests/golden/expected"


def execute(case_id: str, raw: bytes, folder: Path):
    suffix=CASE_SUFFIXES[case_id]
    path=folder/("synthetic-b5."+suffix)
    path.write_bytes(raw)
    program={"python":sys.executable,"node":"node","php":"php"}[RUNTIMES[suffix]]
    env=os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"]="1"
    env["TZ"]="UTC"
    return subprocess.run(
        [program,str(ROOT/SCRIPTS[suffix]),str(path)],
        cwd=ROOT,capture_output=True,check=False,timeout=20,env=env,
    )


class A23Batch5Goldens(unittest.TestCase):
    def test_01_all_positive_cases_meaningful_and_exact_when_frozen(self):
        cases={
            row["id"]:row
            for row in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]
        }
        with tempfile.TemporaryDirectory(prefix="a23-b5-") as folder:
            for case_id,generator in GENERATORS.items():
                with self.subTest(case=case_id):
                    stdout=execute(case_id,generator(),Path(folder))
                    self.assertEqual(stdout.returncode,0,f"{case_id}: {stdout.stderr!r}")
                    self.assertEqual(stdout.stderr,b"",f"{case_id}: {stdout.stderr!r}")
                    self.assertIn(b"example.org",stdout.stdout,case_id)
                    self.assertTrue(stdout.stdout.strip())
                    expected=GOLDENS/(case_id+".txt")
                    if cases[case_id]["linuxGolden"] != "verified_linux_ci":
                        self.fail(f"Unverified golden: {case_id}")
                    self.assertEqual(stdout.stdout,expected.read_bytes())
                    self.assertEqual(
                        hashlib.sha256(stdout.stdout).hexdigest(),
                        cases[case_id]["expectedRawUtf8Sha256"],
                    )

    def test_02_manifest_and_determinism(self):
        manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
        registry=json.loads((ROOT/"decoders.json").read_text(encoding="utf-8"))["decoders"]
        rows={x["suffix"]:x for x in manifest["extensions"]}
        cases={x["id"]:x for x in manifest["fixtureCaseDefinitions"]}
        self.assertEqual(len(GENERATORS),10)
        self.assertEqual(len({CASE_SUFFIXES[k] for k in GENERATORS}),10)
        for case_id,gen in GENERATORS.items():
            suffix=CASE_SUFFIXES[case_id]
            with self.subTest(case=case_id):
                self.assertEqual(gen(),gen())
                self.assertEqual(registry[suffix]["script"],SCRIPTS[suffix])
                self.assertEqual(rows[suffix]["caseIds"],[case_id])
                self.assertEqual(get_supported_extension("sample."+suffix),suffix)
                self.assertEqual(cases[case_id]["androidGolden"],"not_started")
                self.assertEqual(cases[case_id]["linuxGolden"],"verified_linux_ci")
                self.assertEqual(hashlib.sha256(gen()).hexdigest(),cases[case_id]["inputSha256"])
        self.assertEqual(len([x for x in rows.values() if not x["caseIds"]]),1)

    def test_03_invalid_inputs_cannot_produce_a_valid_dummy_config(self):
        with tempfile.TemporaryDirectory(prefix="a23-b5-bad-") as folder:
            for case_id in GENERATORS:
                with self.subTest(case=case_id):
                    out=execute(case_id,b"invalid encrypted synthetic test",Path(folder))
                    self.assertNotIn(b"example.org",out.stdout)
                    self.assertLess(len(out.stdout),16000)
                    self.assertLess(len(out.stderr),16000)

    def test_04_pinned_input_output_hashes_when_verified(self):
        cases={x["id"]:x for x in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]}
        for case_id,gen in GENERATORS.items():
            with self.subTest(case=case_id):
                case=cases[case_id]
                self.assertEqual(case["linuxGolden"],"verified_linux_ci")
                self.assertEqual(hashlib.sha256(gen()).hexdigest(),case["inputSha256"])
                self.assertEqual(
                    hashlib.sha256((GOLDENS/(case_id+".txt")).read_bytes()).hexdigest(),
                    case["expectedRawUtf8Sha256"],
                )


if __name__=="__main__":
    unittest.main()

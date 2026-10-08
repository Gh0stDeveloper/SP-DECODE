"""A.2.3 batch 6: 10 exact synthetic CLI goldens — Python + Node.

The historic STK TEA generator exercises source-defined encrypt/decrypt (a
self-roundtrip). No exporter-version or Android compatibility is implied.
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
from tests.golden.a23_batch6 import GENERATORS, CASE_SUFFIXES, SCRIPTS, ROOT

MANIFEST=ROOT/"tests/golden/manifest.json"
EXPECTED=ROOT/"tests/golden/expected"


def execute(case_id: str, value: bytes, temp: Path):
    suffix=CASE_SUFFIXES[case_id]
    path=temp/("b6-dummy."+suffix)
    path.write_bytes(value)
    exe="node" if suffix=="stk" else sys.executable
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",TZ="UTC")
    return subprocess.run(
        [exe,str(ROOT/SCRIPTS[suffix]),str(path)],
        cwd=ROOT,env=env,capture_output=True,check=False,timeout=25,
    )


class A23Batch6Goldens(unittest.TestCase):
    def test_01_ten_valid_profiles_match_entire_original_stdout(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-b6-good-") as folder:
            for case_id,generate in GENERATORS.items():
                with self.subTest(case=case_id):
                    output=execute(case_id,generate(),Path(folder))
                    self.assertEqual(output.returncode,0,output.stderr)
                    self.assertEqual(output.stderr,b"")
                    self.assertIn(b"example.org",output.stdout,
                        "Do not accept error-only output as a positive fixture")
                    self.assertEqual(output.stdout,(EXPECTED/(case_id+".txt")).read_bytes())

    def test_02_all_ten_are_registered_and_reproducible(self):
        manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
        registry=json.loads((ROOT/"decoders.json").read_text(encoding="utf-8"))["decoders"]
        bysuffix={r["suffix"]:r for r in manifest["extensions"]}
        byid={r["id"]:r for r in manifest["fixtureCaseDefinitions"]}
        self.assertEqual(len(GENERATORS),10)
        self.assertEqual(len(set(CASE_SUFFIXES.values())),10)
        for case_id,gen in GENERATORS.items():
            suffix=CASE_SUFFIXES[case_id]
            with self.subTest(case=case_id):
                self.assertEqual(gen(),gen())
                self.assertEqual(registry[suffix]["script"],SCRIPTS[suffix])
                self.assertEqual(bysuffix[suffix]["caseIds"],[case_id])
                self.assertEqual(bysuffix[suffix]["fixtureStatus"],"synthetic_linux_golden_verified")
                self.assertEqual(byid[case_id]["linuxGolden"],"verified_linux_ci")
                self.assertEqual(byid[case_id]["androidGolden"],"not_started")
                self.assertEqual(get_supported_extension("synthetic."+suffix),suffix)
        self.assertEqual(len([r for r in bysuffix.values() if not r["caseIds"]]),11)

    def test_03_invalid_files_never_reveal_synthetic_profile(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-b6-invalid-") as folder:
            for case_id in GENERATORS:
                with self.subTest(case=case_id):
                    output=execute(case_id,b"not valid fake ciphertext",Path(folder))
                    self.assertNotIn(b"example.org",output.stdout)
                    self.assertLess(len(output.stdout),16384)
                    self.assertLess(len(output.stderr),16384)

    def test_04_all_ten_inputs_outputs_have_frozen_sha256(self):
        cases={r["id"]:r for r in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]}
        for id_,generate in GENERATORS.items():
            with self.subTest(case=id_):
                c=cases[id_]
                self.assertEqual(hashlib.sha256(generate()).hexdigest(),c["inputSha256"])
                self.assertEqual(hashlib.sha256((EXPECTED/(id_+".txt")).read_bytes()).hexdigest(),c["expectedRawUtf8Sha256"])
                self.assertEqual(c["goldenOutputKind"],"cli_stdout_exact")


if __name__=="__main__":
    unittest.main()

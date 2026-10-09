"""Batch 7: byte-exact Linux CLI golden coverage, 10 synthetic file suffixes.

All profiles are artificial and offline. A success here does NOT prove current
vendor exports, an Android parser or EHI standard-IV/Argon2 compatibility.
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
from tests.golden.a23_batch7 import CASE_SUFFIXES,GENERATORS,RUNTIMES,SCRIPTS,ROOT

MANIFEST=ROOT/"tests/golden/manifest.json"
EXPECTED=ROOT/"tests/golden/expected"

def execute(cid: str, data: bytes, folder: Path):
    suffix=CASE_SUFFIXES[cid]
    file=folder/("offline-batch7."+suffix)
    file.write_bytes(data)
    exe="node" if RUNTIMES[suffix]=="node" else sys.executable
    environment=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",TZ="UTC")
    return subprocess.run([exe,str(ROOT/SCRIPTS[suffix]),str(file)],cwd=ROOT,
           env=environment,check=False,capture_output=True,timeout=60)

class A23Batch7Goldens(unittest.TestCase):
    def test_01_positive_complete_raw_stdout(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-b7-positive-") as folder:
            for cid,generate in GENERATORS.items():
                with self.subTest(id=cid):
                    result=execute(cid,generate(),Path(folder))
                    self.assertEqual(result.returncode,0,(cid,result.stderr))
                    self.assertEqual(result.stderr,b"",cid)
                    self.assertIn(b"example.org",result.stdout,cid)
                    self.assertEqual(result.stdout,(EXPECTED/(cid+".txt")).read_bytes(),cid)

    def test_02_exact_registry_manifest_and_determinism(self):
        rows=json.loads(MANIFEST.read_text(encoding="utf-8"))
        registry=json.loads((ROOT/"decoders.json").read_text(encoding="utf-8"))["decoders"]
        bysuffix={e["suffix"]:e for e in rows["extensions"]}
        byid={e["id"]:e for e in rows["fixtureCaseDefinitions"]}
        self.assertEqual(len(GENERATORS),10)
        self.assertEqual(len(set(CASE_SUFFIXES.values())),10)
        for cid,fn in GENERATORS.items():
            suffix=CASE_SUFFIXES[cid]
            with self.subTest(suffix=suffix):
                self.assertEqual(fn(),fn())
                self.assertEqual(registry[suffix]["script"],SCRIPTS[suffix])
                self.assertEqual(bysuffix[suffix]["caseIds"],[cid])
                self.assertEqual(bysuffix[suffix]["fixtureStatus"],"synthetic_linux_golden_verified")
                self.assertEqual(byid[cid]["linuxGolden"],"verified_linux_ci")
                self.assertEqual(byid[cid]["androidGolden"],"not_started")
                self.assertEqual(get_supported_extension("profile."+suffix),suffix)
        self.assertEqual([x["suffix"] for x in rows["extensions"] if not x["caseIds"]],[])

    def test_03_corrupt_input_does_not_produce_successful_profile(self):
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-b7-bad-") as folder:
            for cid in GENERATORS:
                with self.subTest(id=cid):
                    p=execute(cid,b"synthetic-not-a-valid-blob",Path(folder))
                    self.assertNotIn(b"example.org",p.stdout,cid)
                    self.assertLess(len(p.stdout),16384)
                    self.assertLess(len(p.stderr),16384)

    def test_04_golden_input_and_output_sha256_frozen(self):
        cases={x["id"]:x for x in json.loads(MANIFEST.read_text(encoding="utf-8"))["fixtureCaseDefinitions"]}
        for cid,fn in GENERATORS.items():
            with self.subTest(id=cid):
                c=cases[cid]
                self.assertEqual(hashlib.sha256(fn()).hexdigest(),c["inputSha256"])
                self.assertEqual(hashlib.sha256((EXPECTED/(cid+".txt")).read_bytes()).hexdigest(),c["expectedRawUtf8Sha256"])
                self.assertEqual(c["goldenOutputKind"],"cli_stdout_exact")

    def test_05_node_decoder_never_mutates_shared_config_in_normal_execution(self):
        config=ROOT/"cfg/config.inc.json"
        before=config.read_bytes()
        with tempfile.TemporaryDirectory(prefix="spdecode-a23-b7-config-") as folder:
            for cid in ("batch7-epro","batch7-npv2"):
                with self.subTest(id=cid):
                    result=execute(cid,GENERATORS[cid](),Path(folder))
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(config.read_bytes(),before,
                       "Normal decode MUST NOT alter shared bot configuration")

if __name__=="__main__":
    unittest.main()

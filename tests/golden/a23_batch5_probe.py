"""Controlled CI bootstrap: emit candidate *synthetic only* stdout references.

Never generate expected snapshots automatically during the test run. Review
the CI reference, save exact stdout to tests/golden/expected and freeze digest.
Call only while batch5 manifest is provisional; remove CI bootstrap after merge.
"""
from __future__ import annotations
import hashlib,json,tempfile
from pathlib import Path
from tests.golden.a23_batch5 import GENERATORS
from tests.test_android_a23_batch5 import execute

def main():
    with tempfile.TemporaryDirectory(prefix="a23-b5-probe-") as folder:
        for case,gen in GENERATORS.items():
            inp=gen()
            cp=execute(case,inp,Path(folder))
            print("A23B5_OUTPUT "+json.dumps({
                "case":case,"rc":cp.returncode,
                "stdout":cp.stdout.decode("utf-8",errors="replace"),
                "stderr":cp.stderr.decode("utf-8",errors="replace"),
                "inputSha256":hashlib.sha256(inp).hexdigest(),
                "outputSha256":hashlib.sha256(cp.stdout).hexdigest(),
            },ensure_ascii=True,sort_keys=True, separators=(",",":")),flush=True)
    return 0

if __name__=="__main__":
    raise SystemExit(main())

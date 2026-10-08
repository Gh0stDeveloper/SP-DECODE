"""Diagnostic only: candidate positives with raw stdout and SHA256 in CI logs.

Cannot be interpreted as a golden success until exact expected bytes are
reviewed and pinned in the fixture manifest.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from tests.golden.a23_batch6 import GENERATORS, CASE_SUFFIXES, SCRIPTS, ROOT

with tempfile.TemporaryDirectory(prefix="spdecode-b6-probe-") as temp:
    for id_, fn in GENERATORS.items():
        ext = CASE_SUFFIXES[id_]
        path = Path(temp) / ("synthetic." + ext)
        try:
            value = fn()
            path.write_bytes(value)
            args = ["node" if ext == "stk" else sys.executable, str(ROOT / SCRIPTS[ext]), str(path)]
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            r = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, timeout=20)
            print("[B6_PROBE] " + json.dumps({
                "id": id_, "exit": r.returncode, "stdout": r.stdout.decode("utf-8", "replace"),
                "stderr": r.stderr.decode("utf-8", "replace"),
                "inputSha256": hashlib.sha256(value).hexdigest(),
                "outputSha256": hashlib.sha256(r.stdout).hexdigest(),
            }, ensure_ascii=True),flush=True)
        except Exception as e:
            print("[B6_PROBE] "+json.dumps({"id":id_,"exception":str(e)}),flush=True)

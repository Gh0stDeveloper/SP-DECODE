"""Synthetic-only decoder probe; diagnostic results do not count as goldens."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
from tests.golden.a23_batch7 import GENERATORS,CASE_SUFFIXES,RUNTIMES,SCRIPTS,ROOT
with tempfile.TemporaryDirectory(prefix="spdecode-b7-") as tmp:
  for cid,fn in GENERATORS.items():
    suffix=CASE_SUFFIXES[cid]
    path=Path(tmp)/("offline."+suffix)
    try:
      data=fn();path.write_bytes(data)
      cmd=["node" if RUNTIMES[suffix]=="node" else sys.executable,str(ROOT/SCRIPTS[suffix]),str(path)]
      result=subprocess.run(cmd,cwd=ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",TZ="UTC"),
                            capture_output=True,timeout=50,check=False)
      print("[B7_PROBE] "+json.dumps({"id":cid,"exit":result.returncode,
        "stderr":result.stderr.decode("utf-8","replace")[-1200:],
        "stdout":result.stdout.decode("utf-8","replace")[:16000],
        "inputSha256":hashlib.sha256(data).hexdigest(),
        "outputSha256":hashlib.sha256(result.stdout).hexdigest()},ensure_ascii=True),flush=True)
    except Exception as exc:
      print("[B7_PROBE] "+json.dumps({"id":cid,"exception":repr(exc)}),flush=True)

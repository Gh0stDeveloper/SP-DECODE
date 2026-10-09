"""Diagnostic CLI probe for SSH. Nothing is golden until hashes are pinned."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
from tests.golden.a23_batch8_ssh import ROOT,SCRIPT,ssh_bytes,GOLDEN_ENV,GOLDEN_VALUE

with tempfile.TemporaryDirectory(prefix="a23-ssh-") as p:
    path=Path(p)/"synthetic.ssh"
    data=ssh_bytes()
    path.write_bytes(data)
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",TZ="UTC")
    env[GOLDEN_ENV]=GOLDEN_VALUE
    result=subprocess.run([sys.executable,str(ROOT/SCRIPT),str(path)],
      cwd=ROOT,env=env,capture_output=True,timeout=15,check=False)
    print("[B8_SSH_PROBE] "+json.dumps({
       "exit":result.returncode,
       "stderr":result.stderr.decode("utf-8","replace"),
       "stdout":result.stdout.decode("utf-8","replace"),
       "inputSha256":hashlib.sha256(data).hexdigest(),
       "outputSha256":hashlib.sha256(result.stdout).hexdigest(),
     },ensure_ascii=True))

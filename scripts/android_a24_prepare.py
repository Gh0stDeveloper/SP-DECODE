#!/usr/bin/env python3
"""Build strictly synthetic Android instrumentation assets from frozen A.2.3.

No authorized real-user profiles or cryptographic keys are copied to outputs.
Every source file's SHA256 must match the source-controlled manifest.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CASES=("ev2ray-plain", "ev2ray-aes128", "tls-aesgcm")


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def prepare(out:Path)->list[dict[str,str]]:
    from tests.golden.a23_generators import SYNTHETIC_GENERATORS
    manifest=json.loads((ROOT/"tests/golden/manifest.json").read_text("utf-8"))
    indexed={c["id"]:c for c in manifest["fixtureCaseDefinitions"]}
    out.mkdir(parents=True,exist_ok=True)
    rows=[]
    for cid in CASES:
        case=indexed[cid]
        assert case["sourceKind"]=="synthetic",cid
        assert case["linuxGolden"]=="verified_linux_ci",cid
        assert case["androidGolden"]=="not_started",cid
        source=SYNTHETIC_GENERATORS[cid]()
        expected=ROOT/case["expectedRawText"]
        if not expected.is_file() or not expected.resolve().is_relative_to((ROOT/"tests/golden/expected").resolve()):
            raise ValueError("Invalid golden path for "+cid)
        truth=expected.read_bytes()
        if sha(source)!=case["inputSha256"] or sha(truth)!=case["expectedRawUtf8Sha256"]:
            raise ValueError("Frozen golden mismatch for "+cid)
        (out/(cid+(".tls" if cid=="tls-aesgcm" else ".v2"))).write_bytes(source)
        (out/(cid+".txt")).write_bytes(truth)
        rows.append({"id":cid,"inputSha256":sha(source),"expectedRawUtf8Sha256":sha(truth)})
    (out/"checksums.json").write_text(json.dumps(rows,indent=2)+"\n","utf-8")
    return rows


def main()->int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir",type=Path,required=True)
    args=ap.parse_args()
    result=prepare(args.output_dir)
    print("[A.2.4] Prepared",len(result),"synthetic Android golden vectors; output-only; no customer exports")
    return 0


if __name__=="__main__":
    raise SystemExit(main())

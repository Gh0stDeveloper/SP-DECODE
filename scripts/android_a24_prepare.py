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
CASES=("ev2ray-plain", "ev2ray-aes128", "tls-aesgcm", "batch4-phc", "batch5-mina", "batch6-vpnlite", "batch4-cloudy", "batch4-mij", "batch4-fnnetwork", "batch4-uwu", "sksrv-sksrv", "batch5-maya", "batch5-xui", "batch6-at", "batch6-nm", "batch4-ost", "batch4-sbr", "batch6-pcx", "batch6-nt", "batch6-pb", "aro-minus18", "batch6-ipt", "batch7-gold", "multides-agn", "multides-cly", "multides-fɴ", "multides-jvc", "multides-jvi", "multides-v2i", "sksrv-sksrv-png", "xscks-aescbc", "batch5-mrc", "batch5-mtl", "batch5-jez", "batch5-hrt", "batch6-ziv", "batch7-epro", "batch7-npv2", "batch5-rez", "batch5-rezl", "batch7-tvt", "batch6-stk", "batch7-xtp", "batch7-roy", "batch4-sksplus", "batch4-sks", "batch7-sut", "batch5-tnl", "batch8-ssh")
SUFFIX={"ev2ray-plain": "v2", "ev2ray-aes128": "v2", "tls-aesgcm": "tls", "batch4-phc": "phc", "batch5-mina": "mina", "batch6-vpnlite": "vpnlite", "batch4-cloudy": "cloudy", "batch4-mij": "mij", "batch4-fnnetwork": "fnnetwork", "batch4-uwu": "uwu", "sksrv-sksrv": "sksrv", "batch5-maya": "maya", "batch5-xui": "xui", "batch6-at": "at", "batch6-nm": "nm", "batch4-ost": "ost", "batch4-sbr": "sbr", "batch6-pcx": "pcx", "batch6-nt": "nt", "batch6-pb": "pb", "aro-minus18": "aro", "batch6-ipt": "ipt", "batch7-gold": "gold", "multides-agn": "agn", "multides-cly": "cly", "multides-fɴ": "fɴ", "multides-jvc": "jvc", "multides-jvi": "jvi", "multides-v2i": "v2i", "sksrv-sksrv-png": "sksrv.png", "xscks-aescbc": "xscks", "batch5-mrc": "mrc", "batch5-mtl": "mtl", "batch5-jez": "jez", "batch5-hrt": "hrt", "batch6-ziv": "ziv", "batch7-epro": "epro", "batch7-npv2": "npv2", "batch5-rez": "rez", "batch5-rezl": "rezl", "batch7-tvt": "tvt", "batch6-stk": "stk", "batch7-xtp": "xtp", "batch7-roy": "roy", "batch4-sksplus": "sksplus", "batch4-sks": "sks", "batch7-sut": "sut", "batch5-tnl": "tnl", "batch8-ssh": "ssh"}


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
        (out/(cid+"."+SUFFIX[cid])).write_bytes(source)
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

#!/usr/bin/env python3
"""Regenerate/verify the read-only Android inventory without overstating support."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CATALOG=ROOT/"android/app/src/main/assets/decoder_catalog.json"


def generate()->dict:
    registry=json.loads((ROOT/"decoders.json").read_text("utf-8"))["decoders"]
    assert len(registry)==59
    rows=[]
    for suffix,entry in registry.items():
        rows.append({
            "suffix":suffix,
            "script":entry["script"],
            "originalRuntime":entry["runtime"],
            "linuxGoldenSynthetic":True,
            "androidPortStatus":("prototype_two_synthetic_cases" if suffix=="v2" else "prototype_tls_aesgcm_synthetic_case" if suffix=="tls" else "not_implemented"),
            "androidVerified":False,
            "exporterVersionsVerified":[],
        })
    rows.sort(key=lambda x:(-len(x["suffix"]),x["suffix"]))
    return {
        "schemaVersion":1,"inventorySource":"decoders.json",
        "syntheticLinuxCoveredSuffixes":59,"androidCertifiedSuffixes":0,
        "androidPrototypeSuffixes":["v2","tls"],"entries":rows,
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write",action="store_true")
    args=ap.parse_args()
    expected=generate()
    if args.write:
        CATALOG.parent.mkdir(parents=True,exist_ok=True)
        CATALOG.write_text(json.dumps(expected,ensure_ascii=False,indent=2)+"\n","utf-8")
    else:
        if not CATALOG.exists() or json.loads(CATALOG.read_text("utf-8"))!=expected:
            raise SystemExit("Android catalog is stale: python scripts/android_a24_catalog.py --write")
    print("[A.2.4] Android registry verified: 59 registered, 2 experimental, 0 certified")


if __name__=="__main__":
    main()

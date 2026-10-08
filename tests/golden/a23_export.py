#!/usr/bin/env python3
"""Export A.2.3 authorized synthetic inputs to files for manual Android testing.

Only deterministic fake data from tests.golden.a23_generators is exported.
No input from production customers or third-party apps. All output hashes are
frozen in tests/golden/manifest.json; fail if a fixture drifts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tests.golden.a23_generators import SYNTHETIC_GENERATORS
from tests.golden.a23_batch3 import BATCH3_CASE_SUFFIXES

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = {
    "tls-aesgcm": "tls",
    "httptweak-v1-ht": "ht",
    "httptweak-v2-htb": "htb",
    "httpcustom-chacha-rst": "hc",
    "ev2ray-plain": "v2",
    "ev2ray-aes128": "v2",
    "ssc-chacha20": "ssc",
    "dark-aescfb-msgpack": "dark",
    **BATCH3_CASE_SUFFIXES,
    "ehil-aescbc-double": "ehil",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "tests/golden/manifest.json").read_text(encoding="utf-8"))
    entries = manifest["fixtureCaseDefinitions"]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    samples = []
    for case in entries:
        id_ = case["id"]
        raw = SYNTHETIC_GENERATORS[id_]()
        digest = hashlib.sha256(raw).hexdigest()
        if case["linuxGolden"] == "verified_linux_ci" and digest != case["inputSha256"]:
            raise SystemExit(f"[FAIL] A.2.3 fixture changed without review: {id_}")
        filename = f"{id_}.{SUFFIX[id_]}"
        (args.output_dir / filename).write_bytes(raw)
        samples.append({"filename": filename, "sha256": digest, "synthetic": True})
        print(f"[A.2.3] export {filename}: sha256={digest}")
    (args.output_dir / "README.txt").write_text(
        "SP-DECODE A.2.3 SYNTHETIC FIXTURES ONLY\n"
        "Generated deterministically by tests/golden/a23_export.py.\n"
        "Not produced by third-party applications. Contains no real credentials.\n"
        "Reference raw outputs live in tests/golden/expected/*.txt.\n"
        "Android compatibility and exporter version support NOT verified.\n",
        encoding="utf-8",
    )
    (args.output_dir / "SHA256.json").write_text(
        json.dumps(samples, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

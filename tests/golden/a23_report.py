#!/usr/bin/env python3
"""Emit metadata-only A.2.3 golden corpus coverage and deterministic SHA-256.

Does not print decoder raw outputs, ciphertext, keys, or credentials. The
reference output snapshots are committed as synthetic files under tests/golden.
All real format/app-version and Android verification claims remain pending.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tests.golden.a23_generators import SYNTHETIC_GENERATORS

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests/golden/manifest.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_report() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = manifest["extensions"]
    cases = []
    for row in manifest["fixtureCaseDefinitions"]:
        id_ = row["id"]
        data = SYNTHETIC_GENERATORS[id_]()
        golden = (ROOT / row["expectedRawText"]).read_bytes()
        if row["linuxGolden"] == "verified_linux_ci":
            if _sha(data) != row.get("inputSha256") or _sha(golden) != row.get("expectedRawUtf8Sha256"):
                raise ValueError(f"frozen golden fixture digest drift for {id_}")
        elif row["linuxGolden"] != "pending_ci":
            raise ValueError(f"invalid golden status: {id_}")
        cases.append({
            "id": id_,
            "inputSha256": _sha(data),
            "expectedRawUtf8Sha256": _sha(golden),
            "inputBytes": len(data),
            "outputBytes": len(golden),
            "sourceKind": "synthetic",
            "expectedRawText": row["expectedRawText"],
            "referenceDecoderScript": next(
                x["script"] for x in rows if id_ in x["caseIds"]
            ),
            "verificationLevel": ("L2_linux_golden_verified_android_pending" if row["linuxGolden"] == "verified_linux_ci" else "L1_linux_golden_pending_ci"),
            "androidStatus": "not_verified",
            "exporterVersion": "not_verified",
        })
    covered = [row["suffix"] for row in rows if row["caseIds"]]
    missing = [row["suffix"] for row in rows if not row["caseIds"]]
    return {
        "schemaVersion": 1,
        "referenceType": "synthetic_golden_metadata_only",
        "formatCount": len(rows),
        "goldenCaseCount": len(cases),
        "positiveCoveredSuffixCount": len(covered),
        "positiveCoveredSuffixes": sorted(covered),
        "missingPositiveFixtureSuffixes": sorted(missing),
        "missingPositiveFixtureCount": len(missing),
        "androidVerifiedSuffixes": 0,
        "cases": cases,
        "limits": [
            "Synthetic generators are not third-party exporter validation.",
            "Frozen Linux outputs are not Android decoder verification.",
            "Input/expected digests are not a substitute for authorized fixture provenance.",
            "A.2.4 Android parity and ABI tests remain pending.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("[A.2.3] Registry coverage:", report["formatCount"])
    print("[A.2.3] Synthetic golden cases:", report["goldenCaseCount"])
    print("[A.2.3] Suffixes with positive synthetic samples:", report["positiveCoveredSuffixCount"])
    print("[A.2.3] Missing positive samples:", report["missingPositiveFixtureCount"])
    print("[A.2.3] Android verified:", report["androidVerifiedSuffixes"])
    print("[A.2.3] SHA256 metadata (synthetic only):")
    for item in report["cases"]:
        print(f"  {item['id']}: input={item['inputSha256']} output={item['expectedRawUtf8Sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

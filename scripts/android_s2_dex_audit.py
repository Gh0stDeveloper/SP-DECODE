#!/usr/bin/env python3
"""Phase S.2: inventory, targeted DEX-literal regression and material parity.

The inventory describes potential embedded material, not a claim that all
matched strings are credentials. Values are never echoed to stdout/reports.
Offline APK-level obfuscation is not a confidentiality boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATERIAL = Path("android/app/src/main/assets/embedded_kotlin_profiles.json")
KOTLIN = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity")
MIGRATED = ("HatPort.kt", "HcPort.kt", "IndependentF1Port.kt", "ZivPort.kt", "PhcPort.kt")
HEX_LITERAL = re.compile(r'"[a-fA-F0-9]{32,}"')
BASE64_LITERAL = re.compile(r'"[A-Za-z0-9+/]{24,}={0,2}"')
IDENTIFIER = re.compile(r"\b(?:private\s+)?(?:const\s+)?val\s+(?:key|iv|password|secret|seed|salt|nonce)\w*\b", re.I)


def materials(root: Path = ROOT) -> dict:
    source = root / MATERIAL
    raw = json.loads(source.read_text("utf-8"))
    if raw.get("schemaVersion") != 1:
        raise ValueError("Unexpected S.2 decoder materials schema")
    hat = raw["hat"]
    hc = raw["httpCustom"]
    f1 = raw["independentF1"]
    import base64
    aes = base64.b64decode(hat["aesKeyB64"], validate=True)
    xor = hat["profileV5XorPassword"].encode("utf-8")
    custom = bytes.fromhex(hc["outerXorKeyHex"])
    ltm = bytes.fromhex(f1["ltmPasswordHex"]).decode("utf-8", errors="replace").encode("utf-8")
    vn7 = [item.encode("utf-8") for item in f1["vn7Passwords"]]
    if len(aes) != 16 or len(xor) != 18 or len(custom) != 11 or len(vn7) != 2:
        raise ValueError("S.2 migrated material size mismatch")
    if not all(vn7) or len(ltm) < 16:
        raise ValueError("S.2 source material missing")
    return {
        "hatAes": aes,
        "hatXor": xor,
        "hcOuterXor": custom,
        "ltmPassword": ltm,
        "vn7One": vn7[0],
        "vn7Two": vn7[1],
    }


def forbidden_literals(root: Path = ROOT) -> dict[str, list[str]]:
    raw = json.loads((root / MATERIAL).read_text("utf-8"))
    hat = raw["hat"]
    hc = raw["httpCustom"]
    f1 = raw["independentF1"]
    ltm = f1["ltmPasswordHex"]
    # The previous constant was concatenated across three Kotlin strings.
    pieces = (ltm[:64], ltm[64:128], ltm[128:])
    return {
        "HatPort.kt": [hat["aesKeyB64"], hat["profileV5XorPassword"]],
        "HcPort.kt": [hc["outerXorKeyHex"]],
        "IndependentF1Port.kt": [*pieces, *f1["vn7Passwords"]],
        "ZivPort.kt": [*f1["vn7Passwords"]],
        "PhcPort.kt": [f1["vn7Passwords"][1]],
    }


def check_source(root: Path = ROOT) -> dict:
    kotlin = root / KOTLIN
    mappings = forbidden_literals(root)
    for name in MIGRATED:
        path = kotlin / name
        body = path.read_text("utf-8")
        if "EmbeddedDecoderMaterials." not in body:
            raise ValueError(f"S.2 migrated port no longer uses typed vault accessor: {name}")
        if any(secret in body for secret in mappings[name] if len(secret) >= 8):
            raise ValueError(f"S.2 decoder constant reintroduced in Kotlin DEX source: {name}")
    loader = (kotlin / "EmbeddedDecoderMaterials.kt").read_text("utf-8")
    if 'SecureAssetVault.readText(ctx, ASSET)' not in loader:
        raise ValueError("Decoder constant loader bypasses authenticated asset vault")
    gradle = (root / "android/app/build.gradle.kts").read_text("utf-8")
    if '"embedded_kotlin_profiles.json"' not in gradle:
        raise ValueError("S.2 constant profile not in protected build allowlist")
    # A coarse, deterministic audit over all native decoder files; count only,
    # never log the values or label heuristic findings as confirmed passwords.
    patterns = {
        "hexCandidates": HEX_LITERAL,
        "base64Candidates": BASE64_LITERAL,
        "keyNamedValues": IDENTIFIER,
    }
    totals = {name: 0 for name in patterns}
    affected = 0
    for path in sorted(kotlin.glob("*.kt")):
        content = path.read_text("utf-8")
        matches = {name: len(p.findall(content)) for name, p in patterns.items()}
        if any(matches.values()):
            affected += 1
        for name, count in matches.items():
            totals[name] += count
    return {
        "scannedKotlinFiles": len(list(kotlin.glob("*.kt"))),
        "heuristicMatchedFiles": affected,
        "heuristicCounts": totals,
        "migratedPorts": list(MIGRATED),
        "migratedMaterialCount": len(materials(root)),
        "classification": {
            "decoderConstants": "historical_public_embedded_reference_data",
            "certificateFingerprint": "public_signing_identity",
            "releaseSigningPrivateKey": "secret_in_github_actions_only",
            "historyKey": "device_generated_android_keystore",
            "userImportedCredentials": "sensitive_runtime_input_not_bundled",
        },
    }


def check_apk(apk: Path, root: Path = ROOT) -> dict:
    if not apk.is_file():
        raise ValueError("APK unavailable: " + str(apk))
    profile = json.loads((root / MATERIAL).read_text("utf-8"))
    literals = [
        profile["hat"]["aesKeyB64"],
        profile["hat"]["profileV5XorPassword"],
        profile["httpCustom"]["outerXorKeyHex"],
        profile["independentF1"]["ltmPasswordHex"][:64],
        profile["independentF1"]["ltmPasswordHex"][64:128],
        *profile["independentF1"]["vn7Passwords"],
    ]
    with zipfile.ZipFile(apk) as zf:
        names = zf.namelist()
        dex = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
        if not dex:
            raise ValueError("APK contains no classes*.dex")
        for name in dex:
            data = zf.read(name)
            for literal in literals:
                if literal.encode("utf-8") in data:
                    raise ValueError(f"Readable migrated decoder literal in DEX ({name})")
        if "assets/embedded_kotlin_profiles.json" in names:
            raise ValueError("Readable S.2 source was packaged in APK")
        if "assets/embedded_kotlin_profiles.json.spv" not in names:
            raise ValueError("Authenticated S.2 material missing from APK")
    return {"dexFilesChecked": len(dex), "migratedDecoderLiteralsPresent": False}


def fixture(root: Path = ROOT) -> dict:
    items = materials(root)
    return {
        "schemaVersion": 1,
        "materials": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            for name, data in sorted(items.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = {"phase": "S.2", "status": "PASS", **check_source()}
    if args.apk:
        result["apk"] = check_apk(args.apk)
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True, exist_ok=True)
        args.fixtures.write_text(json.dumps(fixture(), sort_keys=True) + "\n", "utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf-8")
    print(f"Phase S.2: PASS; {result['scannedKotlinFiles']} native Kotlin files scanned; "
          f"{len(MIGRATED)} ports migrated; "
          f"APK checked: {'yes' if args.apk else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""S.2 batch: prevent reintroduction of six legacy decoder key families in APK DEX.

The original constants are historical public decoder material, not proof of
private backend credentials. Logs and reports contain only names/hashes/counts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("android/app/src/main/assets/embedded_kotlin_profiles.json")
KOTLIN = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity")
MIGRATED = (
    "SipPort.kt", "SshPort.kt", "SksPort.kt",
    "CloudyPort.kt", "GoldPort.kt", "TnlPort.kt",
)


def _root(root: Path) -> dict:
    data = json.loads((root / SOURCE).read_text("utf-8"))
    if data.get("schemaVersion") != 1:
        raise ValueError("Invalid protected decoder material schema")
    return data["legacyBatch2"]


def materials(root: Path = ROOT) -> dict[str, bytes]:
    src = _root(root)
    sip, ssh, sks = src["sip"], src["ssh"], src["sks"]
    cloudy, gold, tnl = src["cloudy"], src["gold"], src["tnl"]
    passwords = tnl["passwords"]
    result = {
        "sipAes": bytes.fromhex(sip["outerAesHex"]),
        "sipVer8": sip["ver8Key"].encode("ascii"),
        "sshBlowfish": ssh["blowfishPassword"].encode("ascii"),
        "sksConfig": sks["configKey"].encode("utf-8"),
        "cloudyAes": base64.b64decode(cloudy["aesKeyB64"], validate=True),
        "cloudyIv": base64.b64decode(cloudy["ivB64"], validate=True),
        "goldSeed": gold["hashSeed"].encode("utf-8"),
        "tnlPassword1": passwords[0].encode("utf-8"),
        "tnlPassword2": passwords[1].encode("utf-8"),
        "tnlOpl": tnl["oplSecret"].encode("utf-8"),
        "tnlOt": bytes.fromhex(tnl["otKeyHex"]),
    }
    required = {
        "sipAes":16,"sipVer8":32,"sshBlowfish":39,"sksConfig":32,
        "cloudyAes":32,"cloudyIv":16,"goldSeed":10,
        "tnlPassword1":32,"tnlPassword2":17,"tnlOpl":64,"tnlOt":32,
    }
    if {name:len(value) for name,value in result.items()} != required:
        raise ValueError("Legacy key family has incorrect original byte sizes")
    return result


def _forbidden(root: Path = ROOT) -> dict[str, list[str]]:
    src = _root(root)
    return {
        "SipPort.kt": [src["sip"]["outerAesHex"], src["sip"]["ver8Key"]],
        "SshPort.kt": [src["ssh"]["blowfishPassword"]],
        "SksPort.kt": [src["sks"]["configKey"]],
        "CloudyPort.kt": [src["cloudy"]["aesKeyB64"], src["cloudy"]["ivB64"]],
        "GoldPort.kt": [src["gold"]["hashSeed"]],
        "TnlPort.kt": [*src["tnl"]["passwords"], src["tnl"]["oplSecret"], src["tnl"]["otKeyHex"]],
    }


def check_source(root: Path = ROOT) -> dict:
    data = materials(root)
    for name, values in _forbidden(root).items():
        body = (root / KOTLIN / name).read_text("utf-8")
        if "LegacyBatch2Materials." not in body:
            raise ValueError(f"Legacy decoder bypassed vault: {name}")
        for value in values:
            if value in body:
                raise ValueError(f"Legacy key returned to Kotlin literals: {name}")
    provider = (root / KOTLIN / "LegacyBatch2Materials.kt").read_text("utf-8")
    if 'SecureAssetVault.readText(context, "embedded_kotlin_profiles.json")' not in provider:
        raise ValueError("Legacy key source bypasses authenticated vault")
    return {
        "migratedPorts": list(MIGRATED),
        "parityMaterials": len(data),
        "keyClassification": "historical_source_available_reference_material",
        "privateSecretsBundled": False,
        "apkUnwrapKeyRecoverable": True,
    }


def check_apk(apk: Path, root: Path = ROOT) -> dict:
    fragments = {
        item.encode("utf-8") for values in _forbidden(root).values()
        for item in values
    }
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
        dex = [name for name in names if re.fullmatch(r"classes\d*\.dex", name)]
        if not dex:
            raise ValueError("No DEX in package")
        for name in dex:
            body = zf.read(name)
            if any(secret in body for secret in fragments):
                raise ValueError(f"Legacy plaintext key exists in APK DEX: {name}")
        if "assets/embedded_kotlin_profiles.json" in names:
            raise ValueError("Plaintext embedded material included in APK")
        if "assets/embedded_kotlin_profiles.json.spv" not in names:
            raise ValueError("Authenticated protected source missing in APK")
    return {"dexFilesChecked": len(dex), "plainKeyLiteralsPresent": False}


def fixture(root: Path = ROOT) -> dict:
    return {
        "schemaVersion": 1,
        "materials": {
            name: {"bytes":len(value), "sha256":hashlib.sha256(value).hexdigest()}
            for name,value in sorted(materials(root).items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = {"phase":"S.2 legacy batch","status":"PASS",**check_source()}
    if args.apk:
        result["apk"] = check_apk(args.apk)
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True,exist_ok=True)
        args.fixtures.write_text(json.dumps(fixture(),sort_keys=True)+"\n","utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf-8")
    print(f"S.2 legacy batch: PASS; {len(MIGRATED)} ports, {len(materials())} material checks; "
          f"APK verified: {'yes' if args.apk else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

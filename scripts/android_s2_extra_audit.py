#!/usr/bin/env python3
"""S.2 continuation: source equivalence and DEX check for TLS, EHI, Dark Tunnel.

No key material printed. Historical public source constants remain recoverable
by reverse engineering; protecting APK string tables is defense-in-depth only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILE = Path("android/app/src/main/assets/embedded_kotlin_profiles.json")
PORT_DIR = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity")
PORTS = {
    "TlsReferencePort.kt": "tls",
    "EhiPort.kt": "ehi",
    "DarkPort.kt": "dark",
    "EhilPort.kt": "ehil",
}


def materials(root: Path = ROOT) -> dict[str, bytes]:
    source = json.loads((root / PROFILE).read_text("utf-8"))
    tls, ehi, dark = source["tls"], source["ehi"], source["dark"]
    tlskeys = [bytes.fromhex(s) for s in tls["hexProfiles"]]
    bypass = [bytes.fromhex(s) for s in ehi["bypassIvHex"]]
    standard = [bytes.fromhex(s) for s in ehi["standardIvHex"]]
    if len(tlskeys) != 6 or any(len(k) != 32 for k in tlskeys):
        raise ValueError("Invalid TLS profile inventory")
    if len(bypass) != 3 or len(standard) != 3 or any(len(k) != 16 for k in bypass + standard):
        raise ValueError("Invalid EHI IV inventory")
    xxtea = ehi["xxteaKeyText"].encode("utf-8")
    dark_outer = dark["outerKeyText"].encode("utf-8")
    dark_nested = dark["nestedKeyText"].encode("utf-8")
    if len(xxtea) != 16 or len(dark_outer) != 32 or len(dark_nested) != 24:
        raise ValueError("Invalid XXTEA or Dark key length")
    one = bytes.fromhex(ehi["firstKeyHex"])
    two = bytes.fromhex(ehi["secondKeyHex"])
    div = bytes.fromhex(dark["ivHex"])
    if len(one) != 32 or len(two) != 16 or len(div) != 16:
        raise ValueError("Invalid EHI keys or Dark IV")
    ehil = source["ehil"]
    ehil_first = [bytes.fromhex(s) for s in ehil["firstLayerKeyHex"]]
    ehil_second = [bytes.fromhex(s) for s in ehil["secondLayerKeyHex"]]
    ehil_ivs = [s.encode("ascii") for s in ehil["ivAscii"]]
    if len(ehil_first) != 3 or any(len(x) != 32 for x in ehil_first):
        raise ValueError("Unexpected EHIL first-layer keys")
    if len(ehil_second) != 2 or any(len(x) != 16 for x in ehil_second):
        raise ValueError("Unexpected EHIL second-layer keys")
    if len(ehil_ivs) != 7 or any(len(x) != 16 for x in ehil_ivs):
        raise ValueError("Unexpected EHIL IV family")
    if ehil_first[0] != one:
        raise ValueError("Shared EHI/EHIL key does not match original source")
    return {
        **{f"ehilFirst{i+1}": value for i,value in enumerate(ehil_first)},
        **{f"ehilSecond{i+1}": value for i,value in enumerate(ehil_second)},
        **{f"ehilIv{i+1}": value for i,value in enumerate(ehil_ivs)},
        **{f"tlsProfile{i+1}": k for i,k in enumerate(tlskeys)},
        "ehiFirst": one, "ehiSecond": two, "ehiXxtea": xxtea,
        **{f"ehiBypassIv{i+1}": k for i,k in enumerate(bypass)},
        **{f"ehiStandardIv{i+1}": k for i,k in enumerate(standard)},
        "darkOuter": dark_outer, "darkNested": dark_nested, "darkIv": div,
    }


def literals(root: Path = ROOT) -> dict[str, list[str]]:
    source = json.loads((root / PROFILE).read_text("utf-8"))
    return {
        "TlsReferencePort.kt": source["tls"]["hexProfiles"],
        "EhiPort.kt": [
            source["ehi"]["firstKeyHex"], source["ehi"]["secondKeyHex"],
            source["ehi"]["xxteaKeyText"][:12],
            *source["ehi"]["bypassIvHex"], *source["ehi"]["standardIvHex"],
        ],
        "DarkPort.kt": [
            source["dark"]["outerKeyText"][1:],
            source["dark"]["nestedKeyText"], source["dark"]["ivHex"],
        ],
        "EhilPort.kt": [
            *source["ehil"]["firstLayerKeyHex"],
            *source["ehil"]["secondLayerKeyHex"],
            *source["ehil"]["ivAscii"],
        ],
    }


def check_sources(root: Path = ROOT) -> dict:
    material = materials(root)
    for file, fragments in literals(root).items():
        body = (root / PORT_DIR / file).read_text("utf-8")
        if "AdditionalDecoderMaterials." not in body:
            raise ValueError(f"Missing typed vault loader: {file}")
        if any(fragment in body for fragment in fragments):
            raise ValueError(f"Historical decoder key literal present in Kotlin: {file}")
    accessor = (root / PORT_DIR / "AdditionalDecoderMaterials.kt").read_text("utf-8")
    if 'SecureAssetVault.readText(context, "embedded_kotlin_profiles.json")' not in accessor:
        raise ValueError("Material accessor bypasses authenticated vault")
    return {
        "validatedMaterialCount": len(material),
        "migratedPorts": sorted(PORTS),
        "classification": "historical_public_embedded_constants_not_unrecoverable_secrets",
        "runtimeUnwrapKeyRecoverable": True,
    }


def check_apk(apk: Path, root: Path = ROOT) -> dict:
    candidates = {value for values in literals(root).values() for value in values}
    with zipfile.ZipFile(apk) as zf:
        names = zf.namelist()
        dex = [name for name in names if re.fullmatch(r"classes\d*\.dex", name)]
        if not dex:
            raise ValueError("No DEX files in APK")
        for name in dex:
            data = zf.read(name)
            if any(fragment.encode("utf-8") in data for fragment in candidates):
                raise ValueError(f"S.2 TLS/EHI/Dark/EHIL literal present in DEX: {name}")
        if "assets/embedded_kotlin_profiles.json" in names:
            raise ValueError("Plaintext material source is packaged")
        if "assets/embedded_kotlin_profiles.json.spv" not in names:
            raise ValueError("Protected material asset missing")
    return {"dexCount": len(dex), "plaintextLiteralsFound": False}


def fixture(root: Path = ROOT) -> dict:
    return {
        "schemaVersion": 1,
        "materials": {
            key: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for key, data in sorted(materials(root).items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = {"phase":"S.2 TLS/EHI/Dark/EHIL","status":"PASS", **check_sources()}
    if args.apk:
        result["apk"] = check_apk(args.apk)
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True, exist_ok=True)
        args.fixtures.write_text(json.dumps(fixture(), sort_keys=True)+"\n", "utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", "utf-8")
    print(f"S.2 extra: PASS; {len(materials())} material checks, "
          f"{len(PORTS)} ports; APK={'checked' if args.apk else 'not requested'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

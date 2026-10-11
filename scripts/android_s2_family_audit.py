#!/usr/bin/env python3
"""S.2 E1/E2/F2 source material inventory, parity manifests, DEX regression gate.

Historical public decoder keys are NEVER printed. This is defense in depth:
the offline SPV1 unwrap key can be recovered from the Android binary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ASSET=Path("android/app/src/main/assets/embedded_kotlin_profiles.json")
PORT=Path("android/app/src/main/java/com/ghostdeveloper/spdecode/parity")
CLASSES=("SpecialE1Port.kt","SpecialE2Port.kt","IndependentF2Port.kt")


def source(root:Path=ROOT)->dict:
    data=json.loads((root/ASSET).read_text("utf-8"))
    if data.get("schemaVersion")!=1:
        raise ValueError("Unsupported protected source schema")
    fam=data["specialKeyFamilies"]
    if set(fam)!={"e1","e2","f2"}:
        raise ValueError("Wrong E1/E2/F2 family inventory")
    return fam


def materials(root:Path=ROOT)->dict[str,bytes]:
    f=source(root)
    e1,e2,f2=f["e1"],f["e2"],f["f2"]
    def text(s):return s.encode("utf-8")
    def rawhex(s):return bytes.fromhex(s)
    result={
      "e1Sentinel":e1["sentinelAscii"].encode("ascii"),
      "e1V2Box":rawhex(e1["v2boxKeyHex"]),
      "e1Slipnet":rawhex(e1["slipnetKeyHex"]),
      "e1Eut":e1["eutPasswordLatin1"].encode("latin-1"),
      "e1Juan":text(e1["juanPassword"]),
      "e2Wyr":text(e2["wyrPassword"]),
      "e2Int":text(e2["intPassword"]),
      "e2WyrlChaCha":rawhex(e2["wyrlChaChaKeyHex"]),
      "e2ArMain":rawhex(e2["arMainKeyHex"]),
      "e2ArField":rawhex(e2["arFieldKeyHex"]),
      "e2ArIv":rawhex(e2["arFieldIvHex"]),
      "e2Ec":e2["ecPassword"].encode("ascii"),
      "e2WyrlPbkdf":text(e2["wyrlPbkdfPassword"]),
      "f2KtrKey":rawhex(f2["ktrAesHex"]),
      "f2KtrIv":rawhex(f2["ktrIvHex"]),
      "f2DevSeed":text(f2["devSeed"]),
      "f2DevPassword":text(f2["devPassword"]),
      "f2DevAlphabet":text(f2["devAlphabet"]),
      "f2Zoba":text(f2["zobaPassword"]),
      "f2N4Password":text(f2["n4Password"]),
      "f2N4Seed":text(f2["n4Seed"]),
      "f2N4Table2":text(f2["n4Table2"]),
      "f2N4Table3":text(f2["n4Table3"]),
      "f2N4Table4":text(f2["n4Table4"]),
    }
    for i,val in enumerate(e2["fthpPasswords"],1):
        result[f"e2Fthp{i}"]=text(val)
    for i,val in enumerate(f2["crevPasswords"],1):
        result[f"f2Crev{i}"]=text(val)
    expected={
      "e1Sentinel":32,"e1V2Box":32,"e1Slipnet":32,"e1Eut":16,"e1Juan":26,
      "e2Wyr":16,"e2Int":16,"e2WyrlChaCha":32,"e2ArMain":32,
      "e2ArField":32,"e2ArIv":16,"e2Ec":15,"e2WyrlPbkdf":16,
      "f2KtrKey":32,"f2KtrIv":16,"f2DevSeed":9,
      "f2Zoba":16,"f2N4Password":6,"f2N4Seed":3,
    }
    if len(e2["fthpPasswords"])!=2 or len(f2["crevPasswords"])!=4:
        raise ValueError("Candidate key counts changed")
    if len(f2["devAlphabet"])!=16 or len(f2["n4Table2"])!=17 or len(f2["n4Table3"])!=16 or len(f2["n4Table4"])!=16:
        raise ValueError("Unicode source alphabet lengths changed")
    for name, size in expected.items():
        if len(result[name])!=size:
            raise ValueError("Original byte count mismatch for "+name)
    if len(result)!=30:
        raise ValueError("Unexpected E1/E2/F2 source inventory")
    return result


def candidates(root:Path=ROOT)->dict[str,list[str]]:
    f=source(root)
    a,b,c=f["e1"],f["e2"],f["f2"]
    return {
      "SpecialE1Port.kt":[a["sentinelAscii"],a["slipnetKeyHex"],a["eutPasswordLatin1"],a["juanPassword"]],
      "SpecialE2Port.kt":[b["wyrPassword"],b["intPassword"],b["wyrlChaChaKeyHex"],
        b["arMainKeyHex"],b["arFieldKeyHex"],b["arFieldIvHex"],b["ecPassword"],
        b["wyrlPbkdfPassword"],*b["fthpPasswords"]],
      "IndependentF2Port.kt":[*c["crevPasswords"],c["ktrAesHex"],c["ktrIvHex"],c["devSeed"],
        c["devPassword"],c["devAlphabet"],c["zobaPassword"],c["n4Password"],c["n4Seed"],
        c["n4Table2"],c["n4Table3"],c["n4Table4"]],
    }


def check_source(root:Path=ROOT)->dict:
    data=materials(root)
    for name,literals in candidates(root).items():
        kotlin=(root/PORT/name).read_text("utf-8")
        if "PhaseS2FamilyMaterials." not in kotlin:
            raise ValueError("Unsafe old material access in "+name)
        if any(s in kotlin for s in literals):
            raise ValueError("Decoder constant regressed into "+name)
    provider=(root/PORT/"PhaseS2FamilyMaterials.kt").read_text("utf-8")
    if 'SecureAssetVault.readText(ctx, "embedded_kotlin_profiles.json")' not in provider:
        raise ValueError("S.2 family provider bypassed authenticated vault")
    router=(root/PORT/"AndroidOfflineDecoderRouter.kt").read_text("utf-8")
    for s in ("SpecialE1Port.decode(context,","SpecialE2Port.decode(context,","IndependentF2Port.decode(context,"):
        if s not in router:
            raise ValueError("Native route bypassed family vault")
    return {
      "status":"PASS",
      "migratedPorts":list(CLASSES),
      "materialCount":len(data),
      "classification":"source_available_historical_decoder_constants",
      "compiledUnwrapKeyRecoverable":True,
    }


def check_apk(apk:Path,root:Path=ROOT)->dict:
    # Keep exact string comparisons for distinctive strings: short, generic
    # strings can legitimately exist in unrelated decoders or Android SDK.
    strings={s.encode("utf-8") for values in candidates(root).values()
             for s in values if len(s)>=12}
    with zipfile.ZipFile(apk) as zf:
        names=set(zf.namelist())
        dex=sorted(n for n in names if re.fullmatch(r"classes\d*\.dex",n))
        if not dex:
            raise ValueError("APK is missing DEX")
        for name in dex:
            code=zf.read(name)
            if any(s in code for s in strings):
                raise ValueError("S.2 protected E/F literal found in DEX: "+name)
        if "assets/embedded_kotlin_profiles.json" in names:
            raise ValueError("Unencrypted E/F vault source exists in APK")
        if "assets/embedded_kotlin_profiles.json.spv" not in names:
            raise ValueError("S.2 protected asset absent")
    return {"dexFilesChecked":len(dex),"sourceLiteralsInDex":False}


def fixture(root:Path=ROOT)->dict:
    return {
      "schemaVersion":1,
      "materials": {
        name:{"bytes":len(val),"sha256":hashlib.sha256(val).hexdigest()}
        for name,val in sorted(materials(root).items())
      },
    }


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk",type=Path)
    p.add_argument("--fixtures",type=Path)
    p.add_argument("--report",type=Path)
    args=p.parse_args()
    result={"phase":"S.2 E1/E2/F2",**check_source()}
    if args.apk: result["apk"]=check_apk(args.apk)
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True,exist_ok=True)
        args.fixtures.write_text(json.dumps(fixture(),sort_keys=True)+"\n","utf-8")
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n","utf-8")
    print("Phase S.2 E1/E2/F2: PASS, 30 source-parity materials, 3 engines")
    return 0


if __name__=="__main__":
    raise SystemExit(main())

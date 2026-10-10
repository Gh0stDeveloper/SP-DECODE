#!/usr/bin/env python3
"""Canonical 16-format Android RENZ/7NET profiles and Python parity vectors.

Only the source module's registered file suffixes and local keys are exported.
Remote URLs and text protocols are excluded from the APK profile manifest.
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
OUT = ROOT / "android/app/src/main/assets/renz_d_profiles.json"


def generate() -> dict:
    from decoders.Python import renz
    from spdecode.registry import DECODER_REGISTRY
    if len(renz.RENZ_FILE_EXTENSIONS) != 16:
        raise ValueError("Expected exactly sixteen RENZ file suffixes")
    assert renz.RENZ_FILE_EXTENSIONS[".osp"] == "7net"
    assert renz.RENZ_FILE_EXTENSIONS[".actun"] == "actunnelvpn"
    if ".vlx" in renz.RENZ_FILE_EXTENSIONS or ".izph" in renz.RENZ_FILE_EXTENSIONS:
        raise ValueError("Collision with Ultra/IZPH")
    aliases = []
    for suffix, profile in sorted(renz.RENZ_FILE_EXTENSIONS.items()):
        item = DECODER_REGISTRY[suffix.removeprefix(".")]
        if item.script != "decoders/Python/renz.py":
            raise ValueError(f"Wrong Python family for {suffix}")
        aliases.append({
            "suffix": suffix.removeprefix("."),
            "profile": profile,
            "name": renz.RENZ_FILE_NAMES[suffix],
        })
    selected = sorted(set(renz.RENZ_FILE_EXTENSIONS.values()))
    if len(selected) != 14:
        raise ValueError(f"Unexpected RENZ key inventory: {selected}")
    profiles = []
    for name in selected:
        value = renz.RENZ_KEYS[name]
        profiles.append({
            "key": name,
            "seed": value.get("KEY_SEED", b"").hex(),
            "iv": value.get("IV", b"").hex(),
            "salt": value.get("FIXED_SALT", b"").hex(),
        })
    return {
        "schemaVersion": 1,
        "suffixCount": 16,
        "profileCount": 14,
        "legacyTypes": [0, 1, 2, 3],
        "profiles": profiles,
        "aliases": aliases,
    }


def make_fixtures() -> dict:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from decoders.Python import renz
    from tests.test_renz_family import (
        profile_fixture, special_fixture, threefish_encrypt256_block,
        xxtea_encrypt,
    )
    from tests.test_renz_legacy_types import legacy_encrypt
    import hashlib

    originals = generate()
    corpus = []
    doc = {
        "Server": "test.invalid", "Port": 443, "Enabled": False,
        "Notes": "Prueba 日本語", "Empty": "",
        "Modes": ["SSH", "V2Ray"], "Nested": {"Port": 22, "Enabled": True},
    }

    def add(suffix: str, mode: str, raw: bytes) -> None:
        expected = renz.decode_file(raw, "." + suffix)
        if expected is None:
            raise AssertionError(f"RENZ Python cannot decode {suffix} mode {mode}")
        parsed = json.loads(expected)
        if parsed["extension"] != "." + suffix:
            raise AssertionError("Wrong RENZ suffix selected")
        corpus.append({
            "suffix": suffix, "mode": mode,
            "encodedInput": base64.b64encode(raw).decode("ascii"),
            "expected": expected,
        })

    for alias in originals["aliases"]:
        add(alias["suffix"], "outer", profile_fixture(alias["profile"], doc))

    # Nested HKDF/Threefish host and PBKDF2/XXTEA username from actual Python.
    special = special_fixture("7net", "edge.example.com")
    add("7net", "nested_host", profile_fixture(
        "7net", {"Host": special, "Port": 22, "Empty": ""}))
    spec = renz.RENZ_KEYS["7net"]
    k = hashlib.pbkdf2_hmac("sha256", spec["KEY_SEED"], spec["FIXED_SALT"], 100000, 32)
    inner = bytes(range(16)) + b"username_ghost"
    ciphertext = AES.new(k, AES.MODE_CBC, spec["IV"]).encrypt(pad(inner,16))
    username = base64.b64encode(xxtea_encrypt(ciphertext,k)).decode("ascii")
    add("7net", "nested_username", profile_fixture(
        "7net", {"Username": username, "Port": 22}))

    # Four independent types, as implemented in Python's 7net fallback.
    typed = {"Host":"typed.example", "Mode":2, "Enabled": False}
    clear = json.dumps(typed, separators=(",", ":")).encode()
    key0 = renz.RENZ_SHA256_KEY_16
    ct0 = AES.new(key0,AES.MODE_CBC,renz.RENZ_FIXED_IV).encrypt(
        pad(legacy_encrypt(bytes((b+2)&255 for b in clear),key0),16))
    add("7net","type0",base64.b64encode(ct0))

    key1a=renz.renz_get_hkdf_key_16()
    key1b=renz.renz_get_hkdf_key()
    aes1=AES.new(key1a,AES.MODE_CBC,renz.RENZ_FIXED_IV).encrypt(pad(clear,16))
    aes1+=bytes(-len(aes1)%32)
    encrypted1=b"".join(
        threefish_encrypt256_block(key1b,(i//32,0),aes1[i:i+32])
        for i in range(0,len(aes1),32))
    add("7net","type1",base64.b64encode(encrypted1))

    key2=renz.renz_get_pbkdf2_key()
    iv=bytes(range(16))
    inner2=iv+AES.new(key2,AES.MODE_CBC,iv).encrypt(pad(clear,16))
    add("7net","type2",base64.b64encode(legacy_encrypt(inner2,key2[:16])))

    key3=renz.renz_get_hkdf_key()
    inner3=iv+AES.new(key3,AES.MODE_CBC,iv).encrypt(pad(clear,16))
    add("osp","type3",base64.b64encode(inner3))
    if len(corpus) != 22:
        raise ValueError(f"Expected 16 outer + 2 nested + 4 typed; got {len(corpus)}")
    return {"schemaVersion":1,"suffixCount":16,"caseCount":len(corpus),"vectors":corpus}


def main():
    parser=argparse.ArgumentParser()
    options=parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--write",action="store_true")
    options.add_argument("--check",action="store_true")
    options.add_argument("--fixtures",type=Path)
    args=parser.parse_args()
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True, exist_ok=True)
        args.fixtures.write_text(json.dumps(make_fixtures(),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        print("[D] 16 RENZ/7NET suffixes and 22 Python reference vectors")
        return
    expected=generate()
    if args.write:
        OUT.parent.mkdir(parents=True,exist_ok=True)
        OUT.write_text(json.dumps(expected,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    else:
        if not OUT.is_file() or json.loads(OUT.read_text(encoding="utf-8")) != expected:
            raise SystemExit("Stale RENZ asset: python scripts/android_d_renz_profiles.py --write")
    print("[D] 16 RENZ aliases, 14 native profiles, source-matched")


if __name__=="__main__":
    main()

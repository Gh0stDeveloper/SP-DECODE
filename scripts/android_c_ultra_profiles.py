#!/usr/bin/env python3
"""Canonical Ultra/Sandok Android profiles and independent Python parity corpus.

Reads *only* the owner's existing decoders/Python/ultra.py and bot routing.
The 41 new suffixes are ported natively. The collided .ost legacy route is
deliberately excluded: it remains OstPort (future conditional support requires
a separately audited migration).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "android/app/src/main/assets/ultra_c_profiles.json"
PREFERRED_FALLBACK = (
    "greattunnel", "mmtunnel", "ultratunnel", "vlxtunnelvpn", "wolfcustom",
    "tiktunnelvpn", "beevpn", "txtunnel", "t20vpn", "luckyproxy",
    "auranetvpn", "velmoravpn", "mehafvpn", "deepvpn", "nurtunnel", "default",
)
INNER_FIELDS = (
    "BugDNS", "CustomProxy", "Payload", "SNI", "V2rayAddress", "V2rayConfig",
    "V2rayHost", "V2raySNI", "Info", "Host", "Server",
)


def generate() -> dict:
    from decoders.Python import ultra
    from spdecode.registry import DECODER_REGISTRY

    if set(ultra.ULTRA_CONFIGS) != set(ultra.VPNS_SD) | {
        "nurtunnel", "mehafvpn", "deepvpn", "default"
    }:
        raise ValueError("Unexpected Ultra/Sandok profile inventory")
    if len(ultra.ULTRA_EXTS) != 42 or len(ultra.EXT_TO_KEY) != 42:
        raise ValueError("Unexpected Ultra/Sandok source extensions")
    if ultra.EXT_TO_KEY[".ost"] != "default" or "ost" not in DECODER_REGISTRY:
        raise ValueError("Legacy .ost route changed")
    if DECODER_REGISTRY["ost"].script != "decoders/Python/ost.py":
        raise ValueError("The historical .ost route MUST remain legacy")
    if len(PREFERRED_FALLBACK) != 16 or len(INNER_FIELDS) != 11:
        raise ValueError("Source search/field shape changed")

    names = []
    for profile, config in sorted(ultra.ULTRA_CONFIGS.items()):
        p1 = config["password"]
        p2 = config["password2"]
        mem = config["mem"]
        if (not isinstance(p1, bytes) or not p1 or
                not isinstance(p2, bytes) or not p2 or mem not in {4096, 8192, 16384}):
            raise ValueError(f"Unsupported Argon2id parameters in {profile}")
        names.append({
            "key": profile,
            "name": config["name"],
            "memoryKiB": mem,
            "password": base64.b64encode(p1).decode("ascii"),
            "password2": base64.b64encode(p2).decode("ascii"),
        })

    aliases = []
    for extension in sorted(ultra.ULTRA_EXTS):
        suffix = extension.removeprefix(".")
        spec = DECODER_REGISTRY[suffix]
        if suffix == "ost":
            continue
        if spec.script != "decoders/Python/ultra.py" or spec.name != ultra.ULTRA_NAMES[extension]:
            raise ValueError(f"Unsupported/colliding Ultra route: {extension}")
        assigned = ultra.EXT_TO_KEY[extension]
        if assigned not in ultra.ULTRA_CONFIGS:
            raise ValueError(f"Alias with no Ultra profile: {extension}")
        aliases.append({"suffix": suffix, "name": ultra.ULTRA_NAMES[extension],
                        "profile": assigned})
    if len(aliases) != 41 or len(names) != 19:
        raise ValueError(f"Ultra source drift: aliases={len(aliases)} profiles={len(names)}")
    return {
        "schemaVersion": 1,
        "source": "decoders.Python.ultra",
        "algorithm": "argon2id-v19-aes256gcm",
        "suffixCount": 41,
        "profileCount": 19,
        "legacyOstIsolated": True,
        "argonIterations": 3,
        "argonLanes": 1,
        "argonKeyBytes": 32,
        "fallbackProfiles": list(PREFERRED_FALLBACK),
        "encryptedFields": list(INNER_FIELDS),
        "profiles": names,
        "aliases": aliases,
    }


def make_fixtures() -> dict:
    from Crypto.Cipher import AES
    from argon2.low_level import Type, hash_secret_raw
    from decoders.Python import ultra

    manifest = generate()
    cases = []

    def encrypt(plaintext: bytes, password: bytes, mem: int, seed: str, *,
                aad: bool) -> bytes:
        salt = hashlib.sha256(("c-salt:" + seed).encode()).digest()[:16]
        nonce = hashlib.sha256(("c-nonce:" + seed).encode()).digest()[:12]
        key = hash_secret_raw(password, salt, time_cost=3, memory_cost=mem,
                              parallelism=1, hash_len=32, type=Type.ID)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(salt)
        encrypted, tag = cipher.encrypt_and_digest(plaintext)
        return salt + nonce + encrypted + tag

    for alias in manifest["aliases"]:
        extension = "." + alias["suffix"]
        p = ultra.ULTRA_CONFIGS[alias["profile"]]
        for mode in ("aad", "no_aad"):
            seed = extension + "-" + mode
            doc = {"Server": alias["suffix"] + ".example.invalid",
                   "Enabled": False, "Port": 443,
                   "Notes": "Prueba 日本語", "Empty": "",
                   "List": ["a", {"key": 0}], "metadata": {"retain": True}}
            if mode == "aad" and alias["suffix"] in {"ultra", "mmt", "t20", "flynet"}:
                # Exercise all 11 fields for 4096/8192/16384 KiB profiles.
                # Avoid 41 x 11 redundant Argon2 derivations in mobile CI.
                # Verify every inner-field name using authenticated ciphertext,
                # including the case where the nested tag has been corrupted.
                for j, field in enumerate(INNER_FIELDS):
                    inner = encrypt(("value-" + field).encode(), p["password2"],
                                    p["mem"], seed + "-" + field, aad=False)
                    doc[field] = base64.b64encode(inner).decode()
                failed = bytearray(encrypt(b"should remain encrypted", p["password2"],
                                           p["mem"], seed + "-bad-tag", aad=False))
                failed[-1] ^= 1
                doc["Server"] = base64.b64encode(failed).decode()
            plain = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode()
            sealed = encrypt(plain, p["password"], p["mem"], seed, aad=mode == "aad")
            link = ("ultra://" if mode == "aad" else "") + base64.b64encode(sealed).decode()
            expected = ultra.run(link.encode(), extension)
            if expected is None:
                raise ValueError("Python reference failed: " + seed)
            parsed = json.loads(expected)
            if parsed["config"]["_vpn_key"] != alias["profile"]:
                raise ValueError("Python profile selection drift: " + seed)
            if mode == "aad" and alias["suffix"] in {"ultra", "mmt", "t20", "flynet"}:
                for field in INNER_FIELDS:
                    if field != "Server" and parsed["config"][field] != "value-" + field:
                        raise ValueError("Nested field mismatch in " + seed + "/" + field)
                if parsed["config"]["Server"] != doc["Server"]:
                    raise ValueError("Nested authentication failure not preserved")
            cases.append({
                "suffix": alias["suffix"], "mode": mode, "profile": alias["profile"],
                "encodedInput": base64.b64encode(link.encode()).decode(),
                "expected": expected,
            })

    # Reference parity for multi-key fallback beyond the associated alias.
    cross = ultra.ULTRA_CONFIGS["greattunnel"]
    plain = json.dumps({"Host": "alternate-profile.invalid", "Enabled": False},
                       separators=(",", ":")).encode()
    unexpected = encrypt(plain, cross["password"], cross["mem"], "fallback-ultra", aad=True)
    link = base64.b64encode(unexpected)
    expected = ultra.run(link, ".ultra")
    if not expected or json.loads(expected)["config"]["_vpn_key"] != "greattunnel":
        raise ValueError("Python fallback changed")
    cases.append({"suffix": "ultra", "mode": "fallback",
                  "profile": "greattunnel",
                  "encodedInput": base64.b64encode(link).decode(),
                  "expected": expected})

    if len(cases) != 83:
        raise ValueError("Incomplete Ultra positive corpus")
    return {"schemaVersion": 1, "suffixCount": 41, "caseCount": 83,
            "aadVectors": 41, "noAadVectors": 41, "fallbackVectors": 1,
            "vectors": cases}


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--fixtures", type=Path)
    args = parser.parse_args()
    if args.fixtures:
        target = args.fixtures
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(make_fixtures(), indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
        print("[C] 41 Ultra/Sandok formats; 83 Python reference vectors generated")
    else:
        content = json.dumps(generate(), indent=2, ensure_ascii=False) + "\n"
        if args.write:
            OUT.parent.mkdir(parents=True, exist_ok=True)
            OUT.write_text(content, encoding="utf-8")
        elif not OUT.is_file() or OUT.read_text("utf-8") != content:
            raise SystemExit("Ultra profiles stale: python scripts/android_c_ultra_profiles.py --write")
        print("[C] 41 Ultra/Sandok native profiles verified; .ost legacy preserved")


if __name__ == "__main__":
    main()

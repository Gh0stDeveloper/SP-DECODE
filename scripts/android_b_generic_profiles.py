#!/usr/bin/env python3
"""Reproducible Phase B native profiles and synthetic Python reference vectors.

Source of truth: decoders/Python/generic_profiles.py + spdecode.registry.
The Android runtime asset includes only the 81 selected historical keys.
Keys are historical recovery constants already public in the Python project;
Base64 encoding is representation, NOT secrecy or key protection.

Usage:
  python scripts/android_b_generic_profiles.py --check
  python scripts/android_b_generic_profiles.py --write
  python scripts/android_b_generic_profiles.py --fixtures OUTPUT.json
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

PROFILE_ASSET = ROOT / "android/app/src/main/assets/generic_b_profiles.json"
EXPECTED_EXTENSIONS = 81
EXPECTED_AES = 74
EXPECTED_DES = 13
EXPECTED_DUAL = 6


def generate() -> dict:
    from decoders.Python.generic_profiles import AES_PROFILES, DES_PROFILES
    from spdecode.registry import DECODER_REGISTRY

    entries: list[dict] = []
    for suffix, spec in sorted(DECODER_REGISTRY.items()):
        if spec.script not in {
            "decoders/Python/generic_aes.py",
            "decoders/Python/generic_des.py",
        }:
            continue
        ext = "." + suffix
        aes_keys = AES_PROFILES.get(ext, ())
        des_key = DES_PROFILES.get(ext)
        if not aes_keys and not des_key:
            raise ValueError(f"Missing generic encryption profile for {ext}")
        if (des_key is not None) != (spec.script.endswith("generic_des.py")):
            raise ValueError(f"DES routing drift for {ext}")
        if not all(isinstance(key, bytes) and key for key in aes_keys):
            raise ValueError(f"Invalid AES key list for {ext}")
        if des_key is not None and not isinstance(des_key, bytes):
            raise ValueError(f"Invalid DES key for {ext}")
        entries.append({
            "suffix": suffix,
            "aesKeys": [base64.b64encode(key).decode("ascii") for key in aes_keys],
            "desKey": base64.b64encode(des_key).decode("ascii") if des_key else None,
        })
    aes_count = sum(bool(row["aesKeys"]) for row in entries)
    des_count = sum(row["desKey"] is not None for row in entries)
    both = sum(bool(row["aesKeys"]) and row["desKey"] is not None for row in entries)
    if (len(entries), aes_count, des_count, both) != (
        EXPECTED_EXTENSIONS, EXPECTED_AES, EXPECTED_DES, EXPECTED_DUAL
    ):
        raise ValueError(f"Generic source drift: {len(entries)}, {aes_count}, {des_count}, {both}")
    return {
        "schemaVersion": 1,
        "formatCount": EXPECTED_EXTENSIONS,
        "aesProfileCount": EXPECTED_AES,
        "desProfileCount": EXPECTED_DES,
        "dualProfileCount": EXPECTED_DUAL,
        "source": "decoders.Python.generic_profiles",
        "profiles": entries,
    }


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def generate_fixtures() -> dict:
    from Crypto.Cipher import AES, DES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2
    from decoders.Python.generic_profiles import AES_PROFILES, DES_PROFILES
    from decoders.Python.generic_aes import run as python_aes
    from decoders.Python.generic_des import run as python_des

    profiles = generate()["profiles"]
    samples = []
    for row in profiles:
        suffix = row["suffix"]
        extension = "." + suffix
        info = {
            "extension": extension,
            "host": f"{suffix}.phase-b.invalid",
            "port": 443,
            "sshUser": "ghost",
            "sshPass": "synthetic-test-only",
            "enabled": False,
            "metadata": {"unicode": "Prueba 日本語", "newline": "one\ntwo"},
        }
        if row["aesKeys"]:
            plain = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
            salt = hashlib.sha256(("phase-b/salt/" + suffix).encode()).digest()[:16]
            nonce = hashlib.sha256(("phase-b/nonce/" + suffix).encode()).digest()[:12]
            for index, password in enumerate(AES_PROFILES[extension]):
                key = PBKDF2(password, salt, dkLen=16, count=1000, hmac_hash_module=SHA256)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                encrypted, tag = cipher.encrypt_and_digest(plain.encode("utf-8"))
                packet = b".".join(base64.b64encode(piece) for piece in (salt, nonce, encrypted + tag))
                expected = python_des(packet, extension) if row["desKey"] else python_aes(packet, extension)
                if expected is None or json.loads(expected) != info:
                    raise ValueError(f"Reference AES failure: {extension}, password {index}")
                samples.append({
                    "suffix": suffix, "engine": "aes", "passwordIndex": index,
                    "inputBase64": base64.b64encode(packet).decode("ascii"),
                    "expected": expected,
                })
        if row["desKey"]:
            xml = (
                f'<entry key="Host">{suffix}.phase-b.invalid</entry>\n'
                '<entry key="User">ghost</entry>\n'
                '<entry key="Password">synthetic-test-only</entry>\n'
                '<entry key="Empty"/>\n'
                '<entry key="Host">duplicate-value</entry>'
            )
            password = DES_PROFILES[extension]
            key = password[:8].ljust(8, b"\0")
            plain = xml.encode("utf-8")
            plain += b" " * (-len(plain) % 8)
            encrypted = DES.new(key, DES.MODE_ECB).encrypt(plain)
            for wrapping in ("raw", "base64"):
                packet = base64.b64encode(encrypted) if wrapping == "base64" else encrypted
                expected = python_des(packet, extension)
                if expected is None:
                    raise ValueError(f"Reference DES failure: {extension}, variant {wrapping}")
                parsed = json.loads(expected)
                if len(parsed.get("entries", [])) != 5 or parsed["entries"][-1]["value"] != "duplicate-value":
                    raise ValueError(f"Incomplete reference DES extraction: {extension}")
                samples.append({
                    "suffix": suffix, "engine": "des", "wrapping": wrapping,
                    "inputBase64": base64.b64encode(packet).decode("ascii"),
                    "expected": expected,
                })
    counts = {
        "aesVectors": sum(s["engine"] == "aes" for s in samples),
        "desVectors": sum(s["engine"] == "des" for s in samples),
    }
    if counts["aesVectors"] < EXPECTED_AES or counts["desVectors"] != 2 * EXPECTED_DES:
        raise ValueError(f"Incomplete synthetic corpus: {counts}")
    return {"schemaVersion": 1, "source": "Python generic AES/DES encryption",
            "profileCount": len(profiles), **counts, "vectors": samples}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--write", action="store_true")
    action.add_argument("--fixtures", metavar="FILE", type=Path)
    args = parser.parse_args()
    if args.fixtures is not None:
        target = args.fixtures
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_canonical(generate_fixtures()), encoding="utf-8")
        print(f"[B] Generated 81-profile Python reference corpus: {target}")
        return
    content = _canonical(generate())
    if args.write:
        PROFILE_ASSET.parent.mkdir(parents=True, exist_ok=True)
        PROFILE_ASSET.write_text(content, encoding="utf-8")
    elif not PROFILE_ASSET.is_file() or PROFILE_ASSET.read_text("utf-8") != content:
        raise SystemExit("Phase B profiles asset stale: python scripts/android_b_generic_profiles.py --write")
    print("[B] 81 native generic profiles (74 AES, 13 DES, 6 dual), source-exact")


if __name__ == "__main__":
    main()

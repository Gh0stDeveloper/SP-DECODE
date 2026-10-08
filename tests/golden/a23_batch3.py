"""A.2.3 batch 3: ten synthetic file suffixes, no real credentials.

The six MultiDES suffixes exercise distinct *registry filename routes* using the
shared first DES key. They are not vendor-specific export compatibility tests.
SKSRV two suffixes share one authenticated AES-GCM container. XSCKS and ARO
are CLI decoders; avoid importing their modules because they execute at import.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[2]
DES_SUFFIXES = ("agn", "cly", "fɴ", "jvc", "jvi", "v2i")
SKSRV_SUFFIXES = ("sksrv", "sksrv.png")
BATCH3_SUFFIXES = DES_SUFFIXES + SKSRV_SUFFIXES + ("xscks", "aro")
SOURCE_SCRIPTS = {
    **{suffix: "decoders/Python/multides.py" for suffix in DES_SUFFIXES},
    **{suffix: "decoders/Python/sksrv.py" for suffix in SKSRV_SUFFIXES},
    "xscks": "decoders/Python/xscks.py",
    "aro": "decoders/Python/aro.py",
}


def des_xml_bytes(suffix: str) -> bytes:
    """Forward-encrypt two dummy properties with shared first-key DES-ECB.

    The stock script iterates all DES keys, rather than dispatching keys by
    suffix. This golden proves common first-key decoding and suffix routing,
    NOT distinct .agn/.jvc vendor export key variants.
    """
    if suffix not in DES_SUFFIXES:
        raise ValueError("not a MultiDES registry suffix")
    text = (
        '<entry key="Host">example.org</entry>\n'
        '<entry key="Port">443</entry>'
    ).encode("utf-8")
    text += b" " * ((-len(text)) % 8)  # legacy decoder does not remove padding
    return DES.new(b"cinbdf66", DES.MODE_ECB).encrypt(text)


def sksrv_xml_bytes(suffix: str) -> bytes:
    """PBKDF2-SHA256 and AES-GCM with fixed PUBLIC salt/nonce; dummy XML only."""
    if suffix not in SKSRV_SUFFIXES:
        raise ValueError("not an SKSRV registry suffix")
    text = (
        '<properties>\n'
        '<entry key="Host">example.org</entry>\n'
        '<entry key="Port">443</entry>\n'
        '</properties>'
    ).encode("utf-8")
    # Read the existing decoder's static key from a Python literal, without
    # importing or running the CLI module; no secret printed to test reports.
    source = ast.parse((ROOT / "decoders/Python/sksrv.py").read_text(encoding="utf-8"))
    key = next(
        n.value.value for n in source.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == "DECRYPTION_KEY"
        and isinstance(n.value, ast.Constant)
    )
    salt = b"public-synthetic-salt-23"
    nonce = b"test-nonce-12"  # fixed for deterministic fixtures; never use in production
    dk = PBKDF2(key.encode("utf-8"), salt, hmac_hash_module=SHA256)
    ciphertext, tag = AES.new(dk, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(text)
    return (
        base64.b64encode(salt) + b"." + base64.b64encode(nonce) + b"."
        + base64.b64encode(ciphertext + tag)
    )


def xscks_json_bytes() -> bytes:
    """AES-CBC test input; password comes from script AST, not a live account."""
    mod = ast.parse((ROOT / "decoders/Python/xscks.py").read_text(encoding="utf-8"))
    encoded = next(
        n.value.value for n in mod.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == "CHICO_CP"
        and isinstance(n.value, ast.Constant)
    )
    original_password = base64.b64decode(encoded).decode("utf-8")
    key = hashlib.sha256(original_password.encode("utf-8")).digest()
    clear = json.dumps(
        {"Server": "example.org", "Port": 443},
        separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return base64.b64encode(
        AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(clear, 16))
    )


def aro_json_bytes() -> bytes:
    """Inverse of the repo's byte+18/Base64 envelope (no external app needed)."""
    clear = json.dumps(
        {"CONFIG": {"Server": "example.org", "Port": "443"}},
        separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return base64.b64encode(bytes((x - 18) % 256 for x in clear))


BATCH3_GENERATORS = {
    **{f"multides-{s}": (lambda suffix=s: des_xml_bytes(suffix)) for s in DES_SUFFIXES},
    **{f"sksrv-{s.replace('.', '-')}": (
        lambda suffix=s: sksrv_xml_bytes(suffix)
    ) for s in SKSRV_SUFFIXES},
    "xscks-aescbc": xscks_json_bytes,
    "aro-minus18": aro_json_bytes,
}

BATCH3_CASE_SUFFIXES = {
    **{f"multides-{s}": s for s in DES_SUFFIXES},
    **{f"sksrv-{s.replace('.', '-')}": s for s in SKSRV_SUFFIXES},
    "xscks-aescbc": "xscks",
    "aro-minus18": "aro",
}

"""A.2.3 batch 5 — ten source-backed, offline synthetic profiles.

All endpoint names are from RFC 2606 domains; no real customer exports.
The old REZ cipher has no standalone reference: its own unused encrypt
function runs in a restricted JS sandbox. This is self-roundtrip evidence,
NOT independent vendor/exporter compatibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

from decoders.Python._noobcrypt import KEYS

ROOT = Path(__file__).resolve().parents[2]
SUFFIXES = ("jez", "hrt", "rez", "rezl", "maya", "xui", "mrc", "mtl", "mina", "tnl")
SCRIPTS = {
    "jez": "decoders/PHP/jez.php",
    "hrt": "decoders/PHP/hrt.php",
    "rez": "decoders/JavaScript/rez.js",
    "rezl": "decoders/JavaScript/rez.js",
    "maya": "decoders/Python/maya.py",
    "xui": "decoders/Python/xui.py",
    "mrc": "decoders/Python/mrc.py",
    "mtl": "decoders/Python/mtl.py",
    "mina": "decoders/Python/mina.py",
    "tnl": "decoders/Python/tnl.py",
}
RUNTIMES = {s: ("php" if s in ("jez", "hrt") else "node" if s in ("rez", "rezl") else "python") for s in SUFFIXES}
CASE_SUFFIXES = {"batch5-" + s: s for s in SUFFIXES}
DUMMY_XML = b'<entry key="Host">example.org</entry>\n<entry key="Port">443</entry>'
DUMMY_JSON = {"Host": "example.org", "Port": 443}


def php_radztunnel_bytes() -> bytes:
    clear = json.dumps(DUMMY_JSON, separators=(",", ":")).encode("utf-8")
    key = hashlib.sha256(b"Radz_11_2021").digest()
    return base64.b64encode(AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(clear, 16)))


def rez_tea_bytes() -> bytes:
    # Calls the historical primitive from the versioned source in a VM
    # without filesystem access inside the VM itself.
    return subprocess.check_output(
        ["node", str(ROOT / "tests/golden/a23_batch5_rez.cjs")],
        cwd=ROOT, timeout=10,
    )


def noobcrypt_bytes(variant: str) -> bytes:
    if variant not in ("maya", "xui"):
        raise ValueError("unknown NoobCrypt test variant")
    clear = json.dumps(
        {"Host": "example.org", "Port": 443, "Note": "A23 synthetic"},
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    iv = bytes(range(16))
    return base64.b64encode(
        iv + AES.new(KEYS[variant], AES.MODE_CBC, iv).encrypt(pad(clear, 16))
    )


def gcm_mrc_mtl_bytes() -> bytes:
    salt = b"a23-batch5-public-salt"
    nonce = b"a23-batch5nonce"
    key = PBKDF2("Ed\u0001".encode("utf-8"), salt, hmac_hash_module=SHA256)
    ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(DUMMY_XML)
    return b".".join(map(base64.b64encode, (salt, nonce, ciphertext + tag)))


def mina_bytes() -> bytes:
    # Script's password is an octal-encoded UTF-8 phrase (not a live token).
    password = bytes(int(x, 8) for x in "101 156 144 162 157 151 144 126".split())
    key = hashlib.sha256(password).digest()
    clear = json.dumps(DUMMY_JSON, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad(clear, 16)))


def tnl_bytes() -> bytes:
    # Original tnl.py's first registered password; no production secrets.
    from decoders.Python.tnl import PASSWORDS
    salt, nonce = b"a23-batch5-tnl-salt", b"batch5-tnl-nonce"
    key = PBKDF2(PASSWORDS[".tnl"][0], salt, hmac_hash_module=SHA256)
    ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(DUMMY_XML)
    return b".".join(map(base64.b64encode, (salt, nonce, ciphertext + tag)))


GENERATORS = {
    "batch5-jez": php_radztunnel_bytes,
    "batch5-hrt": php_radztunnel_bytes,
    "batch5-rez": rez_tea_bytes,
    "batch5-rezl": rez_tea_bytes,
    "batch5-maya": lambda: noobcrypt_bytes("maya"),
    "batch5-xui": lambda: noobcrypt_bytes("xui"),
    "batch5-mrc": gcm_mrc_mtl_bytes,
    "batch5-mtl": gcm_mrc_mtl_bytes,
    "batch5-mina": mina_bytes,
    "batch5-tnl": tnl_bytes,
}

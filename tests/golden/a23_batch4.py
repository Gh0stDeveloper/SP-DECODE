"""A.2.3 batch 4 — ten *synthetic* input files, 3 runtimes.

Fixture generators implement the reverse envelope of the audited decoders.
Fixed salts/nonces/IVs are test-only and must NEVER be reused for production
encryption. Source-provided historical decoder keys remain in decoder files;
this helper does not write or log key material.

Passing proves Linux CLI semantics for known artificial envelopes, not a
vendor-produced current file, an Android integration or independent engines.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
from pathlib import Path

from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[2]
BATCH4_SUFFIXES = (
    "hat", "sks", "sksplus", "cloudy", "mij",
    "fnnetwork", "uwu", "phc", "ost", "sbr",
)
BATCH4_SCRIPTS = {
    "hat": "decoders/JavaScript/hat.js",
    "sks": "decoders/JavaScript/sks.js",
    "sksplus": "decoders/PHP/sksplus.php",
    "cloudy": "decoders/Python/cloudy.py",
    "mij": "decoders/Python/mij.py",
    "fnnetwork": "decoders/Python/fnnetwork.py",
    "uwu": "decoders/Python/uwu.py",
    "phc": "decoders/Python/phc.py",
    "ost": "decoders/Python/ost.py",
    "sbr": "decoders/Python/sbr.py",
}
BATCH4_CASE_SUFFIXES = {f"batch4-{suffix}": suffix for suffix in BATCH4_SUFFIXES}
BATCH4_CLI_RUNTIMES = {
    f"batch4-{suffix}": "node" if suffix in ("hat", "sks")
    else "php" if suffix == "sksplus" else "python"
    for suffix in BATCH4_SUFFIXES
}
DUMMY_XML = (
    '<entry key="Host">example.org</entry>\n'
    '<entry key="Port">443</entry>'
).encode("utf-8")
DUMMY_JSON = {"Host": "example.org", "Port": 443}


def _literal(path: str, variable: str):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"), filename=path)
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if any(isinstance(t, ast.Name) and t.id == variable for t in targets):
                return ast.literal_eval(statement.value)
    raise ValueError(f"missing audited literal {variable} in {path}")


def _gcm_xml(password: str, suffix: str) -> bytes:
    # Fixed test data only: deterministic SHA-256 digests, no live accounts.
    salt = b"a23-b4-synthetic-salt"
    nonce = b"a23-b4-nonce"
    key = PBKDF2(password.encode("utf-8"), salt, hmac_hash_module=SHA256)
    crypt, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(DUMMY_XML)
    return b".".join(map(base64.b64encode, (salt, nonce, crypt + tag)))


def hat_bytes() -> bytes:
    source = (ROOT / BATCH4_SCRIPTS["hat"]).read_text(encoding="utf-8")
    match = re.search(r"const key = Buffer\.from\('([^']+)', 'base64'\)", source)
    if not match:
        raise ValueError("HAT historical key declaration no longer matches")
    key = base64.b64decode(match.group(1), validate=True)
    clear = json.dumps(
        {"meta": {"meta_vendor_msg": "A23 synthetic"}},
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(pad(clear, 16)))


def sks_bytes() -> bytes:
    source = (ROOT / BATCH4_SCRIPTS["sks"]).read_text(encoding="utf-8")
    header = source.split("const configKeys = [", 1)[1].split("];", 1)[0]
    candidates = re.findall(r'"([^"]+)"', header)
    if len(candidates) < 2:
        raise ValueError("SKS password source changed")
    version = "A23"
    key_hex = hashlib.md5((candidates[1] + " " + version).encode("utf-8")).hexdigest()
    iv = bytes(range(16))
    clear = json.dumps(
        {"sshServer": "example.org", "sshPort": 443,
         "profileSshAuth": {"sshUser": "dummy-user"},
         "configProtect": {"blockRoot": True}},
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    encrypted = AES.new(key_hex.encode("ascii"), AES.MODE_CBC, iv).encrypt(pad(clear, 16))
    return json.dumps(
        {"v": version, "d": base64.b64encode(encrypted).decode("ascii") + "."
         + base64.b64encode(iv).decode("ascii")},
        ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def sksplus_bytes() -> bytes:
    source = (ROOT / BATCH4_SCRIPTS["sksplus"]).read_text(encoding="utf-8")
    match = re.search(r'hex2bin\("([0-9a-fA-F]+)"\)', source)
    if not match:
        raise ValueError("PHP SKSPlus historical key declaration changed")
    key = bytes.fromhex(match.group(1))
    iv = bytes(range(16))
    clear = json.dumps(DUMMY_JSON, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(clear, 16))
    # PHP source maps signed integers back to unsigned bytes.
    to_signed = lambda value: value if value < 128 else value - 256
    return json.dumps(
        {"payload": {"iv": [to_signed(x) for x in iv],
                     "encoded": [to_signed(x) for x in encrypted]}},
        separators=(",", ":")
    ).encode("utf-8")


def cloudy_bytes() -> bytes:
    script = BATCH4_SCRIPTS["cloudy"]
    key = base64.b64decode(_literal(script, "key_base64"))
    iv = base64.b64decode(_literal(script, "iv_base64"))
    clear = json.dumps(DUMMY_JSON, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(clear, 16)))


def mij_bytes() -> bytes:
    return _gcm_xml(_literal(BATCH4_SCRIPTS["mij"], "DECRYPTION_KEY"), "mij")


def fnnetwork_bytes() -> bytes:
    return _gcm_xml(_literal(BATCH4_SCRIPTS["fnnetwork"], "DECRYPTION_KEY"), "fnnetwork")


def uwu_bytes() -> bytes:
    return _gcm_xml(_literal(BATCH4_SCRIPTS["uwu"], "key_password"), "uwu")


def phc_bytes() -> bytes:
    encoded = _literal(BATCH4_SCRIPTS["phc"], "dd_ssff")
    return _gcm_xml(bytes.fromhex(encoded).decode("utf-8"), "phc")


def ost_bytes() -> bytes:
    source = (ROOT / BATCH4_SCRIPTS["ost"]).read_text(encoding="utf-8")
    match = re.search(r"'\.ost': base64\.b64decode\(b'([^']+)'\)", source)
    if not match:
        raise ValueError("OST key source changed")
    key = base64.b64decode(match.group(1))
    clear = DUMMY_XML + b" " * ((-len(DUMMY_XML)) % 8)
    return DES.new(key, DES.MODE_ECB).encrypt(clear)


def sbr_bytes() -> bytes:
    source = (ROOT / BATCH4_SCRIPTS["sbr"]).read_text(encoding="utf-8")
    match = re.search(r"'\.sbr': b'([^']+)'", source)
    if not match:
        raise ValueError("SBR key source changed")
    key = match.group(1).encode("ascii")
    clear = DUMMY_XML + b" " * ((-len(DUMMY_XML)) % 8)
    return DES.new(key, DES.MODE_ECB).encrypt(clear)


BATCH4_GENERATORS = {
    "batch4-hat": hat_bytes,
    "batch4-sks": sks_bytes,
    "batch4-sksplus": sksplus_bytes,
    "batch4-cloudy": cloudy_bytes,
    "batch4-mij": mij_bytes,
    "batch4-fnnetwork": fnnetwork_bytes,
    "batch4-uwu": uwu_bytes,
    "batch4-phc": phc_bytes,
    "batch4-ost": ost_bytes,
    "batch4-sbr": sbr_bytes,
}

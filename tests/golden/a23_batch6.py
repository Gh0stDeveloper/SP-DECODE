"""A.2.3 batch 6: ten deterministic OFFLINE synthetic configuration envelopes.

No files produced by third-party apps; no real credentials. The historical
REZ/STK-family TEA encrypt is reused via Node to generate the matching legacy
envelope, and the coverage report marks that roundtrip as non-independent.
Test-only IV/nonce values MUST NOT be used for actual encryption.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[2]
SUFFIXES = ("nm", "pb", "pcx", "nt", "ziv", "vpnlite", "sip", "at", "ipt", "stk")
SCRIPTS = {
    "nm": "decoders/Python/nms.py",
    "pb": "decoders/Python/pb.py",
    "pcx": "decoders/Python/pcx.py",
    "nt": "decoders/Python/nt.py",
    "ziv": "decoders/Python/ziv.py",
    "vpnlite": "decoders/Python/vpnlite.py",
    "sip": "decoders/Python/sockip.py",
    "at": "decoders/Python/at.py",
    "ipt": "decoders/Python/ipt.py",
    "stk": "decoders/JavaScript/stk.js",
}
CASE_SUFFIXES = {"batch6-" + s: s for s in SUFFIXES}
DUMMY_XML = b'<entry key="sshServer">example.org</entry>\n<entry key="sshPort">443</entry>'
GCM_SALT = b"b6-synthetic-salt"
GCM_NONCE = b"batch6-nonce"


def _literal(script: str, variable: str):
    code = (ROOT / script).read_text(encoding="utf-8")
    tree = ast.parse(code, filename=script)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == variable for t in node.targets):
                return ast.literal_eval(node.value)
    raise ValueError(f"Audited literal changed: {script}/{variable}")


def gcm_file(suffix: str) -> bytes:
    script = SCRIPTS[suffix]
    pw = _literal(script, "PASSWORDS")["." + suffix]
    if isinstance(pw, list):
        pw = pw[0]
    key = PBKDF2(pw, GCM_SALT, hmac_hash_module=SHA256)
    c, tag = AES.new(key, AES.MODE_GCM, nonce=GCM_NONCE).encrypt_and_digest(DUMMY_XML)
    return b".".join(base64.b64encode(x) for x in (GCM_SALT, GCM_NONCE, c + tag))


def nm_file() -> bytes:
    password = _literal(SCRIPTS["nm"], "PASSWORDS")[".nm"][0]
    data = json.dumps({"Server": "example.org", "Port": 443}, separators=(",", ":")).encode()
    return base64.b64encode(AES.new(password, AES.MODE_ECB).encrypt(pad(data, 16)))


def vpnlite_file() -> bytes:
    source = (ROOT / SCRIPTS["vpnlite"]).read_text(encoding="utf-8")
    match = re.search(r'^\s*key\s*=\s*("[^"]+")', source, re.M)
    if not match:
        raise ValueError("VPN Lite password source no longer matches")
    key = hashlib.sha256(ast.literal_eval(match.group(1)).encode()).digest()
    iv = bytes(range(16))
    data = b'{"Host":"example.org","Port":"443"}'
    return base64.b64encode(iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16)))


def sip_file() -> bytes:
    """Minimal Java Object Serialization with one String field; no pickle or Java VM."""
    def utfs(s: str) -> bytes:
        data = s.encode("utf-8")
        return struct.pack(">H", len(data)) + data
    # AC ED 00 05 TC_OBJECT TC_CLASSDESC, one object field (server).
    data = bytearray(bytes.fromhex("aced00057372"))
    data += utfs("SyntheticProfile")
    data += b"\x00" * 8              # serialVersionUID
    data += b"\x02\x00\x01"        # SC_SERIALIZABLE, fieldCount = 1
    data += b"L" + utfs("server")  # object field
    data += b"\x74" + utfs("Ljava/lang/String;")
    data += b"\x78\x70"            # end class annotation; super=null
    data += b"\x74" + utfs("example.org")
    # Original outer AES-ECB envelope from the audited source.
    from decoders.Python.sockip import SIP_AES_KEY
    return base64.b64encode(
        AES.new(SIP_AES_KEY, AES.MODE_ECB).encrypt(pad(bytes(data), 16))
    )


def at_file() -> bytes:
    from decoders.Python.at import STATIC
    seed = b"synthetic-seed16"
    n1, n2 = b"batch6nonce1", b"batch6nonce2"
    clear = json.dumps({"Server": "example.org", "Port": 443}, separators=(",", ":")).encode()
    c2, tag2 = AES.new(seed, AES.MODE_GCM, nonce=n2).encrypt_and_digest(clear)
    c1, tag1 = AES.new(seed + STATIC, AES.MODE_GCM, nonce=n1).encrypt_and_digest(n2 + c2 + tag2)
    return (seed + n1 + c1 + tag1).hex().encode("ascii")


def _legacy_tea_file(plaintext: str, password: str) -> bytes:
    """Exercise the historical *source* encrypt function, like batch 5 REZ.

    This is a deterministic self-roundtrip, not a cross-implementation vector.
    """
    path = ROOT / SCRIPTS["stk"]
    runner = r"""
const fs=require('fs'),vm=require('vm');
const code=fs.readFileSync(process.argv[1],'utf8').split('var decryptedData = Tea.decrypt')[0];
const ctx={require,Buffer,console,process:{argv:['node','stk.js','test.stk']}};
vm.runInNewContext(code,ctx,{timeout:8000});
process.stdout.write(ctx.Tea.encrypt(process.argv[2],process.argv[3]));
"""
    run = subprocess.run(
        ["node", "-e", runner, str(path), plaintext, password],
        cwd=ROOT, capture_output=True, check=True, timeout=12
    )
    return run.stdout


def ipt_file() -> bytes:
    password = _literal(SCRIPTS["ipt"], "ipt")  # base64-encoded in source
    decoded_password = base64.b64decode(password).decode("utf-8")
    data = json.dumps({"Server": "example.org", "Port": 443}, separators=(",", ":"))
    return _legacy_tea_file(data, decoded_password)


def stk_file() -> bytes:
    return _legacy_tea_file('{"server_port":443,"custom_host":"example.org"}', "Bgw34Nmk")


GENERATORS = {
    "batch6-nm": nm_file,
    "batch6-pb": lambda: gcm_file("pb"),
    "batch6-pcx": lambda: gcm_file("pcx"),
    "batch6-nt": lambda: gcm_file("nt"),
    "batch6-ziv": lambda: gcm_file("ziv"),
    "batch6-vpnlite": vpnlite_file,
    "batch6-sip": sip_file,
    "batch6-at": at_file,
    "batch6-ipt": ipt_file,
    "batch6-stk": stk_file,
}

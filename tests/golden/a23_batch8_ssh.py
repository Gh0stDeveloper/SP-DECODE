"""Final A.2.3 synthetic fixture: legacy SSH Injector Blowfish-CBC.

This fixture is NOT exported by any third-party application. It uses only
fake data at the reserved example.org domain and a fixed historical key
already shipped with this repository. No real usernames/passwords.
"""
from __future__ import annotations
import ast
import base64
from pathlib import Path
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = "decoders/Python/ssh.py"
CASE_ID = "batch8-ssh"
SUFFIX = "ssh"
GOLDEN_ENV = "SPDECODE_SSH_GOLDEN_TEST"
GOLDEN_VALUE = "1"
PAYLOAD = (
    '<entry key="Host">example.org</entry>\n'
    '<entry key="Port">443</entry>\n'
    '<entry key="Note">A23 synthetic offline SSH test</entry>\n'
).encode("utf-8")


def _audited_function_literals() -> tuple[bytes, bytes]:
    tree = ast.parse((ROOT / SCRIPT).read_text(encoding="utf-8"), filename=SCRIPT)
    method = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == "ssh_injector")
    local = {}
    for node in method.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ("key", "iv"):
                    local[target.id] = ast.literal_eval(node.value)
    if set(local) != {"key", "iv"}:
        raise ValueError("Audited SSH key or IV definition has changed")
    return local["key"], local["iv"]


def ssh_bytes() -> bytes:
    key, iv = _audited_function_literals()
    encrypted = Blowfish.new(key, Blowfish.MODE_CBC, iv).encrypt(
        pad(PAYLOAD, Blowfish.block_size)
    )
    return base64.b64encode(encrypted)


GENERATORS = {CASE_ID: ssh_bytes}
CASE_SUFFIXES = {CASE_ID: SUFFIX}

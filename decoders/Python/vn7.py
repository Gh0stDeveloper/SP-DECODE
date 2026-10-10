#!/usr/bin/env python3
"""SP-DECODE modular Python VPN configuration decoder extracted from authorized 66.py.

No Telegram handlers, no network calls, full configuration output and fail-closed CLI.
"""
from __future__ import annotations
import base64
import hashlib
import json
import logging
import re
import struct
import sys
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)
MAX_INPUT_BYTES = 2 * 1024 * 1024

VN7_KEYS = [b"SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5", b"fubvx788b46v"]
def decrypt_vn7_file(file_data: bytes) -> str:
    try:
        if isinstance(file_data, str):
            file_data = file_data.encode('utf-8')
        
        parts = file_data.split(b'.')
        decoded = [base64.b64decode(p) for p in parts]
        
        for key in VN7_KEYS:
            try:
                decryption_key = PBKDF2(key, decoded[0], hmac_hash_module=SHA256)
                cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=decoded[1])
                decrypted = cipher.decrypt_and_verify(decoded[2][:-16], decoded[2][-16:])
                return decrypted.decode('utf-8')
            except Exception:
                continue
        return None
    except Exception:
        return None
def run(data: bytes) -> str | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        return None
    decoded = decrypt_vn7_file(data)
    if not isinstance(decoded, str) or not decoded.strip():
        return None
    try:
        obj = json.loads(decoded)
        if isinstance(obj, (dict, list)):
            return json.dumps(obj, ensure_ascii=False, indent=2)
    except (ValueError, TypeError):
        pass
    return decoded

EXTENSIONS = (".vn7",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python vn7.py <configuration-file>", file=sys.stderr)
        return 2
    filename = Path(args[0])
    if filename.suffix.lower() not in EXTENSIONS:
        print("Unsupported vn7 extension", file=sys.stderr)
        return 2
    try:
        result = run(filename.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Cannot read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt vn7 configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

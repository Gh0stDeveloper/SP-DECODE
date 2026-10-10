#!/usr/bin/env python3
"""One standalone SP-DECODE bot file decoder sourced from authorized 66.py."""
from __future__ import annotations
import base64
import binascii
import gzip
import hashlib
import html
import json
import logging
import re
import string
import struct
import sys
from pathlib import Path
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger=logging.getLogger(__name__)

FTHP_KEYS = ["furious0982", "Version6"]
def decrypt_fthp_file(encrypted_data: bytes, password: str) -> str:
    try:
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        parts = [base64.b64decode(p) for p in encrypted_data.split(b'.')]
        key = PBKDF2(password.encode('utf-8'), parts[0], hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=parts[1])
        return cipher.decrypt_and_verify(parts[2][:-16], parts[2][-16:]).decode('utf-8', 'ignore')
    except Exception:
        return None

def decrypt_fthp_with_multiple_keys(encrypted_data: bytes) -> str:
    for key in FTHP_KEYS:
        result = decrypt_fthp_file(encrypted_data, key)
        if result:
            return result
    return None
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    content=data.decode("utf-8",errors="replace").strip().encode("utf-8")
    output=decrypt_fthp_with_multiple_keys(content)
    if not output:
        return None
    try:
        parsed=json.loads(output)
        return json.dumps(parsed,ensure_ascii=False,indent=2)
    except (ValueError,TypeError):
        return output

def main():
    if len(sys.argv)!=2:
        print("Usage: python fthp.py <config-file>",file=sys.stderr)
        return 2
    filename=Path(sys.argv[1])
    try:
        result=run(filename.read_bytes())
    except (OSError,ValueError) as exc:
        print(str(exc),file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decode configuration",file=sys.stderr)
        return 1
    print(result)
    return 0
if __name__=="__main__":
    raise SystemExit(main())

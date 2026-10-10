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


DELTA = -1704280
KEY = b"technore_008515\x00" 

def _java_int(v):
    v &= 0xFFFFFFFF
    return v - 2**32 if v >= 2**31 else v

def _f0(data, incl_len=False):
    n = (len(data) + 3) // 4
    res = [0] * (n + 1) if incl_len else [0] * n
    if incl_len:
        res[n] = len(data)
    for i, b in enumerate(data):
        res[i // 4] |= (b & 0xFF) << ((i & 3) * 8)
    return [_java_int(x) for x in res]

def _e0(arr, trim=False):
    if not arr:
        return b""
    total = len(arr) * 4
    if trim:
        orig = arr[-1]
        if orig < 0:
            orig += 2**32
        if not (total - 7 <= orig <= total - 4):
            return None
        total = orig
    out = bytearray(total)
    for i in range(total):
        v = arr[i // 4]
        if v < 0:
            v += 2**32
        out[i] = (v >> ((i & 3) * 8)) & 0xFF
    return bytes(out)

def _mx(z, y, s, p, e, k):
    z, y, s = _java_int(z), _java_int(y), _java_int(s)
    a = _java_int((s ^ y) + (k[(p & 3) ^ e] ^ z))
    b = _java_int(((z & 0xFFFFFFFF) >> 5) ^ ((y << 2) & 0xFFFFFFFF))
    c = _java_int(((y & 0xFFFFFFFF) >> 3) ^ ((z << 4) & 0xFFFFFFFF))
    return _java_int(a ^ _java_int(b + c))

def decrypt_zoba_file(file_data: bytes, key: bytes = KEY, delta: int = DELTA) -> str:
    """
    فك تشفير ملف .zoba (أو أي ملف يستخدم هذه الخوارزمية)
    """
    try:
        # إذا كانت البيانات مدخلة بصيغة Base64 (مثل الكود الأصلي)
        # لكن يمكن أن تكون مباشرة بدون Base64. سنحاول فك Base64 إذا فشل.
        try:
            blob = base64.b64decode(file_data)
        except:
            blob = file_data  # ليست Base64، نستخدمها كما هي

        if not blob:
            return None

        v = _f0(blob)
        k = _f0(key)
        n = len(v)
        if n < 2:
            return None

        rnd = (52 // n) + 6
        s = _java_int(rnd * delta)
        y = v[0]

        while s != 0:
            e = ((s & 0xFFFFFFFF) >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = _java_int(v[p] - _mx(z, y, s, p, e, k))
                y = v[p]
            z = v[n - 1]
            v[0] = _java_int(v[0] - _mx(z, y, s, 0, e, k))
            y = v[0]
            s = _java_int(s - delta)

        decrypted_bytes = _e0(v, trim=True)
        if decrypted_bytes is None:
            return None

        # محاولة فك التشفير كنص UTF-8
        return decrypted_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None
def run(data: bytes) -> str | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        return None
    decrypted = decrypt_zoba_file(data)
    if not isinstance(decrypted, str) or not decrypted.strip():
        return None
    try:
        result = json.loads(decrypted)
        if isinstance(result, (dict, list)):
            return json.dumps(result, ensure_ascii=False, indent=2)
    except (ValueError, TypeError):
        pass
    return decrypted if len(decrypted) > 3 and decrypted.isprintable() else None

EXTENSIONS = (".zoba",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python zoba.py <configuration-file>", file=sys.stderr)
        return 2
    filename = Path(args[0])
    if filename.suffix.lower() not in EXTENSIONS:
        print("Unsupported zoba extension", file=sys.stderr)
        return 2
    try:
        result = run(filename.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Cannot read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt zoba configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

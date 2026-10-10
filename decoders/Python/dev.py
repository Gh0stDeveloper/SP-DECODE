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

DEV_SKY_KEY = "demondevs"
DEV_AES_KEY = "❤️🧑‍💻Bøbõ⁰⁰!!"
def skycrypt_decrypt(data: bytes, key: bytes) -> bytes:
    DELTA = 0x9a7393b4
    
    def fix_key(k):
        if len(k) == 16:
            return k
        fixed = bytearray(16)
        copy_len = min(len(k), 16)
        fixed[:copy_len] = k[:copy_len]
        return bytes(fixed)
    
    def to_int_array(d, include_length):
        length = len(d) // 4 if len(d) % 4 == 0 else len(d) // 4 + 1
        if include_length:
            arr = [0] * (length + 1)
            arr[length] = len(d)
        else:
            arr = [0] * length
        for i in range(len(d)):
            arr[i >> 2] |= (d[i] & 0xFF) << ((i & 3) << 3)
        return arr
    
    def to_byte_array(arr, include_length):
        length = len(arr) * 4
        if include_length:
            i = arr[-1]
            i2 = length - 4
            if i < i2 - 3 or i > i2:
                return None
            length = i
        result = bytearray(length)
        for i in range(length):
            result[i] = (arr[i >> 2] >> ((i & 3) << 3)) & 0xFF
        return bytes(result)
    
    def mx(sum_val, y, z, p, e, k):
        z &= 0xFFFFFFFF
        y &= 0xFFFFFFFF
        return (((sum_val ^ y) + (k[(p & 3) ^ e] ^ z)) ^ (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))) & 0xFFFFFFFF
    
    if len(data) == 0:
        return data
    
    v = to_int_array(data, False)
    k = to_int_array(fix_key(key), False)
    length = len(v) - 1
    
    if length < 1:
        return data
    
    y = v[0]
    rounds = 52 // (length + 1) + 6
    sum_val = (rounds * DELTA) & 0xFFFFFFFF
    
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for p in range(length, 0, -1):
            z = v[p - 1]
            y = (v[p] - mx(sum_val, y, z, p, e, k)) & 0xFFFFFFFF
            v[p] = y
        z = v[length]
        y = (v[0] - mx(sum_val, y, z, 0, e, k)) & 0xFFFFFFFF
        v[0] = y
        sum_val = (sum_val - DELTA) & 0xFFFFFFFF
    
    return to_byte_array(v, True)

def decrypt_dev_file(file_data: bytes) -> dict:
    try:
        if isinstance(file_data, bytes):
            content = file_data.decode('utf-8', errors='ignore')
        else:
            content = file_data
        
        encrypted_bytes = base64.b64decode(content.strip())
        sky_key = DEV_SKY_KEY.encode('utf-8')
        decrypted_bytes = skycrypt_decrypt(encrypted_bytes, sky_key)
        
        if not decrypted_bytes:
            return None
        
        json_str = decrypted_bytes.decode('utf-8')
        payload = json.loads(json_str)
        
        FUCKYOU_CHARS = "           ​‌‍‎‏"
        
        def gen_string(s):
            try:
                length = len(s) // 2
                result = bytearray(length)
                for i in range(length):
                    i2 = i * 2
                    c1 = s[i2]
                    c2 = s[i2 + 1]
                    val = (FUCKYOU_CHARS.index(c1) * 16) + FUCKYOU_CHARS.index(c2)
                    result[i] = val & 0xFF
                return result.decode('utf-8')
            except (ValueError, IndexError):
                return s
        
        def decrypt_aes_value(password, encrypted_str):
            try:
                decoded = gen_string(encrypted_str)
                hex_pass = password.encode('utf-8').hex().upper()
                key = hashlib.sha256(hex_pass.encode('utf-8')).digest()
                encrypted = base64.b64decode(decoded)
                cipher = AES.new(key, AES.MODE_CBC, bytes([0] * 16))
                decrypted = cipher.decrypt(encrypted)
                padding = decrypted[-1]
                return decrypted[:-padding].decode('utf-8')
            except Exception:
                return encrypted_str
        
        result = {}
        for k, v in payload.items():
            if isinstance(v, str) and v:
                result[k] = decrypt_aes_value(DEV_AES_KEY, v)
            else:
                result[k] = v
        
        return result
    except Exception:
        return None
def run(data: bytes) -> str | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        return None
    config = decrypt_dev_file(data)
    return json.dumps(config, ensure_ascii=False, indent=2) if isinstance(config, dict) else None

EXTENSIONS = (".dev",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python dev.py <configuration-file>", file=sys.stderr)
        return 2
    filename = Path(args[0])
    if filename.suffix.lower() not in EXTENSIONS:
        print("Unsupported dev extension", file=sys.stderr)
        return 2
    try:
        result = run(filename.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Cannot read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt dev configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

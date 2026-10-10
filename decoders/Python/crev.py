#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot decoder, adapted from authorized 66.py.

No Telegram handlers, network access, or third-party requests are performed.
This engine is imported on demand by the bot's central extension registry.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import logging
import re
import struct
import zlib
from pathlib import Path
import sys
from typing import Any
from xml.etree import ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)
MAX_INPUT_BYTES = 2 * 1024 * 1024

DELTA_CREV = -1703701580

def crev_to_int_array(data, include_length):
    length = len(data)
    n = (length >> 2) + (0 if (length & 3) == 0 else 1)
    if include_length:
        int_arr = [0] * (n + 1)
        int_arr[n] = length
    else:
        int_arr = [0] * n
    for i in range(length):
        int_arr[i >> 2] |= (data[i] & 0xff) << ((i & 3) << 3)
    return int_arr


def crev_to_byte_array(int_arr, include_length):
    length = len(int_arr) << 2
    if include_length:
        i2 = int_arr[-1]
        i = length - 4
        if i2 >= length - 7:
            if i2 <= i:
                length = i2
            else:
                return None
        else:
            return None
    bArr = bytearray(length)
    for i in range(length):
        bArr[i] = (int_arr[i >> 2] >> ((i & 3) << 3)) & 0xff
    return bytes(bArr)


def crev_fix_key(key):
    if len(key) == 16:
        return key
    key2 = bytearray(16)
    key2[:min(len(key), 16)] = key[:min(len(key), 16)]
    return bytes(key2)


def crev_mx(sum_, y, z, p, e, k):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z))


def crev_xxtea_decrypt(data, key):
    if not data:
        return data
    v = crev_to_int_array(data, False)
    k = crev_to_int_array(crev_fix_key(key), False)
    n = len(v) - 1
    if n < 1:
        return b''
    rounds = 6 + 52 // (n + 1)
    sum_ = (rounds * DELTA_CREV) & 0xffffffff
    y = v[0]
    while sum_ != 0:
        e = (sum_ >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - crev_mx(sum_, y, z, p, e, k)) & 0xffffffff
            y = v[p]
        z = v[n]
        v[0] = (v[0] - crev_mx(sum_, y, z, 0, e, k)) & 0xffffffff
        y = v[0]
        sum_ = (sum_ - DELTA_CREV) & 0xffffffff
    return crev_to_byte_array(v, True)


def crev_decrypt_base64(b64_data, key):
    try:
        enc = base64.b64decode(b64_data)
        dec = crev_xxtea_decrypt(enc, key.encode('utf-8'))
        if dec is None:
            return None
        return dec.decode('utf-8', errors='ignore')
    except Exception:
        return None


def decrypt_crev_config(encrypted_data, key="DEV_CREEB"):
    """
    فك تشفير إعدادات CREV
    
    Args:
        encrypted_data (str): البيانات المشفرة بصيغة Base64
        key (str): مفتاح فك التشفير (افتراضي: DEV_CREEB)
    
    Returns:
        dict: البيانات المفككة أو None في حالة الفشل
    """
    decrypted = crev_decrypt_base64(encrypted_data, key)
    if not decrypted:
        return None
    
    try:
        config = json.loads(decrypted)
    except json.JSONDecodeError:
        return None
    
    # فك الحقول المتداخلة
    if "Tweaks" not in config or not isinstance(config["Tweaks"], list):
        return config
    
    for tweak in config["Tweaks"]:
        for field in ["Payload", "Nameserver", "Slowchave", "ServerPass",
                      "ServerUser", "ProxyHost", "DnsHost", "ServerHost", "SNI"]:
            if field in tweak and isinstance(tweak[field], str) and tweak[field]:
                try:
                    inner = crev_decrypt_base64(tweak[field], key)
                    if inner:
                        tweak[field] = inner
                except Exception:
                    pass
    
    return config


def decrypt_crev_file_enhanced(file_data: bytes) -> dict:
    """
    فك تشفير ملف .crev
    
    Args:
        file_data (bytes): محتوى الملف المشفر
        
    Returns:
        dict: البيانات المفككة أو None في حالة الفشل
    """
    try:
        # محاولة قراءة الملف كنص
        try:
            content = file_data.decode('utf-8', errors='ignore').strip()
        except:
            content = str(file_data)
        
        # إزالة أي بروتوكول مسبق
        if '://' in content:
            content = content.split('://', 1)[1]
        
        # إزالة المسافات والأسطر الجديدة
        content = ''.join(content.split())
        
        # تجربة المفاتيح المختلفة
        keys_to_try = ["DEV_CREEB", "CREEB", "dev_creeb", "DEV_CREV"]
        
        for key in keys_to_try:
            try:
                config = decrypt_crev_config(content, key)
                if config:
                    return config
            except Exception:
                continue
        
        return None
        
    except Exception as e:
        logger.error(f"CREV decryption error: {e}")
        return None
def run(file_bytes: bytes) -> str | None:
    if not isinstance(file_bytes, bytes) or not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return None
    result = decrypt_crev_file_enhanced(file_bytes)
    return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, dict) else None

EXTENSIONS = (".crev", ".cer", ".cerv")

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python crev.py <configuration-file>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if path.suffix.lower() not in EXTENSIONS:
        print("Unsupported crev extension", file=sys.stderr)
        return 2
    try:
        result = run(path.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Unable to read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt crev configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

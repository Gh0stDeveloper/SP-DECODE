#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot file decoder, derived from authorized 66.py."""
from __future__ import annotations
import base64
import binascii
import gzip
import hashlib
import html
import json
import logging
import re
import struct
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)

class EUTDecoder:
    """فك تشفير بيانات eut-settings:// وملفات .eut"""
    AES_KEY = "@Hh8Y2/[q$-@2f<9}8x£1_PU2RX!Aqlw"

    @staticmethod
    def pad_key(key: str) -> bytes:
        if len(key) < 16:
            key += '0' * (16 - len(key))
        elif len(key) > 16:
            key = key[:16]
        return key.encode('ISO-8859-1')

    @classmethod
    def decrypt_one_layer(cls, encrypted_text: str) -> str:
        """فك طبقة واحدة: نص بالصيغة 'enc_base64:iv_base64'"""
        if not encrypted_text or encrypted_text == "null":
            return encrypted_text
        parts = encrypted_text.split(":", 1)
        if len(parts) != 2:
            return encrypted_text
        enc_b64, iv_b64 = parts
        # تحقق بسيط من أن iv_b64 عبارة عن base64 صالح
        if not re.match(r'^[A-Za-z0-9+/=]+$', iv_b64):
            return encrypted_text
        try:
            key_bytes = cls.pad_key(cls.AES_KEY)
            iv_bytes = base64.b64decode(iv_b64)
            encrypted_bytes = base64.b64decode(enc_b64)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            pad_len = decrypted_padded[-1]
            if pad_len < 1 or pad_len > 16:
                return encrypted_text
            return decrypted_padded[:-pad_len].decode('utf-8', errors='ignore')
        except:
            return encrypted_text

    @classmethod
    def decrypt_recursive(cls, obj):
        """تطبيق فك التشفير على كامل الكائن (dict, list, str)"""
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, str) and ':' in v and len(v.split(':')) == 2:
                    dec = cls.decrypt_one_layer(v)
                    try:
                        parsed = json.loads(dec)
                        obj[k] = cls.decrypt_recursive(parsed)
                    except:
                        obj[k] = dec
                elif isinstance(v, (dict, list)):
                    obj[k] = cls.decrypt_recursive(v)
            return obj
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if isinstance(obj[i], (dict, list, str)):
                    obj[i] = cls.decrypt_recursive(obj[i])
            return obj
        elif isinstance(obj, str) and ':' in obj and len(obj.split(':')) == 2:
            dec = cls.decrypt_one_layer(obj)
            try:
                return cls.decrypt_recursive(json.loads(dec))
            except:
                return dec
        else:
            return obj

    @classmethod
    def decrypt(cls, text_or_bytes):
        """فك تشفير النص (قد يكون رابط eut-settings:// أو نص خام)"""
        # إذا كان bytes، نحوله إلى str
        if isinstance(text_or_bytes, bytes):
            text = text_or_bytes.decode('utf-8', errors='ignore')
        else:
            text = str(text_or_bytes)
        # إزالة البروتوكول
        if text.startswith("eut-settings://"):
            text = text[15:]
        # فك الطبقة الأولى
        first_layer = cls.decrypt_one_layer(text)
        # محاولة تحويل إلى JSON
        try:
            data = json.loads(first_layer)
        except:
            data = first_layer
        # فك متكرر
        decrypted = cls.decrypt_recursive(data)
        return decrypted
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    text=data.decode("utf-8",errors="replace").strip()
    if not text:
        return None
    decrypted=EUTDecoder.decrypt(text)
    if isinstance(decrypted,(dict,list)):
        return json.dumps(decrypted,ensure_ascii=False,indent=2)
    if not isinstance(decrypted,str) or decrypted==text:
        return None
    return decrypted

def main():
    if len(sys.argv) != 2:
        print("Usage: python eut.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".eut"):
        print("Unsupported extension", file=sys.stderr)
        return 2
    try:
        raw = path.read_bytes()
        output = run(raw)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if output is None:
        print("Unable to decode configuration", file=sys.stderr)
        return 1
    print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

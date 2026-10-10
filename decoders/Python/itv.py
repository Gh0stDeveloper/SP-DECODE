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

def clean_html(raw):
    if not raw:
        return ""
    raw=html.unescape(raw)
    return " ".join(x.strip() for x in re.sub(r"<[^>]+>","",raw).splitlines() if x.strip())
def decrypt_itv_file(file_data: bytes) -> str:
    """
    فك تشفير ملفات .itv:
    - أول 32 بايت: مفتاح AES
    - البايتات 32-44: IV (12 بايت)
    - الباقي: النص المشفر (AES-GCM)
    ثم استخراج إدخالات XML وتنظيف HTML.
    """
    try:
        if len(file_data) < 44:
            logger.warning("ITV file too small")
            return None
        
        key = file_data[:32]
        iv = file_data[32:44]
        ciphertext = file_data[44:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted_bytes = cipher.decrypt(ciphertext)
        decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')
        
        # استخراج الإدخالات
        pattern = r'<entry\s+key="([^"]+)"(?:>([\s\S]*?)</entry>|/>)'
        matches = re.findall(pattern, decrypted_text)
        
        parsed_lines = []
        for key_name, value in matches:
            val_clean = value.strip() if value else ""
            
            # تنظيف HTML
            if "<" in val_clean and ">" in val_clean and not val_clean.startswith("{"):
                val_clean = clean_html(val_clean)
            
            # تنسيق JSON إذا كان كذلك
            if val_clean.startswith("{") and val_clean.endswith("}"):
                try:
                    formatted_json = json.dumps(json.loads(val_clean), indent=2, ensure_ascii=False)
                    val_clean = "\n" + formatted_json
                except Exception:
                    pass
            
            parsed_lines.append(f"{key_name} = {val_clean}")
        
        return "\n".join(parsed_lines) if parsed_lines else decrypted_text
    
    except Exception as e:
        logger.error(f"ITV decryption error: {e}")
        return None
def run(data:bytes)->str|None:
    return decrypt_itv_file(data)

def main():
    if len(sys.argv) != 2:
        print("Usage: python itv.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".itv"):
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

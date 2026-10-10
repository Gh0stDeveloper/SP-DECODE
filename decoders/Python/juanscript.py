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

    return h[:16].lower() == checksum.lower()

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 120000, dklen=32)

def decrypt_payload(encrypted_data: bytes, password: str) -> bytes:
    offset = 0
    salt_len = struct.unpack(">I", encrypted_data[offset:offset+4])[0]
    offset += 4
    salt = encrypted_data[offset:offset+salt_len]
    offset += salt_len
    nonce_len = struct.unpack(">I", encrypted_data[offset:offset+4])[0]
    offset += 4
    nonce = encrypted_data[offset:offset+nonce_len]
    offset += nonce_len
    ciphertext_with_tag = encrypted_data[offset:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_juanscript_gcm(cipher_text: str, password: str = DEFAULT_PASSWORD) -> str:
    try:
        text = cipher_text.strip()
        if text.startswith("juanscript://"):
            body = text[13:]
        elif text.startswith("mobi://"):
            body = text[7:]
        else:
            body = text
        is_v2 = body.startswith("2:")
        if is_v2:
            body = body[2:]
        dot_idx = body.rfind(".")
        if dot_idx <= 0:
            raise ValueError("Invalid format")
        payload_b64 = body[:dot_idx]
        checksum = body[dot_idx+1:]
        if not verify_checksum(payload_b64, checksum):
            raise ValueError("Checksum mismatch")
        payload_b64 = payload_b64.replace('_', '/').replace('-', '+')
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.b64decode(payload_b64)
        plaintext = decrypt_payload(decoded, password)
        try:
            return gzip.decompress(plaintext).decode('utf-8')
        except:
            return plaintext.decode('utf-8')
    except Exception as e:
        return f"[Error] {str(e)}"

def get_decrypted_juanscript_config(input_text: str):
    decrypted = decrypt_juanscript_gcm(input_text)
    if decrypted.startswith("[Error]"):
        return {"status": "fail", "message": decrypted}
    try:
        json_obj = json.loads(decrypted)
        return {"status": "success", "data": json_obj}
    except:
        return {"status": "success", "data": decrypted}

def decrypt_juanscript_file(file_data: bytes):
    try:
        text = file_data.decode('utf-8', errors='ignore').strip()
        result = get_decrypted_juanscript_config(text)
        if result["status"] == "success":
            return result["data"]
        else:
            logger.error(f"Juanscript decryption failed: {result.get('message')}")
            return None
    except Exception as e:
        logger.error(f"Juanscript file decryption error: {e}")
        return None
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    output=decrypt_juanscript_file(data)
    if output is None:
        return None
    return json.dumps(output,ensure_ascii=False,indent=2) if isinstance(output,(dict,list)) else str(output)

def main():
    if len(sys.argv) != 2:
        print("Usage: python juanscript.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".juanscript"):
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

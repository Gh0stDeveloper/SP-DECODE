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

KEY = "84EE1C1019099C62"
PREFIX_LEN = 3
IV_END_IDX = 15
TAG_LENGTH = 16

IV_END_IDX = 15
TAG_LENGTH = 16


def decrypt_aes_gcm(cipher_b64: str, key_str: str) -> str:
    try:
        missing_padding = len(cipher_b64) % 4
        if missing_padding:
            cipher_b64 += '=' * (4 - missing_padding)

        decoded = base64.b64decode(cipher_b64)

        iv = decoded[PREFIX_LEN:IV_END_IDX]
        ciphertext_and_tag = decoded[IV_END_IDX:]

        ciphertext = ciphertext_and_tag[:-TAG_LENGTH]
        tag = ciphertext_and_tag[-TAG_LENGTH:]

        key_bytes = key_str.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode('utf-8')

    except Exception as e:
        return f"[Error] {str(e)}"


def process_nested_json(data):
    fields_to_decrypt = [
        'dnstt_dns',
        'custom_proxy',
        'custom_proxy_port',
        'password',
        'sni',
        'http',
        'v2ray_host',
        'v2ray_json'
    ]

    if isinstance(data, str):
        try:
            data = json.loads(data)
        except:
            return data

    if isinstance(data, list):
        for item in data:
            process_nested_json(item)

    elif isinstance(data, dict):
        for key, value in data.items():
            if key in fields_to_decrypt and isinstance(value, str):
                if value.startswith("djAx"):  # Base64 prefix check
                    decrypted = decrypt_aes_gcm(value, KEY)
                    if not decrypted.startswith("[Error]"):
                        data[key] = decrypted

    return data


def get_decrypted_config(input_text: str):
    decrypted_text = decrypt_aes_gcm(input_text, KEY)

    if decrypted_text.startswith("[Error]"):
        return {"status": "fail", "message": decrypted_text}

    final_data = process_nested_json(decrypted_text)

    return {"status": "success", "data": final_data}


def decrypt_wyrvpn_file(file_data: bytes):

    try:
        raw_text = file_data.decode("utf-8", errors="ignore").strip()
        if not raw_text:
            return None

        # Support either raw cipher or full protocol string inside the file.
        if raw_text.lower().startswith("wyrvpn://"):
            raw_text = raw_text.split("://", 1)[1]
        elif "wyrvpn://" in raw_text:
            raw_text = raw_text.split("wyrvpn://", 1)[1]

        cipher_clean = "".join(raw_text.split())
        result = get_decrypted_config(cipher_clean)
        if result.get("status") != "success":
            return None
        return result.get("data")
    except Exception:
        return None
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    output=decrypt_wyrvpn_file(data)
    if output is None:
        return None
    return json.dumps(output,ensure_ascii=False,indent=2) if isinstance(output,(dict,list)) else str(output)

def main():
    if len(sys.argv)!=2:
        print("Usage: python wyr.py <config-file>",file=sys.stderr)
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

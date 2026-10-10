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

K = b"AD079CFF21766C8A"
import string 
def clean_b64(s):
    x = ''.join(i for i in s if i in (string.ascii_letters + string.digits + '+/='))
    return x + "=" * ((4 - len(x) % 4) % 4)

def decrypt_nested(value):
    try:
        if not (isinstance(value, str) and value.startswith("djAx")):
            return value
        d = value[4:]
        iv = base64.b64decode(clean_b64(d[:16]))
        enc = base64.b64decode(clean_b64(d[16:]))
        cipher_text = enc[:-16]
        tag = enc[-16:]
        decrypted = AES.new(K, AES.MODE_GCM, nonce=iv).decrypt_and_verify(cipher_text, tag)
        return decrypted.decode("utf-8", "replace")
    except:
        return value

def recursive_decrypt(obj):
    if isinstance(obj, dict):
        return {k: recursive_decrypt(decrypt_nested(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [recursive_decrypt(decrypt_nested(i)) for i in obj]
    return obj

def decrypt_intvpn(data: str):
    try:
        if data.startswith("intvpn://"):
            data = data[9:]

        if not data.startswith("djAx"):
            return None

        d = data[4:]
        iv = base64.b64decode(clean_b64(d[:16]))
        enc = base64.b64decode(clean_b64(d[16:]))
        cipher_text = enc[:-16]
        tag = enc[-16:]

        decrypted = AES.new(K, AES.MODE_GCM, nonce=iv).decrypt_and_verify(cipher_text, tag)

        # محاولة تحويل إلى JSON
        try:
            json_data = json.loads(decrypted.decode('utf-8'))
            return recursive_decrypt(json_data)
        except:
            # لو لم يكن JSON، أعرضه بصيغة Base64
            return {"raw_base64": base64.b64encode(decrypted).decode('utf-8')}

    except Exception as e:
        return {"error": str(e)}

def decrypt_intvpn_file(file_data: bytes):
    try:
        raw = file_data.decode("utf-8", errors="ignore").strip()
        return decrypt_intvpn(raw)
    except Exception:
        return None


def decrypt_intvpn_file(file_data: bytes):
    try:
        raw = file_data.decode("utf-8", errors="ignore").strip()
        if not raw:
            return None

        # remove protocol
        if raw.startswith("intvpn://"):
            raw = raw.split("intvpn://", 1)[1]

        raw = "".join(raw.split())

        return decrypt_intvpn(raw)

    except Exception:
        return None
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    output=decrypt_intvpn_file(data)
    if not isinstance(output,(dict,list)) or (isinstance(output,dict) and "error" in output):
        return None
    return json.dumps(output,ensure_ascii=False,indent=2)

def main():
    if len(sys.argv)!=2:
        print("Usage: python int.py <config-file>",file=sys.stderr)
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

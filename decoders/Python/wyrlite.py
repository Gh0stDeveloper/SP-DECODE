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


# ------- Default settings -------
DEFAULT_PASSWORD = "acf54cb87cb8bca0"
V2_HARDCODED_KEY = bytes.fromhex(
    "bb 7f 0a c2 43 b7 e7 37 ad 62 1c 1c 43 b6 20 b8 "
    "c2 40 c0 8f 10 eb cc c9 7e f9 1e 1b d5 7a fa ea"
)

# ------- Helper stubs (replace with your bot functions) -------
def get_verified(): return "✅"
def get_diamond(): return "💎"
def sc(x): return f"⟨ {x} ⟩"
OWNER = "@decrypt_filebot"


# ==================== 1) Raw decryption ====================
def _pbkdf2(password: bytes, dklen=32, iters=10000) -> bytes:
    return pbkdf2_hmac("sha256", password, b"", iters, dklen)


def wyrl_decrypt_v1(data_b64: str, password=DEFAULT_PASSWORD, use_v2_key=False) -> str | None:
    """ChaCha20-Poly1305  (nonce[12] | tag[16] | ciphertext)"""
    try:
        blob = base64.b64decode(data_b64 + "=" * (-len(data_b64) % 4))
        if len(blob) < 28:
            return None
        nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]

        key = V2_HARDCODED_KEY if use_v2_key else _pbkdf2(
            password.encode() if isinstance(password, str) else password
        )

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        # Important: must use decrypt_and_verify with tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8", errors="ignore")
    except Exception:
        return None


def wyrl_decrypt_v2(ciphertext_b64: str,
                    seed: bytes = b"acf54cb87cb8bca0",
                    iterations: int = 10000) -> str | None:
    """AES-GCM  (nonce[12] | tag[16] | ciphertext)"""
    try:
        blob = base64.b64decode(ciphertext_b64 + "=" * (-len(ciphertext_b64) % 4))
        if len(blob) < 28:
            return None
        nonce, tag, ciphertext = blob[:12], blob[12:28], blob[28:]

        derived_key = _pbkdf2(seed, 32, iterations)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8", errors="ignore")
    except Exception:
        return None


# ==================== 2) Recursive decryption of inner fields ====================
def _try_decrypt_string(value: str) -> str:
    """Try every method on a single encrypted string"""
    if not isinstance(value, str) or len(value) < 20:
        return value
    # V2 hardcoded
    for fn, kw in ((wyrl_decrypt_v1, {"use_v2_key": True}),
                   (wyrl_decrypt_v1, {}),
                   (wyrl_decrypt_v2, {})):
        try:
            dec = fn(value, **kw)
            if dec and dec.strip():
                # If the result is nested JSON, decrypt it too
                try:
                    parsed = json.loads(dec)
                    if isinstance(parsed, (dict, list)):
                        return wyrl_recursive_decrypt(parsed)
                except Exception:
                    pass
                return dec
        except Exception:
            continue
    return value


def wyrl_recursive_decrypt(data):
    """Walks through JSON and applies decryption to every string"""
    if isinstance(data, dict):
        return {k: wyrl_recursive_decrypt(_try_decrypt_string(v))
                if isinstance(v, str) else wyrl_recursive_decrypt(v)
                for k, v in data.items()}
    if isinstance(data, list):
        return [wyrl_recursive_decrypt(i) for i in data]
    return data


# ==================== 3) Decrypt the whole file ====================
def decrypt_wyrlite_file(file_data: bytes) -> dict | list | None:
    """Takes file bytes and returns decrypted JSON"""
    try:
        if isinstance(file_data, (bytes, bytearray)):
            content = file_data.decode("utf-8", errors="ignore").strip()
        else:
            content = str(file_data).strip()

        # Remove prefix like wyrlite://
        if "://" in content:
            content = content.split("://", 1)[1]

        content = content.replace("\n", "").replace("\r", "").replace(" ", "")

        # Try external decryption
        decrypted = (wyrl_decrypt_v1(content, use_v2_key=True)
                     or wyrl_decrypt_v1(content)
                     or wyrl_decrypt_v2(content)
                     or content)  # might already be plain JSON

        # Convert to JSON
        try:
            json_data = json.loads(decrypted)
        except json.JSONDecodeError:
            # Fix keys without quotes
            fixed = re.sub(r'([{,])\s*([A-Za-z0-9_\-]+)\s*:', r'\1"\2":', decrypted)
            json_data = json.loads(fixed)

        return wyrl_recursive_decrypt(json_data)

    except Exception as e:
        print(f"[WYRLITE] decryption error: {e}")
        return None
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    output=decrypt_wyrlite_file(data)
    return json.dumps(output,ensure_ascii=False,indent=2) if isinstance(output,(dict,list)) else None

def main():
    if len(sys.argv)!=2:
        print("Usage: python wyrlite.py <config-file>",file=sys.stderr)
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

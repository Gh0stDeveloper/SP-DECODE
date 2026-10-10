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

MAGIC_HEADER = b"STCF"
SUPPORTED_VERSION = 1
KEY_A = bytes([83, 69, 78, 84, 73, 78, 69, 76, 95, 84, 85, 78, 78, 69, 76, 95, 67, 79, 78, 70, 73, 71, 95, 75, 69, 89, 95, 86, 49, 95, 50, 48])
SENSITIVE_FIELDS = ("passwordHash", "salt")
SENSITIVE_CONFIG_FIELDS = ("keySalt", "hmac", "iv", "data")

class DecryptionError(Exception):
    pass

class InvalidConfigError(Exception):
    pass

@dataclass
class DecryptedConfig:
    outer: dict
    inner: dict

    def merged(self) -> dict:
        return {**self.outer, "configData": self.inner}

def _xor_reverse_transform(data: bytes) -> bytes:
    arr = bytearray(data)
    size = len(arr)
    for i in range(0, ((size - 1) // 32) * 32 + 1, 32):
        if i + 16 < size:
            end = min(i + 16, size)
            arr[i:end] = arr[i:end][::-1]
    for i in range(size):
        arr[i] ^= KEY_A[i % 32]
    return bytes(arr)

def _parse_json_robust(raw: bytes) -> dict:
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    text = raw.decode("utf-8", errors="ignore").strip()
    if "`" in text or text.endswith("'"):
        chars = list(text)
        for idx in range(len(chars) - 1, -1, -1):
            if chars[idx] == "`":
                chars[idx] = ":"
                break
        if chars and chars[-1] == "'":
            chars[-1] = "}"
        fixed = "".join(chars)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            pass

    for candidate in [text, text + "}"]:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    raise InvalidConfigError("Failed to parse outer JSON after decryption")

def decrypt_outer_layer(data: bytes) -> dict:
    transformed = _xor_reverse_transform(data)
    if transformed[:4] != MAGIC_HEADER:
        raise InvalidConfigError(f"Invalid header: {transformed[:4]!r}")
    if transformed[4] != SUPPORTED_VERSION:
        raise InvalidConfigError(f"Unsupported version: {transformed[4]}")
    return _parse_json_robust(transformed[5:])

def _derive_key(config_data: dict, outer: dict) -> bytes:
    password_hash_b64 = outer.get("passwordHash")
    key_salt = base64.b64decode(config_data["keySalt"])
    if password_hash_b64:
        return base64.b64decode(password_hash_b64)
    else:
        return hashlib.sha256(KEY_A + key_salt).digest()

def decrypt_inner_layer(config_data: dict, outer: dict) -> dict:
    if not config_data.get("keySalt"):
        raise InvalidConfigError("Missing keySalt")
    raw  = base64.b64decode(config_data["data"])
    iv   = base64.b64decode(config_data["iv"])
    hmac = base64.b64decode(config_data["hmac"])
    key  = _derive_key(config_data, outer)

    h = HMAC.new(key, digestmod=SHA256)
    h.update(iv + raw)
    if h.digest() != hmac:
        raise DecryptionError("HMAC verification failed")

    cipher    = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    plaintext = cipher.decrypt_and_verify(raw[:-16], raw[-16:])
    return json.loads(plaintext.decode("utf-8"))

def sanitize(data: dict) -> dict:
    result = {k: v for k, v in data.items() if k not in SENSITIVE_FIELDS}
    if isinstance(result.get("configData"), dict):
        result["configData"] = {k: v for k, v in result["configData"].items()
                                if k not in SENSITIVE_CONFIG_FIELDS}
    return result

def load_and_decrypt(raw_data: bytes) -> dict:
    """يقبل bytes مباشرة ويعيد القاموس المفكك"""
    outer       = decrypt_outer_layer(raw_data)
    config_data = outer.get("configData", {})
    inner       = decrypt_inner_layer(config_data, outer)
    return DecryptedConfig(outer, inner).merged()

def sentinel_dec(data: bytes) -> dict:
    """دالة الواجهة للبوت"""
    try:
        return load_and_decrypt(data)
    except (InvalidConfigError, DecryptionError) as e:
        logger.debug("ST decrypt failed: %s", e)
        return None
def run(data:bytes)->str|None:
    if not isinstance(data,bytes) or len(data)<8:
        return None
    try:
        config = load_and_decrypt(data)
        return json.dumps(config,ensure_ascii=False,indent=2)
    except (ValueError,KeyError,TypeError,DecryptionError,InvalidConfigError):
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python st.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".st"):
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

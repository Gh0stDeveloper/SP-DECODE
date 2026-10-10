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

G_RAW_HEX: str = (
    "333a33333232c933cc393d3b3e38383fcbcfc8cbc9cf333f3e3ccb3a32cb3ccf"
    "3dcb3239c9cfc83c3c3a393f3e3332cf333fce3839cc3d323ec8c8ce32c83333"
    "898ee1ea8b"
)

_g_raw_bytes: bytes = bytes.fromhex(G_RAW_HEX)
LTM_PASSWORD: bytes = _g_raw_bytes.decode("utf-8", errors="replace").encode("utf-8")
LTM_ITERATIONS: int = 1000
LTM_KEY_LENGTH: int = 16
def ltm_decrypt_config(encrypted_data: str) -> str:
    """Original LTM salt.nonce.ciphertext+tag with PBKDF2-HMAC-SHA256 AES-GCM."""
    parts = encrypted_data.split(".")
    if len(parts) != 3:
        raise ValueError("LTM expects three Base64 parts")
    salt, nonce, sealed = (base64.b64decode(part, validate=True) for part in parts)
    if not salt or len(nonce) < 8 or len(sealed) < 17:
        raise ValueError("Invalid LTM encrypted envelope")
    key = PBKDF2(LTM_PASSWORD, salt, dkLen=LTM_KEY_LENGTH,
                 count=LTM_ITERATIONS, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(sealed[:-16], sealed[-16:]).decode("utf-8")

def ltm_strip_invalid_xml_refs(xml_str: str) -> str:
    """إزالة المراجع غير الصالحة في XML"""
    def _replace_ref(m: re.Match) -> str:
        try:
            code = int(m.group(1))
        except ValueError:
            return m.group(0)
        if (
            0xD800 <= code <= 0xDFFF
            or 0x00 <= code <= 0x08
            or 0x0B <= code <= 0x0C
            or 0x0E <= code <= 0x1F
            or 0x7F <= code <= 0x84
            or 0x86 <= code <= 0x9F
            or code > 0x10FFFF
        ):
            return ""
        return m.group(0)
    return re.sub(r"&#(\d+);", _replace_ref, xml_str)


def ltm_xml_properties_to_dict(xml_string: str) -> dict[str, Any]:
    """تحويل XML Properties إلى قاموس Python"""
    xml_clean = ltm_strip_invalid_xml_refs(xml_string)
    root = ET.fromstring(xml_clean)
    result: dict[str, Any] = {}
    
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is None:
            continue
        result[key] = entry.text or ""
    
    comment = root.find("comment")
    if comment is not None and comment.text:
        result["_comment"] = comment.text
    
    return result


def decrypt_ltm_file(file_data: bytes) -> dict:
    """فك تشفير ملف HTTP LTM (.ltm)"""
    try:
        content = file_data.decode('utf-8', errors='ignore').strip()
        
        if "://" in content:
            content = content.split("://", 1)[1]
        
        content = ''.join(content.split())
        
        decrypted = ltm_decrypt_config(content)
        
        if not decrypted:
            return None
        
        config_dict = ltm_xml_properties_to_dict(decrypted)
        
        return config_dict
        
    except Exception as e:
        logger.debug("LTM decoding failed: %s", e)
        return None
def run(data: bytes) -> str | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        return None
    result = decrypt_ltm_file(data)
    return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, dict) else None

EXTENSIONS = (".ltm", ".lt")

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python ltm.py <configuration-file>", file=sys.stderr)
        return 2
    filename = Path(args[0])
    if filename.suffix.lower() not in EXTENSIONS:
        print("Unsupported ltm extension", file=sys.stderr)
        return 2
    try:
        result = run(filename.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Cannot read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt ltm configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

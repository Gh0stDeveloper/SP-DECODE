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

import re as _ktr_re
import base64 as _ktr_b64
import struct as _ktr_struct
from Crypto.Cipher import AES as _ktr_AES
from Crypto.Util.Padding import unpad as _ktr_unpad

KTR_KEY = bytes.fromhex(
    "6f8deb1015ca70be2b53aef0858d7781"
    "1f352c073b6708d72d9d10a30914dff9"
)
KTR_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KTR_JAVA_MAGIC = b"\xac\xed\x00\x05"


# ═══════════════════════════════════════════════════════════
# AES-256-CBC value decryption
# ═══════════════════════════════════════════════════════════
def ktr_decrypt_value(value):
    if not isinstance(value, str) or not value:
        return None
    if len(value) < 4 or len(value) % 4 != 0:
        return None
    try:
        encrypted = _ktr_b64.b64decode(value, validate=True)
    except Exception:
        return None
    if len(encrypted) < 16 or len(encrypted) % 16 != 0:
        return None
    try:
        cipher = _ktr_AES.new(KTR_KEY, _ktr_AES.MODE_CBC, KTR_IV)
        plaintext = cipher.decrypt(encrypted)
        plaintext = _ktr_unpad(plaintext, _ktr_AES.block_size)
        result = plaintext.decode("utf-8")
    except Exception:
        return None
    if not result:
        return None
    printable = sum(c.isprintable() or c in "\r\n\t" for c in result)
    if printable / len(result) < 0.85:
        return None
    return result


# ═══════════════════════════════════════════════════════════
# Field name pattern: UPPERCASE_WITH_UNDERSCORES
# ═══════════════════════════════════════════════════════════
_KTR_FIELD_RE = _ktr_re.compile(r'^[A-Z][A-Z0-9_]{1,60}$')

_KTR_SKIP_PREFIX = (
    'java.', 'com.', 'org.', 'sun.', 'javax.',
    'Ljava.', '[L', 'Lsc.', 'Lcom/',
)
_KTR_SKIP_EXACT = {'key', 'value', 'next', 'hash', 'this$0', 'serialVersionUID'}


def _ktr_pair_fields(strings):
    """
    Pair field names with the following values.

    Algorithm:
      - When a field name pattern is seen → set as pending key
      - When a non-field string is seen → assign as value for pending key
      - When two field names appear consecutively → first one has null value
    """
    result = {}
    pending_key = None
    i, n = 0, len(strings)

    while i < n:
        s = strings[i]

        # Skip class descriptor / metadata strings
        if s in _KTR_SKIP_EXACT:
            i += 1
            continue
        if any(s.startswith(p) for p in _KTR_SKIP_PREFIX):
            i += 1
            continue

        is_field = bool(_KTR_FIELD_RE.match(s))

        if pending_key is not None:
            if is_field:
                # Previous field had null value
                result[pending_key] = None
                pending_key = s
            else:
                # This is the value for pending_key
                result[pending_key] = s
                pending_key = None
        else:
            if is_field:
                pending_key = s

        i += 1

    if pending_key is not None:
        result[pending_key] = None

    return result


# ═══════════════════════════════════════════════════════════
# Extract Java TC_STRING / TC_LONGSTRING
# ═══════════════════════════════════════════════════════════
def _ktr_extract_java_strings(data):
    strings = []
    i, n = 0, len(data)
    while i < n:
        tag = data[i]
        if tag == 0x74:  # TC_STRING
            if i + 3 <= n:
                ln = _ktr_struct.unpack(">H", data[i + 1:i + 3])[0]
                if 0 < ln <= 65535 and i + 3 + ln <= n:
                    try:
                        strings.append(data[i + 3:i + 3 + ln].decode("utf-8"))
                        i += 3 + ln
                        continue
                    except Exception:
                        pass
        elif tag == 0x7C:  # TC_LONGSTRING
            if i + 9 <= n:
                ln = _ktr_struct.unpack(">Q", data[i + 1:i + 9])[0]
                if 0 < ln <= 10_000_000 and i + 9 + ln <= n:
                    try:
                        strings.append(data[i + 9:i + 9 + ln].decode("utf-8"))
                        i += 9 + ln
                        continue
                    except Exception:
                        pass
        i += 1
    return strings


# ═══════════════════════════════════════════════════════════
# Extract Base64 strings (with deduplication)
# ═══════════════════════════════════════════════════════════
_B64_RE = _ktr_re.compile(rb'[A-Za-z0-9+/]{20,}={0,2}')


def _ktr_extract_base64_values(data):
    """Extract and decrypt all Base64 strings."""
    values = []
    seen = set()
    for raw in _B64_RE.findall(data):
        try:
            value = raw.decode('ascii')
        except Exception:
            continue
        if value in seen:
            continue
        try:
            decoded = _ktr_b64.b64decode(value, validate=True)
        except Exception:
            continue
        if len(decoded) < 16 or len(decoded) % 16 != 0:
            continue
        decrypted = ktr_decrypt_value(value)
        if decrypted is not None:
            seen.add(value)
            values.append(decrypted)
    return values


# ═══════════════════════════════════════════════════════════
# Main decoder — multi-strategy with field pairing
# ═══════════════════════════════════════════════════════════
def decrypt_ktr_file(file_data):
    """
    Universal KTR decoder — multi-strategy extraction.

    Strategy 1: TC_STRING → decrypt each → pair
    Strategy 2: Base64 raw extraction → decrypt → pair
    Strategy 3: Merge results
    """
    if not isinstance(file_data, bytes):
        raise TypeError("KTR file_data must be bytes")
    if not file_data.startswith(KTR_JAVA_MAGIC):
        raise ValueError("Not Java Serialization")

    result = {}

    # ── Strategy 1: TC_STRING extraction + decryption + pairing ──
    try:
        tc_strings = _ktr_extract_java_strings(file_data)
        decrypted_tc = []
        for s in tc_strings:
            dec = ktr_decrypt_value(s)
            decrypted_tc.append(dec if dec is not None else s)

        pairs_tc = _ktr_pair_fields(decrypted_tc)
        for k, v in pairs_tc.items():
            result[k] = v

        logger.debug(f"KTR strategy 1: {len(result)} fields from TC_STRING")
    except Exception as e:
        logger.debug(f"KTR strategy 1 failed: {e}")

    # ── Strategy 2: Base64 raw extraction + pairing ──
    try:
        b64_plaintexts = _ktr_extract_base64_values(file_data)
        pairs_b64 = _ktr_pair_fields(b64_plaintexts)

        added = 0
        for k, v in pairs_b64.items():
            if k not in result:
                result[k] = v
                added += 1

        logger.debug(f"KTR strategy 2: added {added} fields, total {len(result)}")
    except Exception as e:
        logger.debug(f"KTR strategy 2 failed: {e}")

    return {
        "mode": "java",
        "count": len(result),
        "data": result,
    }
def run(data: bytes) -> str | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_BYTES:
        return None
    try:
        output = decrypt_ktr_file(data)
        if not isinstance(output, dict) or not output.get("count"):
            return None
        return json.dumps(output, ensure_ascii=False, indent=2)
    except (ValueError, TypeError, struct.error):
        return None

EXTENSIONS = (".ktr",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python ktr.py <configuration-file>", file=sys.stderr)
        return 2
    filename = Path(args[0])
    if filename.suffix.lower() not in EXTENSIONS:
        print("Unsupported ktr extension", file=sys.stderr)
        return 2
    try:
        result = run(filename.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Cannot read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt ktr configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

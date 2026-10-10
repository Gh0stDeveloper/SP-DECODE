#!/usr/bin/env python3
"""Generic AES-GCM/PBKDF2 VPN profiles from the authorized 66.py source.

Files use three dot-separated Base64 segments: salt, nonce and ciphertext
with the 16-byte GCM tag appended. The original PBKDF2 defaults are
HMAC-SHA256, 1000 iterations, 16-byte AES key (PyCryptodome).
The tag is always authenticated; wrong passwords never yield output.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

try:
    from decoders.Python.generic_profiles import AES_PROFILES
except ModuleNotFoundError:
    from generic_profiles import AES_PROFILES

MAX_INPUT_BYTES = 2 * 1024 * 1024
GCM_TAG_BYTES = 16
KDF_ROUNDS = 1000
KDF_KEY_BYTES = 16
_ENTRY_RE = re.compile(
    r'<entry\s+key\s*=\s*["\'](?P<key>[^"\']+)["\']\s*'
    r'(?:>(?P<value>.*?)</entry\s*>|/>)',
    flags=re.IGNORECASE | re.DOTALL,
)


def normalize_extension(value: str) -> str:
    return "." + value.lower().strip().lstrip(".")


def _decode_base64(part: bytes) -> bytes:
    clean = b"".join(part.split())
    if not clean:
        raise ValueError("Empty Base64 segment")
    return base64.b64decode(clean, validate=True)


def decrypt_with_extension(file_bytes: bytes, extension: str) -> str | None:
    """Return authenticated UTF-8 plaintext, using only the extension's keys."""
    ext = normalize_extension(extension)
    passwords = AES_PROFILES.get(ext, ())
    if not passwords or not isinstance(file_bytes, bytes):
        return None
    if not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return None
    try:
        segments = file_bytes.strip().split(b".")
        if len(segments) != 3:
            return None
        salt, nonce, sealed = (_decode_base64(segment) for segment in segments)
        if not 1 <= len(salt) <= 128 or not 1 <= len(nonce) <= 128:
            return None
        if len(sealed) <= GCM_TAG_BYTES:
            return None
    except (binascii.Error, ValueError):
        return None

    for password in passwords:
        if not password:
            continue
        try:
            key = PBKDF2(
                password, salt, dkLen=KDF_KEY_BYTES, count=KDF_ROUNDS,
                hmac_hash_module=SHA256,
            )
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plain = cipher.decrypt_and_verify(
                sealed[:-GCM_TAG_BYTES], sealed[-GCM_TAG_BYTES:]
            )
            text = plain.decode("utf-8")
            return text if text.strip() else None
        except (ValueError, UnicodeDecodeError):
            # A failed GCM tag is expected when checking a different
            # historical password; never surface unauthenticated plaintext.
            continue
    return None


def render_plaintext(text: str) -> str | None:
    """Show every original field; never hide passwords or trim XML values."""
    if not text or not text.strip():
        return None
    try:
        structured = json.loads(text)
        return json.dumps(structured, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        pass

    matches = list(_ENTRY_RE.finditer(text))
    if matches:
        # The original parser emitted dict fields but discarded unrecognized
        # XML, duplicate keys and extra values. Keep raw text as well.
        entries = [
            {"key": match.group("key"), "value": match.group("value") or ""}
            for match in matches
        ]
        return json.dumps(
            {"entries": entries, "raw_xml": text},
            ensure_ascii=False, indent=2,
        )

    # Authenticated plaintext need not be JSON/XML in older exports.
    return text


def run(file_bytes: bytes, extension: str) -> str | None:
    plaintext = decrypt_with_extension(file_bytes, extension)
    return render_plaintext(plaintext) if plaintext is not None else None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python generic_aes.py <config.extension>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if normalize_extension(path.suffix) not in AES_PROFILES:
        print("Unsupported AES-GCM profile", file=sys.stderr)
        return 2
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"Cannot read file: {exc}", file=sys.stderr)
        return 1
    result = run(data, path.suffix)
    if result is None:
        print("Unable to authenticate AES-GCM profile", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

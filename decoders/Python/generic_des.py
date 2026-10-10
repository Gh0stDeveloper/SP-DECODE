#!/usr/bin/env python3
"""Generic DES-ECB VPN config profiles, source-compatible with 66.py.

The historical dispatcher tried DES before AES for colliding suffixes.
For such suffixes this module validates the decrypted XML/JSON and then
tries the authenticated AES-GCM engine when DES doesn't match.
Never return random decrypted bytes as a successful configuration.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from pathlib import Path

from Crypto.Cipher import DES

try:
    from decoders.Python.generic_profiles import AES_PROFILES, DES_PROFILES
    from decoders.Python.generic_aes import (
        MAX_INPUT_BYTES, normalize_extension, render_plaintext,
        run as run_generic_aes,
    )
except ModuleNotFoundError:
    from generic_profiles import AES_PROFILES, DES_PROFILES
    from generic_aes import (
        MAX_INPUT_BYTES, normalize_extension, render_plaintext,
        run as run_generic_aes,
    )

# Raw Java/Android SharedPreferences-style <entry> elements.
_ENTRY_RE = re.compile(
    r'<entry\s+key\s*=\s*["\'][^"\']+["\']\s*'
    r'(?:>.*?</entry\s*>|/>)',
    flags=re.IGNORECASE | re.DOTALL,
)


def _credible_plaintext(plaintext: bytes) -> str | None:
    # Historical DES used errors='ignore', which could report random bytes
    # as a decoded profile. Fail closed on malformed UTF-8 instead.
    try:
        text = plaintext.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    # DES exports in 66.py were XML <entry> records, including optional
    # empty entries. Allow an actual JSON object as an additional variant.
    if _ENTRY_RE.search(text):
        return text
    try:
        data = json.loads(text)
        if isinstance(data, (dict, list)):
            return text
    except ValueError:
        pass
    return None


def decrypt_des_with_extension(file_bytes: bytes, extension: str) -> str | None:
    ext = normalize_extension(extension)
    key = DES_PROFILES.get(ext)
    if not key or not isinstance(file_bytes, bytes):
        return None
    if not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return None

    # The historical code decrypted raw bytes directly with a truncated or
    # NUL-padded 8-byte DES key. A strict Base64 variant is also accepted
    # only if the decrypted content passes the XML/JSON check.
    key8 = key[:8].ljust(8, b"\0")
    candidates = [file_bytes]
    try:
        clean = b"".join(file_bytes.split())
        if clean != file_bytes and clean:
            encoded = base64.b64decode(clean, validate=True)
            if encoded != file_bytes:
                candidates.append(encoded)
        elif clean and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in clean):
            decoded = base64.b64decode(clean, validate=True)
            if decoded != file_bytes:
                candidates.append(decoded)
    except (ValueError, binascii.Error):
        pass
    for candidate in candidates:
        if len(candidate) < 8 or len(candidate) % 8:
            continue
        try:
            cipher = DES.new(key8, DES.MODE_ECB)
            result = _credible_plaintext(cipher.decrypt(candidate))
            if result is not None:
                return result
        except ValueError:
            continue
    return None


def run(file_bytes: bytes, extension: str) -> str | None:
    ext = normalize_extension(extension)
    des_result = decrypt_des_with_extension(file_bytes, ext)
    if des_result is not None:
        return render_plaintext(des_result)
    if ext in AES_PROFILES:
        # Six new suffixes (.acm, .htp, .pin, .tut, .vmx, .xsks)
        # are in both tables. DES was checked first as in 66.py.
        return run_generic_aes(file_bytes, ext)
    return None


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python generic_des.py <config.extension>", file=sys.stderr)
        return 2
    path = Path(args[0])
    ext = normalize_extension(path.suffix)
    if ext not in DES_PROFILES:
        print("Unsupported DES-ECB profile", file=sys.stderr)
        return 2
    try:
        file_bytes = path.read_bytes()
    except OSError as exc:
        print(f"Cannot read file: {exc}", file=sys.stderr)
        return 1
    output = run(file_bytes, ext)
    if output is None:
        print("Unable to decrypt DES-ECB/AES profile", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

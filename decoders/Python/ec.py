#!/usr/bin/env python3
"""EC (.ec) — standalone XXTEA file decoder.

Portable pure-Python form of standard XXTEA with a length trailer,
equivalent to the xxtea.decrypt() call in authorized 66.py.
"""
from __future__ import annotations
import base64
import json
import struct
import sys
from pathlib import Path

KEY = b"technore_101014"
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _decrypt_xxtea(payload: bytes, key: bytes = KEY) -> bytes | None:
    if len(payload) < 8 or len(payload) % 4:
        return None
    key = key[:16].ljust(16, b"\x00")
    v = list(struct.unpack("<%dI" % (len(payload) // 4), payload))
    k = struct.unpack("<4I", key)
    n = len(v) - 1
    q = 6 + 52 // (n + 1)
    total = (q * DELTA) & MASK
    while total:
        e = (total >> 2) & 3
        y = v[0]
        for p in range(n, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
                (total ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] - mx) & MASK
            y = v[p]
        z = v[n]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ (
            (total ^ y) + (k[e] ^ z))
        v[0] = (v[0] - mx) & MASK
        y = v[0]
        total = (total - DELTA) & MASK
    body = struct.pack("<%dI" % len(v), *v)
    actual = struct.unpack("<I", body[-4:])[0]
    if actual < len(body) - 7 or actual > len(body) - 4:
        return None
    return body[:actual]


def decode_bytes(file_data: bytes) -> dict | list | str | None:
    if not file_data or len(file_data) > 2 * 1024 * 1024:
        return None
    try:
        raw = base64.b64decode(b"".join(file_data.split()), validate=True)
        clear = _decrypt_xxtea(raw)
        if clear is None:
            return None
        text = clear.decode("utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    except (ValueError, UnicodeError, struct.error):
        return None


def run(file_data: bytes) -> str | None:
    decoded = decode_bytes(file_data)
    if decoded is None:
        return None
    return json.dumps(decoded, ensure_ascii=False, indent=2) if isinstance(decoded, (dict, list)) else decoded


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python ec.py <file.ec>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if path.suffix.lower() != ".ec":
        print("Expected a .ec file", file=sys.stderr)
        return 2
    try:
        result = run(path.read_bytes())
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt EC", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Experimental SocksIP VER7 layer analyzer.

This module implements the externally supplied hypothesis that the payload
following the confirmed outer Base64/AES layer is:

    VER7 + hexadecimal(repeating_xor(next_layer, AES_KEY))

The hypothesis is deliberately constrained:

* the VER7 payload must be valid hexadecimal text;
* only the already known 16-byte SocksIP key is used;
* no key search, brute force or lossy text decoding is performed;
* a result is accepted only when a later layer becomes valid JSON or Java
  Object Serialization.

It is kept separate from ``sockip.py`` until a real VER7 sample confirms the
route.
"""

from __future__ import annotations

import hashlib
import json
from argparse import ArgumentParser
from pathlib import Path
from typing import Any, Optional

try:
    from .sockip import (
        AES_KEY,
        MAX_CONTAINER_SIZE,
        STREAM_MAGIC,
        VER7_MAGIC,
        UnsupportedSocksIPVersion,
        _entropy,
        _iter_transforms,
        _try_parse_candidate,
        decode_outer_layer,
    )
except ImportError:  # Direct execution: python decoders/Python/sockip_ver7.py
    from sockip import (  # type: ignore
        AES_KEY,
        MAX_CONTAINER_SIZE,
        STREAM_MAGIC,
        VER7_MAGIC,
        UnsupportedSocksIPVersion,
        _entropy,
        _iter_transforms,
        _try_parse_candidate,
        decode_outer_layer,
    )

MAX_POST_XOR_DEPTH = 5
MAX_POST_XOR_CANDIDATES = 96
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_PREFIX_SEPARATORS = b"\x00\t\r\n :|;,-"


def xor_repeating(data: bytes, key: bytes = AES_KEY) -> bytes:
    """Apply a repeating XOR key without converting the result to text."""
    if not key:
        raise ValueError("la clave XOR no puede estar vacía")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _normalize_hex_text(data: bytes) -> bytes:
    """Normalize a strict hexadecimal payload while allowing visual separators."""
    data = data.lstrip(_PREFIX_SEPARATORS)
    normalized = b"".join(data.split())
    if not normalized:
        raise UnsupportedSocksIPVersion("VER7 no contiene datos después del marcador")
    if len(normalized) % 2:
        raise UnsupportedSocksIPVersion("el payload VER7 hexadecimal tiene longitud impar")
    if any(value not in _HEX_DIGITS for value in normalized):
        raise UnsupportedSocksIPVersion(
            "el payload VER7 no es hexadecimal estricto; la hipótesis XOR recibida no aplica"
        )
    if len(normalized) // 2 > MAX_CONTAINER_SIZE:
        raise ValueError("payload VER7 hexadecimal demasiado grande")
    return normalized


def decode_ver7_hex_xor_layer(plaintext: bytes) -> bytes:
    """Decode only the proposed VER7 -> hex -> repeating-XOR layer."""
    if not plaintext.startswith(VER7_MAGIC):
        raise ValueError("el contenido descifrado no comienza con VER7")
    hex_text = _normalize_hex_text(plaintext[len(VER7_MAGIC):])
    xor_ciphertext = bytes.fromhex(hex_text.decode("ascii"))
    return xor_repeating(xor_ciphertext)


def _signature(data: bytes) -> str:
    stripped = data.lstrip()
    if data.startswith(STREAM_MAGIC):
        return "java-serialization"
    if stripped.startswith(b"{"):
        return "json-object"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
        return "zlib"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data and all(value in b"\t\r\n " or 32 <= value < 127 for value in data[:256]):
        return "printable-ascii"
    return "binary"


def _ascii_preview(data: bytes, limit: int = 96) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in data[:limit])


def decode_ver7_xor_profile(plaintext: bytes) -> tuple[dict[str, Any], str]:
    """Resolve the proposed XOR layer and bounded deterministic layers after it."""
    first = decode_ver7_hex_xor_layer(plaintext)
    queue: list[tuple[str, bytes, int]] = [("VER7->hex->xor-known-key", first, 0)]
    seen: set[str] = set()
    candidates = 0

    while queue:
        route, data, depth = queue.pop(0)
        if not data or len(data) > MAX_CONTAINER_SIZE:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        candidates += 1
        if candidates > MAX_POST_XOR_CANDIDATES:
            break

        try:
            parsed = _try_parse_candidate(data)
        except Exception:
            parsed = None
        if parsed is not None:
            return parsed, route

        if depth >= MAX_POST_XOR_DEPTH:
            continue
        for transform, candidate in _iter_transforms(data):
            queue.append((f"{route}->{transform}", candidate, depth + 1))

    raise UnsupportedSocksIPVersion(
        "la capa VER7 hexadecimal + XOR produjo datos, pero ninguna de las "
        f"{min(candidates, MAX_POST_XOR_CANDIDATES)} rutas posteriores terminó en "
        "JSON ni serialización Java válida"
    )


def inspect_ver7_xor(plaintext: bytes) -> dict[str, Any]:
    """Return non-lossy diagnostics for the proposed XOR layer."""
    if not plaintext.startswith(VER7_MAGIC):
        raise ValueError("el contenido descifrado no comienza con VER7")

    payload = plaintext[len(VER7_MAGIC):]
    result: dict[str, Any] = {
        "hypothesis": "VER7 -> strict hex -> repeating XOR with known SocksIP AES key",
        "verified": False,
        "ver7_payload_size": len(payload),
        "ver7_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "ver7_payload_entropy": round(_entropy(payload), 5),
        "ver7_payload_head_ascii": _ascii_preview(payload),
    }

    try:
        normalized = _normalize_hex_text(payload)
    except UnsupportedSocksIPVersion as exc:
        result.update({"hex_valid": False, "reason": str(exc)})
        return result

    xor_ciphertext = bytes.fromhex(normalized.decode("ascii"))
    xor_plaintext = xor_repeating(xor_ciphertext)
    result.update(
        {
            "hex_valid": True,
            "hex_character_count": len(normalized),
            "xor_ciphertext_size": len(xor_ciphertext),
            "xor_ciphertext_sha256": hashlib.sha256(xor_ciphertext).hexdigest(),
            "xor_plaintext_size": len(xor_plaintext),
            "xor_plaintext_sha256": hashlib.sha256(xor_plaintext).hexdigest(),
            "xor_plaintext_entropy": round(_entropy(xor_plaintext), 5),
            "xor_plaintext_signature": _signature(xor_plaintext),
            "xor_plaintext_head_hex": xor_plaintext[:64].hex(),
            "xor_plaintext_head_ascii": _ascii_preview(xor_plaintext),
            "post_xor_transforms": [name for name, _ in _iter_transforms(xor_plaintext)],
        }
    )

    try:
        parsed, route = decode_ver7_xor_profile(plaintext)
        result.update(
            {
                "verified": True,
                "resolved_route": route,
                "root_keys": sorted(str(key) for key in parsed.keys()),
            }
        )
    except UnsupportedSocksIPVersion as exc:
        result.update({"resolved_route": None, "reason": str(exc)})
    return result


def inspect_sip_file(file_data: bytes) -> dict[str, Any]:
    """Decode the confirmed outer layer and inspect the supplied XOR hypothesis."""
    plaintext = decode_outer_layer(file_data)
    result: dict[str, Any] = {
        "outer_layer": "Base64 + AES-128-ECB + PKCS#7",
        "outer_plaintext_size": len(plaintext),
        "outer_plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "outer_plaintext_signature": _signature(plaintext),
        "starts_ver7": plaintext.startswith(VER7_MAGIC),
    }
    if plaintext.startswith(VER7_MAGIC):
        result["ver7_xor"] = inspect_ver7_xor(plaintext)
    return result


def main() -> int:
    parser = ArgumentParser(description="Analizador experimental SocksIP VER7 + XOR")
    parser.add_argument("file", help="archivo .sip que produce VER7 después de la capa AES")
    parser.add_argument(
        "--decode",
        action="store_true",
        help="imprime la configuración sólo si la ruta termina en JSON o serialización Java válida",
    )
    args = parser.parse_args()

    try:
        file_data = Path(args.file).read_bytes()
        plaintext = decode_outer_layer(file_data)
        if args.decode:
            parsed, route = decode_ver7_xor_profile(plaintext)
            print(json.dumps({"route": route, "data": parsed}, indent=4, ensure_ascii=False))
        else:
            print(json.dumps(inspect_sip_file(file_data), indent=4, ensure_ascii=False))
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"No se pudo resolver la hipótesis VER7/XOR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main())

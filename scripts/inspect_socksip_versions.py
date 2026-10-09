#!/usr/bin/env python3
"""Read-only structural SocksIP .sip envelope diagnostics.

Shared layers are decoded using the production Python implementation.
For VER6/VER7, do not infer a cipher from its version marker or claim
a decoded profile: only bounded format measurements are returned.
No decrypted profile values, tokens, or raw key material are printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

from decoders.Python.sockip import (
    MAX_SERIALIZED_SIZE,
    SIP_STREAM_MAGIC,
    SIP_VER8_KEY,
    _JavaObjectReader,
    _decode_outer_base64,
    _decrypt_aes_ecb,
)

# Existing formats use exactly four marker bytes (VER6/VER7/VER8).
# Never greedily consume digits from the following encrypted nonce/ciphertext.
_VER = re.compile(rb"^VER([0-9])")
_ASCII_HEX = re.compile(rb"^[0-9a-fA-F]+$")
_ASCII_B64 = re.compile(rb"^[A-Za-z0-9+/=_-]+$")
_MAX_FILE = 4 * 1024 * 1024


def _shape(payload: bytes) -> dict[str, Any]:
    """Describe a payload's encoding shape without disclosing bytes."""
    compact = b"".join(payload.split())
    return {
        "payload_size": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "hex_text_candidate": bool(compact and len(compact) % 2 == 0
                                   and _ASCII_HEX.fullmatch(compact)),
        "base64_text_candidate": bool(compact and _ASCII_B64.fullmatch(compact)),
        "java_stream_magic": payload.startswith(SIP_STREAM_MAGIC),
        "gzip_magic": payload.startswith(b"\x1f\x8b"),
        "zip_magic": payload.startswith(b"PK\x03\x04"),
        "zlib_header_candidate": payload.startswith(
            (b"\x78\x01", b"\x78\x9c", b"\x78\xda")),
    }


def _verify_java(data: bytes) -> bool:
    try:
        parsed = _JavaObjectReader(data).read()
        return isinstance(parsed, dict)
    except (ValueError, KeyError, IndexError, TypeError, OverflowError):
        return False


def inspect_sip(raw: bytes) -> dict[str, Any]:
    """Fingerprint structural variant without returning decrypted content."""
    if not raw or len(raw) > _MAX_FILE:
        raise ValueError("El archivo .sip está vacío o excede el tamaño permitido")
    outer = _decrypt_aes_ecb(_decode_outer_base64(raw))
    if len(outer) > MAX_SERIALIZED_SIZE:
        raise ValueError("La capa exterior .sip excede el límite de tamaño")
    report: dict[str, Any] = {
        "format": ".sip",
        "outer_layer": "Base64 -> AES-128-ECB -> PKCS#7",
        "outer_valid": True,
        "outer_size": len(outer),
        "outer_sha256": hashlib.sha256(outer).hexdigest(),
    }
    if outer.startswith(SIP_STREAM_MAGIC):
        report.update({
            "version": "legacy-java",
            "parse_supported": _verify_java(outer),
            "decode_method": "Java Object Serialization",
        })
        return report

    match = _VER.match(outer)
    if not match:
        report.update({
            "version": "unidentified",
            "parse_supported": False,
            "next_step": "Identificar cabecera interna del exportador",
        })
        return report

    number = match.group(1).decode("ascii")
    prefix_size = match.end()
    payload = outer[prefix_size:]
    report.update({
        "version": "VER" + number,
        "version_marker_bytes": prefix_size,
        "inner": _shape(payload),
    })
    if number != "8":
        report.update({
            "parse_supported": False,
            "inner_cipher": "unknown",
            "verified_version_method": False,
            "next_step": "Comparar cabecera, nonce, tag y salida de exportador autorizado",
        })
        return report

    if len(payload) < 12 + 16 + len(SIP_STREAM_MAGIC):
        report.update({
            "parse_supported": False,
            "inner_cipher": "AES-256-GCM",
            "authentication": "truncated",
        })
        return report
    nonce, encrypted, tag = payload[:12], payload[12:-16], payload[-16:]
    try:
        cipher = AES.new(SIP_VER8_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(encrypted, tag)
    except ValueError:
        report.update({
            "parse_supported": False,
            "inner_cipher": "AES-256-GCM",
            "authentication": "failed",
        })
        return report

    report.update({
        "inner_cipher": "AES-256-GCM",
        "nonce_bytes": 12,
        "tag_bytes": 16,
        "authentication": "verified",
        "java_stream_magic": plaintext.startswith(SIP_STREAM_MAGIC),
        "parse_supported": _verify_java(plaintext),
    })
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Diagnóstico local sin exposición de credenciales de SocksIP VER6/7/8"
    )
    parser.add_argument("file", type=Path, help="Archivo .sip exportado por el usuario")
    args = parser.parse_args()
    try:
        report = inspect_sip(args.file.read_bytes())
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

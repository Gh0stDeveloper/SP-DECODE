#!/usr/bin/env python3
"""NUR TUNNEL VPN 1.0.8.8 authenticated .solid profile decoder.

Offline, non-interactive entrypoint for the SP-DECODE bot.
Dependencies: pycryptodome and argon2-cffi. Never handles server catalogs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

MAX_INPUT = 16 * 1024 * 1024
MAX_FIELDS = 100000
MAX_DEPTH = 64
EXPORT_SECRET = b"/4ssU0OjjtKH8AheiAxnc3DwSGDzsy+8"
INTERNAL_SECRET = b"NurChickenPowder"
ENCRYPTED_FIELDS = frozenset({
    "Payload", "SNI", "V2rayAddress", "V2rayConfig", "V2rayHost", "V2raySNI",
    "BugDNS", "CustomProxy", "URI", "ServerIPHost", "OVPNUser", "OVPNPass",
    "UDP_obfs", "UDP_user", "CustomCertificate", "SlowDNSHost", "SlowDNSKey",
    "V2rayUUID", "V2rayPath", "H2pass", "DefOVPNUser", "DefOVPNPass",
    "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert",
})
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")


class DecodeError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _text(data: bytes | str) -> str:
    if not isinstance(data, (bytes, str)):
        raise DecodeError("FORMAT_ERROR", "Expected bytes or text.")
    if len(data) > MAX_INPUT:
        raise DecodeError("SIZE_LIMIT", "Input exceeds 16 MiB.")
    try:
        text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
    except UnicodeError:
        raise DecodeError("FORMAT_ERROR", "The encrypted input is not UTF-8.") from None
    text = text.strip().replace("\r", "").replace("\n", "")
    if not text or len(text) > MAX_INPUT or not text.isascii():
        raise DecodeError("FORMAT_ERROR", "Empty or invalid encrypted input.")
    return text


def _envelope(text: str) -> tuple[bytes, bytes, str]:
    if len(text) % 4 == 1 and len(text) >= 61:
        carrier = text[:3] + text[4:]
        secret, mode = EXPORT_SECRET, "export-legacy"
    elif len(text) % 4 == 0 and len(text) >= 60:
        carrier = text
        secret, mode = INTERNAL_SECRET, "nur-internal"
    else:
        raise DecodeError("FORMAT_ERROR", "Unsupported NUR envelope length.")
    if not _BASE64.fullmatch(carrier):
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 envelope.")
    try:
        raw = base64.b64decode(carrier, validate=True)
    except (binascii.Error, ValueError):
        raise DecodeError("FORMAT_ERROR", "Invalid Base64 envelope.") from None
    if len(raw) < 44:
        raise DecodeError("TRUNCATED", "Missing salt, nonce or GCM tag.")
    return raw, secret, mode


def _open(text: str) -> tuple[str, str]:
    raw, secret, mode = _envelope(text)
    salt, nonce = raw[:16], raw[16:28]
    key = hash_secret_raw(secret, salt, time_cost=3, memory_cost=8192,
                          parallelism=1, hash_len=32, type=Type.ID, version=19)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(salt)
    try:
        clear = cipher.decrypt_and_verify(raw[28:-16], raw[-16:])
    except ValueError:
        raise DecodeError("AUTH_FAILED", "NUR GCM authentication failed.") from None
    try:
        return clear.decode("utf-8"), mode
    except UnicodeError:
        raise DecodeError("INVALID_PLAINTEXT", "Authenticated data is not UTF-8.") from None


def _candidate(value: str) -> bool:
    text = value.strip().replace("\r", "").replace("\n", "")
    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return False
    if len(text) < 60 or len(text) % 4 not in (0, 1):
        return False
    carrier = text[:3] + text[4:] if len(text) % 4 == 1 else text
    return bool(_BASE64.fullmatch(carrier))


def _values(document: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    count = 0

    def visit(node: Any, depth: int = 0, field: str = "") -> Any:
        nonlocal count
        count += 1
        if count > MAX_FIELDS or depth > MAX_DEPTH:
            raise DecodeError("STRUCTURE_LIMIT", "JSON structure limit exceeded.")
        if isinstance(node, dict):
            return {key: visit(value, depth + 1, key) for key, value in node.items()}
        if isinstance(node, list):
            return [visit(value, depth + 1, field) for value in node]
        if isinstance(node, str) and field in ENCRYPTED_FIELDS and _candidate(node):
            plain, _ = _open(_text(node))
            audit["decrypted_fields"] += 1
            return plain
        return node

    return visit(document)


def decode(data: bytes | str, *, decrypt_fields: bool = True,
           audit: dict[str, Any] | None = None) -> dict[str, Any]:
    plain, mode = _open(_text(data))
    try:
        document = json.loads(plain)
    except (ValueError, RecursionError):
        raise DecodeError("INVALID_JSON", "Authenticated data is not a JSON document.") from None
    if not isinstance(document, dict):
        raise DecodeError("INVALID_JSON", "Expected a JSON object.")
    info = {"outer_mode": mode, "outer_authenticated": True, "decrypted_fields": 0}
    if decrypt_fields:
        document = _values(document, info)
    if not isinstance(document.get("Name"), str) or not isinstance(document.get("TunnelType"), str):
        raise DecodeError("WRONG_DOCUMENT", "Expected a NUR .solid profile.")
    if audit is not None:
        audit.update(info)
    return document


def run(data: bytes | str) -> str:
    return json.dumps(decode(data), ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="NUR TUNNEL .solid profile decoder")
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--outer-only", action="store_true")
    args = parser.parse_args()
    try:
        with args.file.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        result = json.dumps(decode(raw, decrypt_fields=not args.outer_only), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            sys.stdout.write(result)
        return 0
    except (DecodeError, OSError) as error:
        code = error.code if isinstance(error, DecodeError) else "IO_ERROR"
        message = str(error) if isinstance(error, DecodeError) else "Cannot read or write the file."
        print(json.dumps({"error": code, "message": message}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Additional locally decipherable text links from the authorized 66.py.

Each family retains its original source algorithm: NetMod/AR use
AES-ECB/PKCS7, PB uses AES-CBC with trailing NULs, Howdy uses an
outer Base64 JSON with optional AES-CBC internal fields, and ZIVPN
uses AES-CBC with SHA256(password). This module makes no network calls.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from urllib.parse import parse_qs, unquote

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MAX_TEXT_SIZE = 2 * 1024 * 1024

NETMOD_MODES = (
    "dns", "vless", "vmess", "trojan", "socks", "ss",
    "ssr", "ssh", "xray-json", "wireguard", "trojan-go",
)
AR_MODES = (
    "dns", "vless", "vmess", "trojan", "ssr", "socks",
    "trojan-go", "ssh", "ss",
)
PB_MODES = ("ssh", "vless", "vmess", "trojan", "socks", "ss")
NM_PREFIXES = tuple(f"nm-{p}://" for p in NETMOD_MODES)
AR_PREFIXES = tuple(f"ar-{p}://" for p in AR_MODES)
PB_PREFIXES = tuple(f"pb-{p}://" for p in PB_MODES)
HOWDY_PREFIXES = ("howdy://", "n7pr://", "mark://")
ZIV_PREFIX = "zivpn://"
ALL_PREFIXES = NM_PREFIXES + AR_PREFIXES + PB_PREFIXES + HOWDY_PREFIXES + (ZIV_PREFIX,)

_NM_KEYS = (b"<n3t5yn4^n3tm0d>", b"_netsyna_netmod_", b"nicetrybuddygoon")
_AR_KEY = base64.b64decode("YXJ0dW5uZWw3ODc5Nzg5eA==")
_PB_KEY = b"4p+ocx+hGTnbDdHOmzQCjVb9KTTSh+A3"
_PB_IV = b"android123456789"
_HOWDY_KEY = b"poiuytrewqas+=~|"
_HOWDY_IV = b"r4tgv3b2zcmdW6ZZ"
_ZIV_PASSWORD = base64.b64decode(
    "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ="
).decode("utf-8")


def _payload(text: str, schemes: tuple[str, ...]) -> tuple[str, str] | None:
    if not isinstance(text, str) or not 0 < len(text) <= MAX_TEXT_SIZE:
        return None
    data = text.strip()
    prefix = next((p for p in schemes if data.lower().startswith(p)), None)
    if prefix is None:
        return None
    value = data[len(prefix):].strip()
    return (prefix, value) if value else None


def _base64(token: str) -> bytes:
    compact = "".join(token.split()).replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    if not compact or len(compact) > MAX_TEXT_SIZE:
        raise ValueError("Invalid text payload")
    return base64.b64decode(compact, validate=True)


def _render(clear: str) -> str | None:
    if not clear or not clear.strip():
        return None
    try:
        item = json.loads(clear)
        if isinstance(item, (dict, list)):
            return json.dumps(item, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        pass
    return clear


def _aes_ecb(token: str, keys: tuple[bytes, ...]) -> str | None:
    try:
        ciphertext = _base64(token)
        if not ciphertext or len(ciphertext) % 16:
            return None
        for key in keys:
            try:
                plain = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16)
                decoded = plain.decode("utf-8")
                if not decoded.strip():
                    continue
                # Never falsely report arbitrary UTF-8 as a decrypted config.
                if (decoded.lstrip().startswith(("{", "[")) or "://" in decoded
                        or "=" in decoded or "@" in decoded):
                    return _render(decoded)
            except (ValueError, UnicodeError):
                continue
    except (ValueError, binascii.Error):
        pass
    return None


def decode_netmod(text: str) -> str | None:
    pair = _payload(text, NM_PREFIXES)
    if pair is None:
        return None
    return _aes_ecb(pair[1], _NM_KEYS)


def decode_ar(text: str) -> str | None:
    pair = _payload(text, AR_PREFIXES)
    if pair is None:
        return None
    return _aes_ecb(pair[1], (_AR_KEY,))


def decode_pb(text: str) -> str | None:
    pair = _payload(text, PB_PREFIXES)
    if pair is None:
        return None
    try:
        ciphertext = _base64(pair[1])
        if not ciphertext or len(ciphertext) % 16:
            return None
        plain = AES.new(_PB_KEY, AES.MODE_CBC, _PB_IV).decrypt(ciphertext)
        # Source 66.py used .rstrip(b'\\0'), not a PKCS#7 unpad.
        clear = plain.rstrip(b"\0").decode("utf-8")
        if pair[0] == "pb-vmess://":
            try:
                clear = _base64(clear).decode("utf-8")
            except (ValueError, UnicodeError):
                return None
        if clear.lstrip().startswith(("{", "[")) or "://" in clear or "=" in clear or "@" in clear:
            return _render(clear)
    except (ValueError, UnicodeError, binascii.Error):
        pass
    return None


def _decrypt_howdy_field(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value
    try:
        ciphertext = _base64(value)
        if not ciphertext or len(ciphertext) % 16:
            return value
        raw = AES.new(_HOWDY_KEY, AES.MODE_CBC, _HOWDY_IV).decrypt(ciphertext)
        try:
            raw = unpad(raw, 16)
        except ValueError:
            raw = raw.rstrip(b"\0").rstrip()
        return raw.decode("utf-8")
    except (ValueError, UnicodeError):
        return value


def decode_howdy(text: str) -> str | None:
    pair = _payload(text, HOWDY_PREFIXES)
    if pair is None:
        return None
    try:
        payload = _base64(pair[1])
        decoded = json.loads(payload.decode("utf-8"))
        if not isinstance(decoded, (dict, list)):
            return None
        if isinstance(decoded, dict):
            # Legacy Howdy only encrypts server/SNI; preserve all other fields.
            for key in ("server", "sni"):
                if key in decoded:
                    decoded[key] = _decrypt_howdy_field(decoded[key])
        return json.dumps(decoded, ensure_ascii=False, indent=2)
    except (ValueError, TypeError, UnicodeError):
        pass
    # 66.py also supported an entire JSON document encrypted using
    # the same static AES-CBC key and IV.
    try:
        decoded = json.loads(_decrypt_howdy_field(pair[1]))
        return json.dumps(decoded, ensure_ascii=False, indent=2) if isinstance(decoded,(dict,list)) else None
    except (ValueError, TypeError):
        return None


def decode_zivpn(text: str) -> str | None:
    pair = _payload(text, (ZIV_PREFIX,))
    if pair is None:
        return None
    try:
        encrypted = _base64(pair[1])
        if not encrypted or len(encrypted) % 16:
            return None
        key = hashlib.sha256(_ZIV_PASSWORD.encode("utf-8")).digest()
        plain = unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(encrypted),16)
        result = plain.decode("utf-8")
        return _render(result)
    except (ValueError, UnicodeError):
        return None


def decode_text(text: str) -> str | None:
    if not isinstance(text,str):
        return None
    lower = text.strip().lower()
    if lower.startswith(NM_PREFIXES):
        return decode_netmod(text)
    if lower.startswith(AR_PREFIXES):
        return decode_ar(text)
    if lower.startswith(PB_PREFIXES):
        return decode_pb(text)
    if lower.startswith(HOWDY_PREFIXES):
        return decode_howdy(text)
    if lower.startswith(ZIV_PREFIX):
        return decode_zivpn(text)
    return None

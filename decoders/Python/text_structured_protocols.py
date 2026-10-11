#!/usr/bin/env python3
"""Structured VPN text import links from 66.py, without network access.

Unlike encrypted file exports, Creeb and many import links are Base64,
JSON, or already plaintext data. Preserve all metadata; label formats
honestly rather than reporting simple decoding as AES decryption.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any

MAX_TEXT_SIZE = 2 * 1024 * 1024

PREFIXES = (
    "flex://", "flexnet://", "npvs://", "vpvs://",
    "v2box://", "kivuvpn://", "slipnet://", "vmess://",
)
LINK_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic|socks)://"
    r"[^\s\"'<>\\]+",
    re.IGNORECASE,
)


def _b64(value: str) -> bytes:
    chars = "".join(value.split()).replace("-", "+").replace("_", "/")
    if not chars or len(chars) > 4 * MAX_TEXT_SIZE // 3 + 16:
        raise ValueError("Invalid Base64 input")
    chars += "=" * (-len(chars) % 4)
    return base64.b64decode(chars, validate=True)


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def decode_flex(text: str) -> str | None:
    from decoders.Python.flex import run as decode_file
    if not isinstance(text, str) or len(text) > MAX_TEXT_SIZE:
        return None
    prefix = "flexnet://" if text.lower().startswith("flexnet://") else "flex://"
    if not text.lower().startswith(prefix):
        return None
    payload = text[len(prefix):].strip()
    if not payload:
        return None
    if payload.startswith("FLXCFG"):
        binary = payload.encode("utf-8")
    else:
        try:
            binary = _b64(payload)
        except (ValueError, binascii.Error):
            return None
    if not binary.startswith(b"FLXCFG"):
        return None
    return decode_file(binary)


def decode_npvs(text: str) -> str | None:
    from decoders.Python.npvs import decode_npvs_complete as decode_file, DecodeError
    if not isinstance(text, str) or len(text) > MAX_TEXT_SIZE:
        return None
    lower = text.lower()
    if not lower.startswith(("npvs://", "vpvs://")):
        return None
    try:
        raw = _b64(text.split("://", 1)[1].strip())
        if len(raw) > MAX_TEXT_SIZE or not raw.startswith(b"NPVS"):
            return None
        # App-key NPVS v5 already validates signature, body and AEAD tags.
        return _json(decode_file(raw))
    except (ValueError, binascii.Error, DecodeError):
        return None


def decode_slipnet_plain(text: str) -> str | None:
    """66.py treated slipnet:// as a Base64 UTF-8 string, not slipnet-enc://."""
    if not isinstance(text,str) or not text.lower().startswith("slipnet://"):
        return None
    try:
        content = _b64(text.split("://",1)[1].strip()).decode("utf-8")
        if not content.strip():
            return None
        try:
            decoded = json.loads(content)
            if isinstance(decoded,(dict,list)):
                return _json(decoded)
        except ValueError:
            pass
        return _json({"data":content})
    except (ValueError, UnicodeError, binascii.Error):
        return None


def decode_vmess(text: str) -> str | None:
    if not isinstance(text,str) or not text.lower().startswith("vmess://"):
        return None
    try:
        decoded=json.loads(_b64(text[8:].strip()).decode("utf-8"))
        if not isinstance(decoded,dict):
            return None
        return _json(decoded)
    except (ValueError, UnicodeError, binascii.Error):
        return None


def normalize_v2box_envelope(text: str) -> dict | None:
    """Normalize Base64URL both outside and inside a V2Box JSON envelope."""
    if not isinstance(text,str) or not text.lower().startswith("v2box://"):
        return None
    try:
        payload=text[len("v2box://"):].strip()
        decoded=(
            json.loads(payload) if payload.startswith("{")
            else json.loads(_b64(payload).decode("utf-8"))
        )
        if not isinstance(decoded,dict) or decoded.get("magic")!="v2box_export":
            return None
        normalized=dict(decoded)
        for field in ("nonce","tag","ciphertext"):
            token=normalized.get(field)
            if not isinstance(token,str) or not token:
                return None
            normalized[field]=base64.b64encode(_b64(token)).decode("ascii")
        return normalized
    except (ValueError,TypeError,UnicodeError,binascii.Error):
        return None


def decode_v2box(text: str) -> str | dict | None:
    from decoders.Python.v2box_export import decrypt_v2box_data
    if not isinstance(text,str) or not text.lower().startswith("v2box://"):
        return None
    if len(text) > MAX_TEXT_SIZE:
        return None
    # Traditional V2Box share links contain a 'locked=' Base64 encoded URL.
    if "locked=" in text.lower():
        encoded = text.lower().find("locked=")
        token=text[encoded + len("locked="):].strip()
        try:
            decoded=_b64(token).decode("utf-8")
            parsed=urllib.parse.urlsplit(decoded)
            if not parsed.scheme or not parsed.netloc:
                return None
            # Parse all repeated parameters; preserve URL and fragment.
            params=urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            return _json({
                "url": decoded,
                "scheme": parsed.scheme,
                "host": parsed.hostname,
                "port": parsed.port,
                "parameters": params,
                "notes": urllib.parse.unquote(parsed.fragment),
            })
        except (ValueError, UnicodeError, binascii.Error):
            return None
    # V2Box export envelopes can use Base64URL for outer JSON AND for
    # each GCM component. The historical file engine expects RFC4648.
    try:
        normalized = normalize_v2box_envelope(text)
        if normalized is None:
            return None
        decoded = decrypt_v2box_data(json.dumps(
            normalized, ensure_ascii=False, separators=(",", ":")
        ))
    except (ValueError, UnicodeError, TypeError, binascii.Error):
        return None
    if isinstance(decoded,dict) and decoded.get("__need_password__"):
        # Caller must request the password privately, not print cipher internals.
        return {"__need_password__": True}
    return _json(decoded) if isinstance(decoded,dict) else None


def decode_kivu(text: str) -> str | None:
    from decoders.Python.DARKTUNNEL import run
    if not isinstance(text,str) or not text.lower().startswith("kivuvpn://"):
        return None
    if len(text) > MAX_TEXT_SIZE:
        return None
    try:
        return run(text.encode("utf-8"))
    except (ValueError, UnicodeError):
        return None


def is_creeb(text: str) -> bool:
    if not isinstance(text,str) or len(text)>MAX_TEXT_SIZE or not text.lstrip().startswith("{"):
        return False
    # Avoid matching arbitrary JSON with a nested string named creeb_profile_bundle.
    try:
        data=json.loads(text)
        return isinstance(data,dict) and data.get("type")=="creeb_profile_bundle"
    except (ValueError,TypeError):
        return False


def decode_creeb(text: str) -> str | None:
    """Retain complete original bundle and extract every profile's V2Ray links."""
    if not is_creeb(text):
        return None
    data=json.loads(text)
    profiles=data.get("profiles",[])
    if not isinstance(profiles,list) or len(profiles)>10000:
        return None
    processed=[]
    for item in profiles:
        if not isinstance(item,dict):
            continue
        links=[]
        seen=set()
        prefs=item.get("prefs")
        # 66.py checked prefs first, then a JSON-serialized whole profile.
        sources=[v for v in prefs.values() if isinstance(v,str)] if isinstance(prefs,dict) else []
        sources.append(json.dumps(item,ensure_ascii=False))
        for value in sources:
            for match in LINK_RE.finditer(value):
                link=match.group(0)
                if link not in seen:
                    seen.add(link)
                    links.append(link)
        processed.append({
            "name":item.get("name",""),"hostPort":item.get("hostPort",""),
            "tunnelType":item.get("tunnelType",""),"links":links,
        })
    return _json({"type":data.get("type"),"version":data.get("version",1),
                  "message":data.get("message",""),"security":data.get("security",{}),
                  "profiles":processed,"original_bundle":data})


def decode_text(text: str) -> str | dict | None:
    if not isinstance(text,str) or not text or len(text)>MAX_TEXT_SIZE:
        return None
    value=text.strip()
    low=value.lower()
    if low.startswith(("flex://","flexnet://")):
        return decode_flex(value)
    if low.startswith(("npvs://","vpvs://")):
        return decode_npvs(value)
    if low.startswith("slipnet://"):
        return decode_slipnet_plain(value)
    if low.startswith("vmess://"):
        return decode_vmess(value)
    if low.startswith("v2box://"):
        return decode_v2box(value)
    if low.startswith("kivuvpn://"):
        return decode_kivu(value)
    if is_creeb(value):
        return decode_creeb(value)
    return None

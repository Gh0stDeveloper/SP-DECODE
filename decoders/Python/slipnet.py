#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot file decoder, derived from authorized 66.py."""
from __future__ import annotations
import base64
import binascii
import gzip
import hashlib
import html
import json
import logging
import re
import struct
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)

def parse_slipnet_enc_data(decrypted_text: str) -> dict:
    """Convert decrypted pipe-separated slipnet-enc text to an ordered dict."""
    parts = decrypted_text.split("|")

    def get(i):
        return parts[i] if 0 <= i < len(parts) else ""

    data = {
        "version":             get(0),
        "tunnel_type":         get(1) or get(21),
        "name":                get(2),
        "domain":              get(3),
        "keepalive":           get(6),
        "congestion":          get(7),
        "tcp_port":            get(8),
        "tcp_host":            get(9),
        "gso":                 get(5),
        "dnstt_key":           get(4),
        "ssh_enabled":         get(16),
        "ssh_user":            get(14),
        "ssh_pass":            get(15),
        "ssh_port":            get(17),
        "ssh_host":            get(18),
        "dns_transport":       get(22),
        "ssh_auth_type":       get(23),
        "naive_port":          get(24),
        "hwid":                get(25),
        "expiry_timestamp":    get(26),
        "locked":              get(33),
        "authoritative_mode":  get(34),
        "resolvers":           get(27),
        "local_port":          get(36),
        "dns_record_type":     get(37),
        "proxy_port":          get(38),
        "load_balance_mode":   get(39),
        "tls_mode":            get(40),
        "transport":           get(20),
        "ws_path":             get(41) or "/",
        "tls_port":            get(28) or get(35) or "",
        "sni_mode":            get(42) or "sni_split",
        "mux_concurrency":     get(43) or "8",
    }

    return {k: v for k, v in data.items() if v not in ("", None)}


def decrypt_slipnet_enc_data(encrypted_input) -> dict:
    """Decrypt slipnet-enc data."""
    try:
        if isinstance(encrypted_input, str):
            encrypted_input = encrypted_input.encode('utf-8')

        if encrypted_input.startswith(b'slipnet-enc://'):
            encrypted_input = encrypted_input.split(b'://', 1)[1]

        try:
            data_bytes = base64.b64decode(encrypted_input)
        except Exception:
            data_bytes = encrypted_input

        AES_KEY = bytes.fromhex("214f052025b2f949605a5429ec3d5fa80c2022c168ad946e68852d447214dbd3")
        IV_LENGTH = 12
        TAG_LENGTH = 16

        try:
            iv = data_bytes[1:1 + IV_LENGTH]
            ct_tag = data_bytes[1 + IV_LENGTH:]
            ct, tag = ct_tag[:-TAG_LENGTH], ct_tag[-TAG_LENGTH:]
            cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=iv)
            decrypted = cipher.decrypt_and_verify(ct, tag).decode()
        except Exception:
            iv = data_bytes[:IV_LENGTH]
            ct_tag = data_bytes[IV_LENGTH:]
            ct, tag = ct_tag[:-TAG_LENGTH], ct_tag[-TAG_LENGTH:]
            cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=iv)
            decrypted = cipher.decrypt_and_verify(ct, tag).decode()

        data_dict = parse_slipnet_enc_data(decrypted)
        return {"status": "success", "data": data_dict}
    except Exception as e:
        return {"status": "error", "message": str(e)}
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    result=decrypt_slipnet_enc_data(data)
    if result.get("status")!="success":
        return None
    return json.dumps(result["data"],ensure_ascii=False,indent=2)

def main():
    if len(sys.argv) != 2:
        print("Usage: python slipnet.py <config-file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.name.lower().endswith(".slipnet"):
        print("Unsupported extension", file=sys.stderr)
        return 2
    try:
        raw = path.read_bytes()
        output = run(raw)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if output is None:
        print("Unable to decode configuration", file=sys.stderr)
        return 1
    print(output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

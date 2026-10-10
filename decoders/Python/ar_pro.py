#!/usr/bin/env python3
"""One standalone SP-DECODE bot file decoder sourced from authorized 66.py."""
from __future__ import annotations
import base64
import binascii
import gzip
import hashlib
import html
import json
import logging
import re
import string
import struct
import sys
from pathlib import Path
from dataclasses import dataclass
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger=logging.getLogger(__name__)

@dataclass(frozen=True, slots=True)
class AesKey:
    name: str
    key: bytes
    iv: bytes
    mode: int
    segment_size: int | None = None

    @classmethod
    def from_hex(cls, name, key_hex, iv_hex, mode, *, segment_size=None):
        return cls(name, binascii.unhexlify(key_hex), binascii.unhexlify(iv_hex), mode, segment_size)

MAIN_KEY = AesKey.from_hex("MAIN_CBC_PKCS7", "496f8d4107be912a6b3b23057dd5ffafaa999bdf77c6a53d1b49b6b0fc555333", "00000000000000000000000000000000", AES.MODE_CBC)
FIELD_KEY = AesKey.from_hex("FIELD_CFB", "d4b28c7cc782e7b756718e84cdb4ff4ba79a3a3cb2ddbec55b8c235853e22dca", "0123456789abcdef1032547698badcfe", AES.MODE_CFB, segment_size=128)
ENCRYPTED_FIELD_NAMES = ("Payload", "WSPayload", "SNIHost", "BUGHost", "DNSHost", "ProxySet", "UDPhost", "UDPobfs", "UDPauth", "V2Ejson", "v2Esni", "EwgConf", "Server")
OWNER = "@DECRYPTFILE1"

# ---------- فك التشفير ----------
class DecryptionError(Exception): pass

class ARProDecoder:
    @staticmethod
    def _unpad_pkcs7(data: bytes) -> bytes:
        if not data: return data
        pad_len = data[-1]
        return data[:-pad_len] if 1 <= pad_len <= 16 else data

    @staticmethod
    def _decrypt(ciphertext_b64: str, key_spec: AesKey) -> bytes | None:
        try:
            raw = base64.b64decode(ciphertext_b64, validate=True)
        except Exception:
            return None
        try:
            kwargs = {"iv": key_spec.iv}
            if key_spec.segment_size:
                kwargs["segment_size"] = key_spec.segment_size
            cipher = AES.new(key_spec.key, key_spec.mode, **kwargs)
            plain = cipher.decrypt(raw)
            if key_spec.mode == AES.MODE_CBC:
                plain = ARProDecoder._unpad_pkcs7(plain)
            return plain
        except Exception:
            return None

    @staticmethod
    def _decrypt_utf8(ciphertext_b64: str, key_spec: AesKey) -> str | None:
        data = ARProDecoder._decrypt(ciphertext_b64, key_spec)
        if data is None: return None
        try:
            return data.decode("utf-8", errors="ignore").rstrip("\x00\x0f\x10")
        except Exception:
            return None

    @staticmethod
    def _try_decrypt_field(value: str) -> str | None:
        if not value or len(value) < 4: return None
        res = ARProDecoder._decrypt_utf8(value, FIELD_KEY)
        if res and any(c.isprintable() for c in res): return res
        res = ARProDecoder._decrypt_utf8(value, MAIN_KEY)
        return res

    @classmethod
    def decrypt(cls, encrypted_b64: str) -> dict[str, Any]:
        # محاولة فك الطبقة الخارجية
        outer = cls._decrypt_utf8(encrypted_b64, MAIN_KEY)
        config = None
        if outer:
            try: config = json.loads(outer)
            except: pass
        if not config:
            try: config = json.loads(encrypted_b64)
            except:
                try: config = json.loads(base64.b64decode(encrypted_b64).decode('utf-8'))
                except: raise DecryptionError("لا يمكن تفسير المدخلات كـ JSON صالح.")
        # فك الحقول الداخلية
        for field in ENCRYPTED_FIELD_NAMES:
            if field in config and isinstance(config[field], str) and config[field]:
                dec = cls._try_decrypt_field(config[field])
                if dec: config[field] = dec
        return config
def run(data:bytes)->str|None:
    if not data or len(data)>2*1024*1024:
        return None
    content=data.decode("utf-8",errors="replace").strip()
    if "://" in content:
        content=content.split("://",1)[1]
    try:
        decoded=ARProDecoder.decrypt(content)
    except (DecryptionError,ValueError,TypeError):
        return None
    if not isinstance(decoded,dict):
        return None
    return json.dumps(decoded,ensure_ascii=False,indent=2)

def main():
    if len(sys.argv)!=2:
        print("Usage: python ar.py <config-file>",file=sys.stderr)
        return 2
    filename=Path(sys.argv[1])
    try:
        result=run(filename.read_bytes())
    except (OSError,ValueError) as exc:
        print(str(exc),file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decode configuration",file=sys.stderr)
        return 1
    print(result)
    return 0
if __name__=="__main__":
    raise SystemExit(main())

"""Deterministic authorized-synthetic inputs for the A.2.3 Linux golden suite.

Input generators are **not** production exporters and do not assert compatibility
with current third-party apps. No personal credentials, servers or tokens.
Only the golden suite imports decoders. Android has not been implemented.
"""
from __future__ import annotations

import base64
import json
from typing import Callable

from Crypto.Cipher import AES, ChaCha20
import msgpack

from decoders.Python.EV2RAY import AES_KEYS, DELIMITER, XOR_KEY
from decoders.Python.SSCCUSTOM import SSCConstants
from decoders.Python.DARKTUNNEL import DTConstants
from tests.test_current_decoders import _tls_fixture

FIXTURE_DOMAIN = "example.org"  # RFC 2606 reserved domain
FIXTURE_USER = "dummy-user"
FIXTURE_PASSWORD = "dummy-not-a-real-secret"

def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def tls_bytes() -> bytes:
    """Uses existing synthetic AEAD test vector, including TLS URI prefix."""
    return b"tls://" + _tls_fixture()


def ev2ray_profile(*, encrypted: bool) -> bytes:
    """Construct plain and encrypted e-V2Ray containers reproducibly."""
    inner_json = '{"v":"2","ps":"SP-DECODE test","add":"v2.example.com","port":"443"}'
    plaintext = DELIMITER.join((_b64("Perfil e-V2Ray"), _b64(inner_json), "true")).encode("utf-8")
    if not encrypted:
        return plaintext
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len]) * pad_len
    aes_bytes = AES.new(AES_KEYS[0], AES.MODE_ECB).encrypt(padded)
    ascii_b64 = base64.b64encode(aes_bytes)
    return bytes(x ^ XOR_KEY[i % len(XOR_KEY)] for i, x in enumerate(ascii_b64))


def ssc_bytes() -> bytes:
    """Single-layer SSC configuration using the known testable local envelope."""
    payload = {
        "a": [{
            "e": "A23 synthetic profile",
            "l": FIXTURE_DOMAIN,
            "m": 443,
            "p": FIXTURE_PASSWORD,
        }],
        "b": "Offline test",
    }
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    cipher = ChaCha20.new(key=SSCConstants.L1_KEY, nonce=SSCConstants.FIXED_NONCE)
    cipher.seek(64)
    return cipher.encrypt(compact).hex().encode("ascii")


def dark_bytes() -> bytes:
    """Synthetic Dark Tunnel envelope without any real customer secrets."""
    msg = msgpack.packb({"Server": FIXTURE_DOMAIN, "Port": 443}, use_bin_type=True)
    encrypted = AES.new(
        DTConstants.KEY_256, AES.MODE_CFB, iv=DTConstants.IV, segment_size=128
    ).encrypt(msg)
    outer = {
        "name": "A23 synthetic",
        "encryptedLockedConfig": base64.b64encode(encrypted).decode("ascii"),
        "testVersion": 1,
    }
    return base64.b64encode(
        json.dumps(outer, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


SYNTHETIC_GENERATORS: dict[str, Callable[[], bytes]] = {
    "tls-aesgcm": tls_bytes,
    "ev2ray-plain": lambda: ev2ray_profile(encrypted=False),
    "ev2ray-aes128": lambda: ev2ray_profile(encrypted=True),
    "ssc-chacha20": ssc_bytes,
    "dark-aescfb-msgpack": dark_bytes,
}

"""Deterministic authorized-synthetic inputs for the A.2.3 Linux golden suite.

Input generators are **not** production exporters and do not assert compatibility
with current third-party apps. No personal credentials, servers or tokens.
Only the golden suite imports decoders. Android has not been implemented.
"""
from __future__ import annotations

import base64
import json
import struct
import zlib
from typing import Callable

from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad
import msgpack

from decoders.Python.EV2RAY import AES_KEYS, DELIMITER, XOR_KEY
from decoders.Python.SSCCUSTOM import SSCConstants
from decoders.Python.DARKTUNNEL import DTConstants
from decoders.Python.HTTPINJECTORLITE import HTTPInjectorLiteConstants
from decoders.Python.HTTPCUSTOM import HCConstants
from decoders.Python.HTTPTWEAK import _TABLES, BLOCK_SIZE, ROUNDS
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



def ehil_bytes() -> bytes:
    """Full synthetic EHIL binary container with two AES-CBC ciphertext layers."""
    constants = HTTPInjectorLiteConstants
    plain = json.dumps(
        {"configSalt": "EVZJNI", "profileName": "A23 synthetic", "serverPort": 443},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    second_layer = AES.new(
        constants.LAYER_TWO_KEYS[0], AES.MODE_CBC, constants.IVS[0]
    ).encrypt(pad(plain, 16))
    envelope = b"prefix:" + base64.b64encode(second_layer)
    first_layer = AES.new(
        constants.LAYER_ONE_KEYS[0], AES.MODE_CBC, constants.IVS[0]
    ).encrypt(pad(envelope, 16))
    extra = b"synthetic"
    return (
        struct.pack(">H", 4) + b"ehil" + bytes(8)
        + struct.pack(">H", len(extra)) + extra + bytes(8)
        + struct.pack(">I", len(first_layer)) + bytes(8) + first_layer
    )


# Reserved-only synthetic JSON, not a profile exported by the vendor.
TWEAK_PROFILE = {
    "name": "A23 offline synthetic",
    "server": "example.org",
    "port": 443,
    "enabled": True,
}


def httptweak_bytes(variant: int) -> bytes:
    """Forward-encrypt zlib JSON with HTTP Tweak's versioned 12-round tables.

    Encryption is implemented independently from decrypt_profile_bytes, so
    the positive golden exercises the full reverse cipher and CBC pipeline.
    """
    if variant not in (1, 2):
        raise ValueError("Only the audited variants 1 and 2 are synthesized")
    round_keys, permutations, substitutions, _ = _TABLES[variant]
    clear = json.dumps(TWEAK_PROFILE, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    compressed = zlib.compress(clear)
    payload = compressed + bytes((-len(compressed)) % BLOCK_SIZE)
    iv = bytes(range(BLOCK_SIZE))
    previous = iv
    blocks = []
    for offset in range(0, len(payload), BLOCK_SIZE):
        block = payload[offset:offset + BLOCK_SIZE]
        state = bytes(value ^ previous[i] for i, value in enumerate(block))
        for round_index in range(ROUNDS):
            base = round_index * BLOCK_SIZE
            substituted = [
                substitutions[round_index * 256 + value] for value in state
            ]
            state = bytes(
                substituted[permutations[base + i] & 0x0F] ^ round_keys[base + i]
                for i in range(BLOCK_SIZE)
            )
        blocks.append(state)
        previous = state
    return base64.b64encode(bytes([variant]) + iv + b"".join(blocks))


def httpcustom_bytes() -> bytes:
    """Forward-encode a minimal HTTP Custom *new-format* container.

    Input uses its actual ChaCha20/outer XOR and RST AES-ECB layers. Tokens
    are intentionally public dummy values, not meaningful VPN credentials.
    """
    tokens = "[splitConfig]".join(
        ("GET", "example.org", "false", "true", "0")
    ).encode("utf-8")
    aes_bytes = AES.new(
        HCConstants.RST_KEYS[0], AES.MODE_ECB
    ).encrypt(pad(tokens, 16))
    enc_b64 = base64.b64encode(aes_bytes)
    rst_ciphertext = bytes(
        value ^ HCConstants.RST_XOR_KEY[i % len(HCConstants.RST_XOR_KEY)]
        for i, value in enumerate(enc_b64)
    ).decode("ascii")
    json_bytes = json.dumps(
        {"cfg": {"content": rst_ciphertext}},
        separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    cha = ChaCha20.new(
        key=HCConstants.CHACHA_KEYS[5], nonce=HCConstants.STATIC_NONCE
    )
    cha.seek(64)
    outer_hex = (cha.encrypt(json_bytes) + bytes(16)).hex().encode("ascii")
    magic = bytes.fromhex("e382e4b8adc386f09f9293")
    raw = bytes(x ^ magic[i % len(magic)] for i, x in enumerate(outer_hex))
    # HTTP Custom's reader converts decoded UTF-8 characters to Latin-1;
    # re-encode the ciphertext as valid UTF-8 to retain all original bytes.
    return raw.decode("latin-1").encode("utf-8")


SYNTHETIC_GENERATORS: dict[str, Callable[[], bytes]] = {
    "tls-aesgcm": tls_bytes,
    "httptweak-v1-ht": lambda: httptweak_bytes(1),
    "httptweak-v2-htb": lambda: httptweak_bytes(2),
    "httpcustom-chacha-rst": httpcustom_bytes,
    "ehil-aescbc-double": ehil_bytes,
    "ev2ray-plain": lambda: ev2ray_profile(encrypted=False),
    "ev2ray-aes128": lambda: ev2ray_profile(encrypted=True),
    "ssc-chacha20": ssc_bytes,
    "dark-aescfb-msgpack": dark_bytes,
}

"""Shared decoder for current NoobCrypt-based VPN profile containers."""

from __future__ import annotations

import base64
import json
from typing import Any


KEYS = {
    "maya": bytes.fromhex(
        "360b82639d6fb4642dc69a1e7b9c720644f9227c7c2f1cc6da14ba9a7dcfead0"
    ),
    "xui": bytes.fromhex(
        "721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c"
    ),
}


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES  # type: ignore

        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad_pkcs7(plaintext)


def _decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES  # type: ignore

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).decrypt(nonce, ciphertext + tag, None)


def _try_decrypt_inner_string(value: str, key: bytes) -> str:
    """Open a NoobCrypt mode-0 value, or return the original string.

    Current Maya/XUI exports use Base64(nonce[12] + ciphertext + tag[16]) for
    sensitive JSON fields. AES-GCM authentication makes probing safe: an
    ordinary Base64-looking value is preserved unless its tag is valid.
    """
    encoded = "".join(value.split())
    if len(encoded) < 36:
        return value
    encoded += "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception:
        return value
    if len(raw) < 28:
        return value
    try:
        plaintext = _decrypt_aes_gcm(raw[12:-16], key, raw[:12], raw[-16:])
        return plaintext.decode("utf-8")
    except Exception:
        return value


def _decode_inner_values(value: Any, key: bytes) -> Any:
    if isinstance(value, dict):
        return {name: _decode_inner_values(item, key) for name, item in value.items()}
    if isinstance(value, list):
        return [_decode_inner_values(item, key) for item in value]
    if isinstance(value, str) and value:
        return _try_decrypt_inner_string(value, key)
    return value


def decrypt_profile(file_bytes: bytes, variant: str) -> dict[str, Any]:
    """Decode the AES-CBC profile and authenticated inner field values."""
    try:
        key = KEYS[variant]
    except KeyError as exc:
        raise ValueError(f"variante NoobCrypt desconocida: {variant}") from exc

    encoded = b"".join(file_bytes.split())
    if not encoded:
        raise ValueError("archivo vacío")
    encoded += b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("Base64 exterior inválido") from exc

    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise ValueError("contenedor AES-CBC incompleto")

    plaintext = _decrypt_aes_cbc(raw[16:], key, raw[:16]).decode("utf-8")
    json_start = plaintext.find("{")
    if json_start < 0:
        raise ValueError("no se encontró el objeto JSON")

    try:
        payload, consumed = json.JSONDecoder().raw_decode(plaintext[json_start:])
    except json.JSONDecodeError as exc:
        raise ValueError("JSON descifrado inválido") from exc
    if not isinstance(payload, dict):
        raise ValueError("la configuración descifrada no es un objeto")
    if plaintext[json_start + consumed :].strip():
        raise ValueError("datos inesperados después del JSON")
    return _decode_inner_values(payload, key)


def format_result(app_name: str, extension: str, payload: dict[str, Any]) -> str:
    rendered = json.dumps(payload, indent=4, ensure_ascii=False, default=str)
    return (
        "┌───────────────\n"
        f"│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 ({extension})\n"
        f"│[۞] Aplicación: {app_name}\n"
        "├───────────────\n"
        f"{rendered}\n"
        "└───────────────\n"
    )

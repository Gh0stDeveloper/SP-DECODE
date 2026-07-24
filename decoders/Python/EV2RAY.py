#!/usr/bin/env python3
"""Decoder for e-V2Ray exported .v2 profiles.

The current format is layered as follows:
    periodic XOR -> Base64 -> AES-128-ECB -> [eV2ray] fields

The V2Ray JSON field has an additional layer:
    Base64 -> periodic XOR -> Base64 -> JSON

The decoder tries the three Easypro AES keys observed in the native library so
older/newer variants using the same container can be handled automatically.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any, Optional

sys.dont_write_bytecode = True

XOR_KEY = bytes(range(0x02, 0x16))
DELIMITER = "[eV2ray]"

# AES-128 keys reconstructed from the three Easypro native key-selection modes.
# The native AES implementation uses the first 16 bytes of each decoded key.
AES_KEYS = (
    b"#%*7K!iuFem%M6BB",
    b"ah@`6js^E5,.esEK",
    b"3gp268y3i9nwd4ut",
)


def _xor_periodic(data: bytes, key: bytes = XOR_KEY) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _b64decode(data: bytes | str) -> bytes:
    if isinstance(data, str):
        raw = data.encode("ascii")
    else:
        raw = data
    raw = b"".join(raw.split())
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.b64decode(raw, validate=False)


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("empty plaintext")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-padding]


def _aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("AES ciphertext length is not a multiple of 16")

    try:
        from Crypto.Cipher import AES  # type: ignore

        plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    except ImportError:
        # Useful for development environments without pycryptodome. The project
        # normally installs pycryptodome from requirements.txt.
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return _pkcs7_unpad(plaintext)


def _decrypt_container(file_bytes: bytes) -> tuple[str, int]:
    raw = file_bytes.strip()

    # Also accept already-decoded material for easier testing/compatibility.
    with_text = raw.decode("utf-8", errors="ignore")
    if DELIMITER in with_text:
        return with_text, -1

    deobfuscated = _xor_periodic(raw)
    encrypted = _b64decode(deobfuscated)

    for key_index, key in enumerate(AES_KEYS):
        try:
            plaintext = _aes_ecb_decrypt(encrypted, key).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if DELIMITER in plaintext:
            return plaintext, key_index

    raise ValueError("no supported e-V2Ray AES key could decrypt this profile")


def _try_decode_plain_base64(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    try:
        decoded = _b64decode(value).decode("utf-8")
    except Exception:
        return None
    if not decoded or any(ord(char) < 9 for char in decoded):
        return None
    printable_ratio = sum(char.isprintable() or char in "\r\n\t" for char in decoded) / len(decoded)
    return decoded if printable_ratio > 0.95 else None


def _decode_metadata_value(value: Any, depth: int = 0) -> Any:
    """Open textual Base64 layers stored inside e-V2Ray metadata fields."""
    if depth >= 3:
        return value
    if isinstance(value, dict):
        return {
            key: _decode_metadata_value(item, depth)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_decode_metadata_value(item, depth) for item in value]
    if not isinstance(value, str):
        return value

    decoded = _try_decode_plain_base64(value)
    if decoded is None or decoded == value:
        return value

    stripped = decoded.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            return _decode_metadata_value(parsed, depth + 1)
    return _decode_metadata_value(decoded, depth + 1)


def _try_decode_v2ray_json(value: str) -> Optional[str]:
    """Decode the protected inner V2Ray body while preserving its JSON text."""
    value = value.strip()
    if not value:
        return None

    candidates: list[bytes] = []
    try:
        first = _b64decode(value)
        candidates.append(_xor_periodic(first))
    except Exception:
        pass

    # Compatibility with profiles where the field is stored one layer closer
    # to the JSON body.
    candidates.append(value.encode("utf-8"))

    for candidate in candidates:
        for stage in (candidate,):
            try:
                decoded = _b64decode(stage).decode("utf-8")
                parsed = json.loads(decoded)
                if isinstance(parsed, (dict, list)):
                    return decoded
            except Exception:
                pass

            try:
                decoded = stage.decode("utf-8")
                parsed = json.loads(decoded)
                if isinstance(parsed, (dict, list)):
                    return decoded
            except Exception:
                pass

    return None


def _parse_profile(plaintext: str, key_index: int) -> dict[str, Any]:
    parts = plaintext.split(DELIMITER)
    if len(parts) < 2:
        raise ValueError("invalid e-V2Ray field container")

    config_index: Optional[int] = None
    config_json: Optional[str] = None

    for index, part in enumerate(parts):
        decoded = _try_decode_v2ray_json(part)
        if decoded is not None:
            config_index = index
            config_json = decoded
            break

    if config_json is None:
        raise ValueError("V2Ray JSON body was not found")

    profile_name: Optional[str] = None
    profile_name_index: Optional[int] = None
    for index, part in enumerate(parts):
        if index == config_index:
            continue
        decoded = _try_decode_plain_base64(part)
        if decoded and len(decoded) <= 256 and "{" not in decoded and "[" not in decoded:
            profile_name = decoded
            profile_name_index = index
            break

    metadata: dict[str, Any] = {}
    for index, value in enumerate(parts):
        if index == config_index:
            continue
        if index == profile_name_index:
            metadata[f"Field {index + 1}"] = profile_name
            continue
        if value == "":
            metadata[f"Field {index + 1}"] = ""
        elif value.lower() == "true":
            metadata[f"Field {index + 1}"] = True
        elif value.lower() == "false":
            metadata[f"Field {index + 1}"] = False
        else:
            metadata[f"Field {index + 1}"] = _decode_metadata_value(value)

    output: dict[str, Any] = {}
    if profile_name:
        output["Profile Name"] = profile_name
    output["V2Ray Config"] = config_json
    output["Metadata"] = metadata
    if key_index >= 0:
        output["Format Variant"] = key_index + 1
    return output


def _format_top_level_json(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        elif value is None:
            rendered = "null"
        elif isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            # Strings containing JSON are intentionally preserved verbatim.
            rendered = str(value)
        lines.append(f"│[۞] {key}: {rendered}")
    return "\n".join(lines)


def run(file_bytes: bytes) -> Optional[str]:
    try:
        plaintext, key_index = _decrypt_container(file_bytes)
        result = _parse_profile(plaintext, key_index)
    except Exception:
        return None

    return (
        "┌───────────────\n"
        "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (e-V2Ray)\n"
        "│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n"
        "├───────────────\n"
        f"{_format_top_level_json(result)}\n"
        "├───────────────\n"
        "│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n"
        "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n"
        "└───────────────\n"
    )


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if len(sys.argv) != 2:
        print(f'Uso: {Path(sys.argv[0]).name} "archivo.v2"', file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"No se encontró el archivo: {input_path}", file=sys.stderr)
        return 2

    try:
        result = run(input_path.read_bytes())
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    if not result:
        print("No se pudo descifrar el archivo e-V2Ray.", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

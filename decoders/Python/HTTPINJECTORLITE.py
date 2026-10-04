#!/usr/bin/env python3
"""Decodificador independiente para perfiles HTTP Injector Lite (.ehil)."""

from __future__ import annotations

import base64
import contextlib
import io
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad as crypto_unpad

    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    AES = None
    crypto_unpad = None
    PYCRYPTODOME_AVAILABLE = False


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("ciphertext AES-CBC inválido")
    if PYCRYPTODOME_AVAILABLE:
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        return crypto_unpad(plaintext, 16)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad_pkcs7(plaintext)


def _format_top_level_json(data):
    if not isinstance(data, dict):
        if isinstance(data, (list, tuple)):
            value = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
        elif data is None:
            value = "null"
        elif isinstance(data, bool):
            value = "true" if data else "false"
        else:
            value = str(data)
        return f"│[۞] DATA: {value}"

    lines = []
    for key, value in data.items():
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
        elif value is None:
            rendered = "null"
        elif isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            rendered = str(value)
        lines.append(f"│[۞] {key}: {rendered}")
    return "\n".join(lines)


class HTTPInjectorLiteConstants:
    """Constantes exclusivas de HTTP Injector Lite 5.4.0."""

    STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    CUSTOM_ALPHABET = (
        "t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN"
    )
    LAYER_ONE_KEYS = (
        bytes.fromhex(
            "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c"
        ),
        bytes.fromhex(
            "4678e0f5295fc9ab3e9daf321b0897c78d045ebf95219514cfef570f49281811"
        ),
        bytes.fromhex(
            "322510155da7325d644ca6e6b7df8b80ed20c30ed932eccb9fe7e2b04cf8f8a4"
        ),
    )
    LAYER_TWO_KEYS = (
        bytes.fromhex("73dcf1fdbf82509064e000a41d494c01"),
        bytes.fromhex("2207a5b5a7ded2ded4eb17ce91c98266"),
    )
    IVS = tuple(
        value.encode("ascii")
        for value in (
            "CFHSIHTTPINISSCF",
            "V5HSIHTTPINISS20",
            "V5HSIHTTPINISS21",
            "SBHSIHTTPINISSLS",
            "OBHSIHTTPINIOCTO",
            "AYJZIHTTPINIECKC",
            "SBHSIHTTPINILITE",
        )
    )
    INNER_FIELDS = {
        "host",
        "user",
        "password",
        "remoteProxy",
        "payload",
        "sniHostname",
        "shadowsocksConfig",
        "httpObfsSettings",
        "v2rWsPath",
        "v2rWsHeader",
        "v2rVmessSecurity",
        "v2rVlessSecurity",
        "v2rUserId",
        "v2rSsSecurity",
        "v2rQuicSecurity",
        "v2rProtocol",
        "v2rPort",
        "v2rPassword",
        "v2rNetwork",
        "v2rMuxConcurrency",
        "v2rKcpHeaderType",
        "v2rHost",
        "v2rAlterId",
        "v2rQuicHeaderType",
        "shadowsocksHost",
        "shadowsocksPassword",
        "publicKey",
        "remoteProxyPassword",
        "remoteProxyUsername",
        "v2rTlsSni",
        "v2rTcpHeaderType",
        "v2rRawJson",
    }


class HTTPInjectorLiteDecryptor:
    """Motor exclusivo del formato .ehil; no depende de HTTPINJECTOR.py."""

    @staticmethod
    def _custom_b64_decode(encoded: str) -> bytes:
        clean = encoded.replace("?", "")
        if remainder := len(clean) % 4:
            clean += "=" * (4 - remainder)
        translation = str.maketrans(
            HTTPInjectorLiteConstants.CUSTOM_ALPHABET,
            HTTPInjectorLiteConstants.STANDARD_ALPHABET,
        )
        return base64.b64decode(clean.translate(translation), validate=True)

    @staticmethod
    def _decrypt_xor_layer(ciphertext: str, key: str) -> Optional[str]:
        if not ciphertext or not ciphertext.strip():
            return ciphertext
        with contextlib.suppress(Exception):
            hexadecimal = HTTPInjectorLiteDecryptor._custom_b64_decode(
                ciphertext[::-1]
            ).decode("ascii")
            if len(hexadecimal) % 2:
                hexadecimal = f"0{hexadecimal}"
            encrypted = bytes.fromhex(hexadecimal)
            plaintext_bytes = bytearray(
                value ^ ord(key[index % len(key)])
                for index, value in enumerate(encrypted)
                if value ^ ord(key[index % len(key)])
            )
            plaintext = plaintext_bytes.decode("utf-8")
            controls = sum(
                1
                for character in plaintext
                if ord(character) < 32 and ord(character) not in (9, 10, 13)
            )
            if plaintext and controls / len(plaintext) > 0.5:
                return None
            return plaintext
        return None

    @staticmethod
    def _decode_config_message(ciphertext: str) -> str:
        if not ciphertext or not ciphertext.strip():
            return ciphertext
        with contextlib.suppress(Exception):
            padded = ciphertext + "=" * ((4 - len(ciphertext) % 4) % 4)
            raw = base64.b64decode(padded)
            utf16 = raw.decode("utf-8", errors="replace").encode(
                "utf-16-be",
                errors="surrogatepass",
            )
            character_count = len(utf16) // 2
            java_characters = struct.unpack(f">{character_count}H", utf16)
            key = [ord(character) for character in "EHIMSG"]
            decoded = [
                value ^ key[index % len(key)]
                for index, value in enumerate(java_characters)
            ]
            decoded_bytes = struct.pack(f">{character_count}H", *decoded)
            return (
                decoded_bytes.decode("utf-16-be", errors="surrogatepass")
                .encode("utf-16", "surrogatepass")
                .decode("utf-16")
            )
        return ciphertext

    @classmethod
    def _decode_inner_fields(
        cls,
        parsed_json: Dict[str, Any],
        salt_key: str,
    ) -> Dict[str, Any]:
        cleaned = dict(parsed_json)
        for key in HTTPInjectorLiteConstants.INNER_FIELDS:
            value = cleaned.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            decrypted = cls._decrypt_xor_layer(value, salt_key)
            if decrypted is not None:
                cleaned[key] = decrypted

        config_message = cleaned.get("configMessage")
        if isinstance(config_message, str) and config_message.strip():
            cleaned["configMessage"] = cls._decode_config_message(config_message)
        return cleaned

    @staticmethod
    def _parse_container(file_bytes: bytes) -> Optional[bytes]:
        try:
            stream = io.BytesIO(file_bytes)

            def read_utf() -> str:
                length_bytes = stream.read(2)
                if len(length_bytes) < 2:
                    return ""
                length = struct.unpack(">H", length_bytes)[0]
                return stream.read(length).decode("utf-8", errors="ignore")

            magic = read_utf().lower()
            if magic != "ehil":
                return None
            stream.read(8)
            read_utf()
            stream.read(8)
            length_bytes = stream.read(4)
            if len(length_bytes) < 4:
                return None
            payload_length = struct.unpack(">I", length_bytes)[0]
            stream.read(8)
            payload = stream.read(payload_length)
            if len(payload) != payload_length:
                return None
            return payload
        except struct.error:
            return None

    @staticmethod
    def _repair_json(plaintext: bytes) -> Optional[Dict[str, Any]]:
        """Restaura el primer bloque JSON cuyo IV varía intencionalmente."""

        text = plaintext.decode("utf-8", errors="replace")
        candidates = [text]
        if len(text) > 17:
            suffix = text[17:]
            candidates.extend(("{\"a" + suffix, "{\"a\":\"" + suffix))

        for marker, prefix in (
            ("estamp\":", "{\"a"),
            ("configIdentifier\"", "{\"aestamp\":0,\""),
        ):
            marker_index = text.find(marker)
            if marker_index >= 0:
                candidates.append(prefix + text[marker_index:])

        for candidate in candidates:
            with contextlib.suppress(json.JSONDecodeError):
                parsed = json.loads(candidate)
                if isinstance(parsed, dict) and "configSalt" in parsed:
                    return parsed
        return None

    @classmethod
    def decode_profile(cls, file_bytes: bytes) -> Optional[Dict[str, Any]]:
        payload = cls._parse_container(file_bytes)
        if not payload:
            return None

        for layer_one_key in HTTPInjectorLiteConstants.LAYER_ONE_KEYS:
            for layer_one_iv in HTTPInjectorLiteConstants.IVS:
                with contextlib.suppress(Exception):
                    first_layer = _aes_cbc_decrypt(
                        payload,
                        layer_one_key,
                        layer_one_iv,
                    )
                    encoded_second_layer = first_layer.decode("utf-8").rsplit(
                        ":",
                        1,
                    )[-1]
                    encrypted_second_layer = base64.b64decode(
                        encoded_second_layer,
                        validate=True,
                    )

                    for layer_two_key in HTTPInjectorLiteConstants.LAYER_TWO_KEYS:
                        for layer_two_iv in HTTPInjectorLiteConstants.IVS:
                            with contextlib.suppress(Exception):
                                second_layer = _aes_cbc_decrypt(
                                    encrypted_second_layer,
                                    layer_two_key,
                                    layer_two_iv,
                                )
                                parsed = cls._repair_json(second_layer)
                                if parsed is None:
                                    continue
                                salt = str(parsed.get("configSalt") or "EVZJNI")
                                return cls._decode_inner_fields(parsed, salt)
        return None

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        parsed = cls.decode_profile(file_bytes)
        if parsed is None:
            return None
        return (
            "┌───────────────\n"
            "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehil)\n"
            "│[۞] Aplicación: HTTP Injector Lite\n"
            "├───────────────\n"
            f"{_format_top_level_json(parsed)}\n\n"
            "├───────────────\n"
            "│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n"
            "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n"
            "└───────────────\n"
        )


def run(file_bytes: bytes) -> Optional[str]:
    return HTTPInjectorLiteDecryptor.execute(file_bytes)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if len(sys.argv) != 2:
        print(f'Uso: {Path(sys.argv[0]).name} "archivo.ehil"', file=sys.stderr)
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
    except Exception as exc:
        print(f"Error al ejecutar HTTP Injector Lite: {exc}", file=sys.stderr)
        return 1

    if not result:
        print(
            "No se pudo decodificar el archivo .ehil o su formato no es válido.",
            file=sys.stderr,
        )
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

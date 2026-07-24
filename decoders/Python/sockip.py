#!/usr/bin/env python3
"""Decoder for SocksIP Tunnel .sip profiles using Java serialization."""

from __future__ import annotations

import base64
import json
import struct
import sys
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

sys.dont_write_bytecode = True

AES_KEY = bytes.fromhex("192e04080804040905592959385f5417")
STREAM_MAGIC = b"\xac\xed\x00\x05"


class UnsupportedSocksIPVersion(ValueError):
    """Raised when a recognized profile uses an unavailable inner container."""


@dataclass
class _ClassDesc:
    name: str
    flags: int
    fields: list[tuple[str, str]]
    superclass: Optional["_ClassDesc"] = None


class _JavaObjectReader:
    """Small, bounded Java Object Serialization reader for SocksIP exports."""

    BASE_HANDLE = 0x7E0000

    def __init__(self, data: bytes):
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("serialización demasiado grande")
        self.data = data
        self.pos = 0
        self.handles: dict[int, Any] = {}
        self.next_handle = self.BASE_HANDLE

    def _read(self, size: int) -> bytes:
        end = self.pos + size
        if size < 0 or end > len(self.data):
            raise ValueError("serialización Java truncada")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def _u1(self) -> int:
        return self._read(1)[0]

    def _u2(self) -> int:
        return struct.unpack(">H", self._read(2))[0]

    def _u4(self) -> int:
        return struct.unpack(">I", self._read(4))[0]

    def _utf(self, long: bool = False) -> str:
        length = struct.unpack(">Q", self._read(8))[0] if long else self._u2()
        if length > 1024 * 1024:
            raise ValueError("cadena Java demasiado grande")
        return self._read(length).decode("utf-8", errors="replace")

    def _new_handle(self, value: Any) -> Any:
        self.handles[self.next_handle] = value
        self.next_handle += 1
        return value

    def read(self) -> Any:
        if self._read(4) != STREAM_MAGIC:
            raise ValueError("cabecera de serialización Java inválida")
        value = self._content()
        if self.pos != len(self.data):
            raise ValueError("datos adicionales en la serialización Java")
        return value

    def _content(self, token: Optional[int] = None) -> Any:
        token = self._u1() if token is None else token
        if token == 0x70:  # TC_NULL
            return None
        if token == 0x71:  # TC_REFERENCE
            handle = self._u4()
            if handle not in self.handles:
                raise ValueError("referencia Java desconocida")
            return self.handles[handle]
        if token == 0x74:  # TC_STRING
            return self._new_handle(self._utf())
        if token == 0x7C:  # TC_LONGSTRING
            return self._new_handle(self._utf(long=True))
        if token == 0x72:  # TC_CLASSDESC
            return self._classdesc()
        if token == 0x73:  # TC_OBJECT
            return self._object()
        raise ValueError(f"token de serialización Java no soportado: 0x{token:02x}")

    def _classdesc(self) -> _ClassDesc:
        name = self._utf()
        self._read(8)  # serialVersionUID
        desc = self._new_handle(_ClassDesc(name=name, flags=0, fields=[]))
        desc.flags = self._u1()
        count = self._u2()
        if count > 512:
            raise ValueError("demasiados campos en la clase Java")
        for _ in range(count):
            typecode = chr(self._u1())
            field_name = self._utf()
            type_name = typecode
            if typecode in {"L", "["}:
                descriptor = self._content()
                if not isinstance(descriptor, str):
                    raise ValueError("descriptor de campo Java inválido")
                type_name = descriptor
            desc.fields.append((field_name, type_name))

        while True:
            annotation = self._u1()
            if annotation == 0x78:  # TC_ENDBLOCKDATA
                break
            self._content(annotation)
        superclass = self._content()
        if superclass is not None and not isinstance(superclass, _ClassDesc):
            raise ValueError("superclase Java inválida")
        desc.superclass = superclass
        return desc

    def _object(self) -> dict[str, Any]:
        desc = self._content()
        if not isinstance(desc, _ClassDesc):
            raise ValueError("objeto Java sin descriptor de clase")
        result: dict[str, Any] = {"__class__": desc.name}
        self._new_handle(result)
        lineage: list[_ClassDesc] = []
        current: Optional[_ClassDesc] = desc
        while current is not None:
            lineage.append(current)
            current = current.superclass
        for current in reversed(lineage):
            for field_name, type_name in current.fields:
                result[field_name] = self._field(type_name)
            if current.flags & 0x01:  # SC_WRITE_METHOD
                while True:
                    token = self._u1()
                    if token == 0x78:
                        break
                    if token == 0x77:
                        self._read(self._u1())
                    elif token == 0x7A:
                        self._read(self._u4())
                    else:
                        self._content(token)
        return result

    def _field(self, type_name: str) -> Any:
        typecode = type_name[0]
        if typecode == "B":
            return struct.unpack(">b", self._read(1))[0]
        if typecode == "C":
            return chr(self._u2())
        if typecode == "D":
            return struct.unpack(">d", self._read(8))[0]
        if typecode == "F":
            return struct.unpack(">f", self._read(4))[0]
        if typecode == "I":
            return struct.unpack(">i", self._read(4))[0]
        if typecode == "J":
            return struct.unpack(">q", self._read(8))[0]
        if typecode == "S":
            return struct.unpack(">h", self._read(2))[0]
        if typecode == "Z":
            return bool(self._u1())
        if typecode in {"L", "["}:
            return self._content()
        raise ValueError(f"tipo de campo Java no soportado: {type_name}")


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _decrypt_aes_ecb(ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("ciphertext AES-ECB inválido")
    try:
        from Crypto.Cipher import AES  # type: ignore

        plaintext = AES.new(AES_KEY, AES.MODE_ECB).decrypt(ciphertext)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(AES_KEY), modes.ECB()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _unpad_pkcs7(plaintext)


def decode_profile(file_bytes: bytes) -> dict[str, Any]:
    encoded = b"".join(file_bytes.split())
    encoded += b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        encrypted = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("Base64 exterior inválido") from exc
    plaintext = _decrypt_aes_ecb(encrypted)
    if plaintext.startswith(b"VER7"):
        raise UnsupportedSocksIPVersion(
            "la muestra usa el contenedor interno VER7, pero el APK SocksIP 15.14.4 "
            "suministrado no contiene ese método; esa compilación sólo produce y "
            "consume serialización Java después de AES-ECB. Se necesita la variante "
            "de SocksIP que pueda importar esta muestra"
        )
    parsed = _JavaObjectReader(plaintext).read()
    if not isinstance(parsed, dict):
        raise ValueError("la raíz SocksIP no es un objeto")
    parsed.pop("__class__", None)
    return parsed


def run(file_bytes: bytes) -> Optional[str]:
    try:
        payload = decode_profile(file_bytes)
    except Exception:
        return None
    return (
        "┌───────────────\n"
        "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.sip)\n"
        "│[۞] Aplicación: SocksIP Tunnel\n"
        "├───────────────\n"
        f"{json.dumps(payload, indent=4, ensure_ascii=False, default=str)}\n"
        "└───────────────\n"
    )


def main() -> int:
    parser = ArgumentParser(description="Decodificador de perfiles SocksIP Tunnel")
    parser.add_argument("file", help="Archivo .sip")
    args = parser.parse_args()
    try:
        payload = decode_profile(Path(args.file).read_bytes())
    except UnsupportedSocksIPVersion as exc:
        print(f"Versión SocksIP no compatible: {exc}.", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"No se pudo descifrar el perfil SocksIP Tunnel: {exc}.", file=sys.stderr)
        return 1
    print(
        json.dumps(payload, indent=4, ensure_ascii=False, default=str)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

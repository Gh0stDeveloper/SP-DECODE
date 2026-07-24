#!/usr/bin/env python3
"""Decoder for SocksIP Tunnel .sip profiles.

The public SocksIP line uses Base64 -> AES/ECB/PKCS#7 -> Java Object
Serialization. Some real-world samples expose a ``VER7`` marker after the
confirmed outer AES layer. The exact private/alternate VER7 transform is not
known yet, so this module only performs deterministic, bounded unwrapping of
common container forms and never guesses cryptographic keys.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import math
import struct
import sys
import zipfile
import zlib
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

sys.dont_write_bytecode = True

AES_KEY = bytes.fromhex("192e04080804040905592959385f5417")
STREAM_MAGIC = b"\xac\xed\x00\x05"
VER7_MAGIC = b"VER7"
MAX_CONTAINER_SIZE = 4 * 1024 * 1024
MAX_PROBE_DEPTH = 2


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
        if len(data) > MAX_CONTAINER_SIZE:
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
    """Reproduce exactamente ``nativo.xyz(data, 2)`` de la línea pública."""
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


def decode_outer_layer(file_bytes: bytes) -> bytes:
    """Decode the confirmed Base64 + AES outer layer used by SocksIP."""
    encoded = b"".join(file_bytes.split())
    encoded += b"=" * ((4 - len(encoded) % 4) % 4)
    try:
        encrypted = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("Base64 exterior inválido") from exc
    return _decrypt_aes_ecb(encrypted)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = len(data)
    result = 0.0
    for count in counts:
        if count:
            probability = count / total
            result -= probability * math.log2(probability)
    return result


def _safe_gzip_decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        result = stream.read(MAX_CONTAINER_SIZE + 1)
    if len(result) > MAX_CONTAINER_SIZE:
        raise ValueError("GZIP interno demasiado grande")
    return result


def _safe_zlib_decompress(data: bytes) -> bytes:
    inflater = zlib.decompressobj()
    result = inflater.decompress(data, MAX_CONTAINER_SIZE + 1)
    if len(result) > MAX_CONTAINER_SIZE or inflater.unconsumed_tail:
        raise ValueError("ZLIB interno demasiado grande")
    result += inflater.flush(MAX_CONTAINER_SIZE + 1 - len(result))
    if len(result) > MAX_CONTAINER_SIZE:
        raise ValueError("ZLIB interno demasiado grande")
    return result


def _strip_container_prefix(data: bytes) -> bytes:
    return data.lstrip(b"\x00\t\r\n :|;,-")


def _looks_ascii(data: bytes) -> bool:
    return bool(data) and all(value in b"\t\r\n " or 32 <= value < 127 for value in data)


def _iter_transforms(data: bytes) -> Iterable[tuple[str, bytes]]:
    """Yield bounded, non-cryptographic inner-container transformations."""
    stripped = _strip_container_prefix(data)
    if stripped != data:
        yield "strip-prefix", stripped

    java_offset = data.find(STREAM_MAGIC)
    if 0 < java_offset <= 65536:
        yield f"java-offset:{java_offset}", data[java_offset:]

    if data.startswith(b"\x1f\x8b"):
        try:
            yield "gzip", _safe_gzip_decompress(data)
        except Exception:
            pass
    if data.startswith((b"\x78\x01", b"\x78\x9c", b"\x78\xda")):
        try:
            yield "zlib", _safe_zlib_decompress(data)
        except Exception:
            pass

    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[:32]:
                    if info.is_dir() or info.file_size > MAX_CONTAINER_SIZE:
                        continue
                    with archive.open(info) as member:
                        value = member.read(MAX_CONTAINER_SIZE + 1)
                    if len(value) <= MAX_CONTAINER_SIZE:
                        yield f"zip:{info.filename}", value
        except Exception:
            pass

    ascii_data = b"".join(data.split())
    if ascii_data and _looks_ascii(ascii_data):
        padded = ascii_data + b"=" * ((4 - len(ascii_data) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
            if decoded and len(decoded) <= MAX_CONTAINER_SIZE:
                yield "base64", decoded
        except (binascii.Error, ValueError):
            pass

        try:
            text = ascii_data.decode("ascii")
            if len(text) % 2 == 0 and text and all(char in "0123456789abcdefABCDEF" for char in text):
                decoded = bytes.fromhex(text)
                if decoded and len(decoded) <= MAX_CONTAINER_SIZE:
                    yield "hex", decoded
        except ValueError:
            pass


def _normalize_root(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("la raíz SocksIP no es un objeto")
    value.pop("__class__", None)
    return value


def _try_parse_candidate(data: bytes) -> Optional[dict[str, Any]]:
    if data.startswith(STREAM_MAGIC):
        return _normalize_root(_JavaObjectReader(data).read())
    stripped = data.lstrip()
    if stripped.startswith(b"{"):
        try:
            parsed = json.loads(stripped.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _decode_ver7_container(plaintext: bytes) -> tuple[dict[str, Any], str]:
    """Try deterministic wrappers around a VER7 payload without guessing crypto."""
    if not plaintext.startswith(VER7_MAGIC):
        raise ValueError("el contenedor no comienza con VER7")

    queue: list[tuple[str, bytes, int]] = [("VER7:payload", plaintext[len(VER7_MAGIC):], 0)]
    seen: set[str] = set()

    while queue:
        label, data, depth = queue.pop(0)
        if not data or len(data) > MAX_CONTAINER_SIZE:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)

        try:
            parsed = _try_parse_candidate(data)
        except Exception:
            parsed = None
        if parsed is not None:
            return parsed, label

        if depth >= MAX_PROBE_DEPTH:
            continue
        for transform, candidate in _iter_transforms(data):
            queue.append((f"{label}->{transform}", candidate, depth + 1))

    raise UnsupportedSocksIPVersion(_ver7_error_message(plaintext, len(seen)))


def inspect_profile(file_bytes: bytes) -> dict[str, Any]:
    """Return safe structural diagnostics for reverse engineering a .sip file."""
    plaintext = decode_outer_layer(file_bytes)
    result: dict[str, Any] = {
        "outer_layer": "Base64 + AES-128-ECB + PKCS#7",
        "plaintext_size": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_entropy": round(_entropy(plaintext), 5),
        "head_hex": plaintext[:64].hex(),
        "java_stream_offset": plaintext.find(STREAM_MAGIC),
        "starts_java_serialization": plaintext.startswith(STREAM_MAGIC),
        "starts_ver7": plaintext.startswith(VER7_MAGIC),
    }
    if plaintext.startswith(VER7_MAGIC):
        payload = plaintext[len(VER7_MAGIC):]
        result.update(
            {
                "ver7_payload_size": len(payload),
                "ver7_payload_sha256": hashlib.sha256(payload).hexdigest(),
                "ver7_payload_entropy": round(_entropy(payload), 5),
                "ver7_payload_block_aligned_16": bool(payload) and len(payload) % 16 == 0,
                "ver7_payload_head_hex": payload[:64].hex(),
                "probe_transforms": [name for name, _ in _iter_transforms(payload)],
            }
        )
        try:
            _, route = _decode_ver7_container(plaintext)
            result["ver7_decodable_route"] = route
        except UnsupportedSocksIPVersion:
            result["ver7_decodable_route"] = None
    return result


def _ver7_error_message(plaintext: bytes, candidates_checked: int = 0) -> str:
    payload = plaintext[len(VER7_MAGIC):]
    java_offset = plaintext.find(STREAM_MAGIC)
    return (
        "contenedor interno VER7 no resuelto; "
        f"total={len(plaintext)} bytes, payload={len(payload)} bytes, "
        f"sha256={hashlib.sha256(plaintext).hexdigest()}, "
        f"entropía={_entropy(payload):.5f}, java_offset={java_offset}, "
        f"candidatos_deterministas={candidates_checked}. "
        "La capa exterior Base64/AES ya está confirmada; falta identificar la "
        "transformación específica de la variante que generó este VER7"
    )


def decode_profile(file_bytes: bytes) -> dict[str, Any]:
    plaintext = decode_outer_layer(file_bytes)
    if plaintext.startswith(VER7_MAGIC):
        payload, _route = _decode_ver7_container(plaintext)
        return payload
    return _normalize_root(_JavaObjectReader(plaintext).read())


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
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="muestra diagnóstico estructural seguro de la capa descifrada",
    )
    args = parser.parse_args()
    try:
        file_bytes = Path(args.file).read_bytes()
        if args.inspect:
            print(json.dumps(inspect_profile(file_bytes), indent=4, ensure_ascii=False))
            return 0
        payload = decode_profile(file_bytes)
    except UnsupportedSocksIPVersion as exc:
        print(f"Versión SocksIP no compatible: {exc}.", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"No se pudo descifrar el perfil SocksIP Tunnel: {exc}.", file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=4, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

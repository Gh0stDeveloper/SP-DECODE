#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES

SIP_AES_KEY = bytes.fromhex("192e04080804040905592959385f5417")
# VER8: second, authenticated AES-256-GCM layer from supplied 2026-10-09 source.
SIP_VER8_KEY = b"cambia_esto_por_tu_llave_de_32_b"
SIP_VER8_MAGIC = b"VER8"

SIP_STREAM_MAGIC = b"\xac\xed\x00\x05"
MAX_SERIALIZED_SIZE = 4 * 1024 * 1024
MAX_STRING_SIZE = 1024 * 1024
MAX_FIELDS = 512
MAX_ARRAY_ITEMS = 100_000


class UnsupportedSocksIPVersion(ValueError):
    """Raised when a known SocksIP outer layer contains an unsupported inner version."""


@dataclass(slots=True)
class _JavaClassDesc:
    name: str
    flags: int
    fields: list[tuple[str, str]]
    superclass: "_JavaClassDesc | None" = None


class _JavaObjectReader:
    """Small, bounded Java Object Serialization reader for SocksIP profiles."""

    BASE_HANDLE = 0x7E0000

    def __init__(self, data: bytes):
        if len(data) > MAX_SERIALIZED_SIZE:
            raise ValueError("Java serialization payload is too large")
        self.data = data
        self.pos = 0
        self.handles: dict[int, Any] = {}
        self.next_handle = self.BASE_HANDLE

    def _read(self, size: int) -> bytes:
        end = self.pos + size
        if size < 0 or end > len(self.data):
            raise ValueError("truncated Java serialization payload")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def _u1(self) -> int:
        return self._read(1)[0]

    def _u2(self) -> int:
        return struct.unpack(">H", self._read(2))[0]

    def _u4(self) -> int:
        return struct.unpack(">I", self._read(4))[0]

    def _utf(self, *, long_string: bool = False) -> str:
        length = struct.unpack(">Q", self._read(8))[0] if long_string else self._u2()
        if length > MAX_STRING_SIZE:
            raise ValueError("Java string is too large")
        return self._read(length).decode("utf-8", errors="replace")

    def _new_handle(self, value: Any) -> Any:
        self.handles[self.next_handle] = value
        self.next_handle += 1
        return value

    def read(self) -> Any:
        if self._read(4) != SIP_STREAM_MAGIC:
            raise ValueError("invalid Java serialization stream header")
        value = self._content()
        if self.pos != len(self.data):
            raise ValueError("unexpected trailing data in Java serialization stream")
        return value

    def _content(self, token: int | None = None) -> Any:
        token = self._u1() if token is None else token

        if token == 0x70:  # TC_NULL
            return None
        if token == 0x71:  # TC_REFERENCE
            handle = self._u4()
            if handle not in self.handles:
                raise ValueError("unknown Java serialization reference")
            return self.handles[handle]
        if token == 0x72:  # TC_CLASSDESC
            return self._classdesc()
        if token == 0x73:  # TC_OBJECT
            return self._object()
        if token == 0x74:  # TC_STRING
            return self._new_handle(self._utf())
        if token == 0x75:  # TC_ARRAY
            return self._array()
        if token == 0x77:  # TC_BLOCKDATA
            return self._read(self._u1())
        if token == 0x79:  # TC_RESET
            self.handles.clear()
            self.next_handle = self.BASE_HANDLE
            return self._content()
        if token == 0x7A:  # TC_BLOCKDATALONG
            length = self._u4()
            if length > MAX_SERIALIZED_SIZE:
                raise ValueError("Java block-data payload is too large")
            return self._read(length)
        if token == 0x7C:  # TC_LONGSTRING
            return self._new_handle(self._utf(long_string=True))
        if token == 0x7E:  # TC_ENUM
            return self._enum()

        raise ValueError(f"unsupported Java serialization token: 0x{token:02x}")

    def _classdesc(self) -> _JavaClassDesc:
        name = self._utf()
        self._read(8)  # serialVersionUID
        desc = self._new_handle(_JavaClassDesc(name=name, flags=0, fields=[]))
        desc.flags = self._u1()

        field_count = self._u2()
        if field_count > MAX_FIELDS:
            raise ValueError("too many fields in Java class descriptor")

        for _ in range(field_count):
            typecode = chr(self._u1())
            field_name = self._utf()
            type_name = typecode
            if typecode in {"L", "["}:
                descriptor = self._content()
                if not isinstance(descriptor, str):
                    raise ValueError("invalid Java field descriptor")
                type_name = descriptor
            desc.fields.append((field_name, type_name))

        while True:
            annotation = self._u1()
            if annotation == 0x78:  # TC_ENDBLOCKDATA
                break
            self._content(annotation)

        superclass = self._content()
        if superclass is not None and not isinstance(superclass, _JavaClassDesc):
            raise ValueError("invalid Java superclass descriptor")
        desc.superclass = superclass
        return desc

    def _lineage(self, desc: _JavaClassDesc) -> list[_JavaClassDesc]:
        lineage: list[_JavaClassDesc] = []
        current: _JavaClassDesc | None = desc
        while current is not None:
            lineage.append(current)
            current = current.superclass
        lineage.reverse()
        return lineage

    def _object(self) -> dict[str, Any]:
        desc = self._content()
        if not isinstance(desc, _JavaClassDesc):
            raise ValueError("Java object has no class descriptor")

        result: dict[str, Any] = {"__class__": desc.name}
        self._new_handle(result)

        for current in self._lineage(desc):
            for field_name, type_name in current.fields:
                result[field_name] = self._field(type_name)

            if current.flags & 0x01:  # SC_WRITE_METHOD
                self._skip_custom_data()

        return result

    def _skip_custom_data(self) -> None:
        while True:
            token = self._u1()
            if token == 0x78:  # TC_ENDBLOCKDATA
                return
            self._content(token)

    def _array(self) -> list[Any]:
        desc = self._content()
        if not isinstance(desc, _JavaClassDesc):
            raise ValueError("Java array has no class descriptor")

        length = self._u4()
        if length > MAX_ARRAY_ITEMS:
            raise ValueError("Java array is too large")

        result: list[Any] = []
        self._new_handle(result)

        array_type = desc.name[1:] if desc.name.startswith("[") else ""
        if array_type == "B":
            raw = self._read(length)
            result.extend(struct.unpack(f">{length}b", raw))
            return result
        if array_type == "I":
            for _ in range(length):
                result.append(struct.unpack(">i", self._read(4))[0])
            return result
        if array_type == "J":
            for _ in range(length):
                result.append(struct.unpack(">q", self._read(8))[0])
            return result
        if array_type == "Z":
            result.extend(bool(value) for value in self._read(length))
            return result

        for _ in range(length):
            result.append(self._content())
        return result

    def _enum(self) -> dict[str, Any]:
        desc = self._content()
        if not isinstance(desc, _JavaClassDesc):
            raise ValueError("Java enum has no class descriptor")
        result: dict[str, Any] = {"__class__": desc.name}
        self._new_handle(result)
        constant = self._content()
        if not isinstance(constant, str):
            raise ValueError("invalid Java enum constant")
        result["value"] = constant
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
        raise ValueError(f"unsupported Java field type: {type_name}")


def _unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty AES plaintext")
    padding = data[-1]
    if padding < 1 or padding > AES.block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-padding]


def _decode_outer_base64(file_bytes: bytes) -> bytes:
    try:
        text = file_bytes.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("SocksIP profile is not UTF-8/Base64 text") from exc

    if text.lower().startswith("sip://"):
        text = text[6:]

    compact = "".join(text.split())
    if not compact:
        raise ValueError("empty SocksIP profile")

    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid SocksIP Base64 payload") from exc


def _decrypt_aes_ecb(ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % AES.block_size:
        raise ValueError("invalid SocksIP AES-ECB ciphertext length")
    plaintext = AES.new(SIP_AES_KEY, AES.MODE_ECB).decrypt(ciphertext)
    return _unpad_pkcs7(plaintext)


def decode_profile(file_bytes: bytes) -> dict[str, Any]:
    ciphertext = _decode_outer_base64(file_bytes)
    plaintext = _decrypt_aes_ecb(ciphertext)

    if plaintext.startswith(b"VER7"):
        raise UnsupportedSocksIPVersion(
            "SocksIP VER7 was detected after AES-ECB. "
            "This inner container is not implemented by the analyzed SocksIP 15.14.4 build."
        )

    if plaintext.startswith(SIP_VER8_MAGIC):
        # The transport starts with VER8, followed by nonce[12],
        # ciphertext and tag[16]. NEVER parse unauthenticated plaintext.
        wrapped = plaintext[len(SIP_VER8_MAGIC):]
        if len(wrapped) < 12 + 16 + len(SIP_STREAM_MAGIC):
            raise ValueError("SocksIP VER8 envelope is truncated")
        try:
            cipher = AES.new(SIP_VER8_KEY, AES.MODE_GCM, nonce=wrapped[:12])
            plaintext = cipher.decrypt_and_verify(wrapped[12:-16], wrapped[-16:])
        except ValueError as exc:
            raise ValueError("SocksIP VER8 authentication failed") from exc

    if not plaintext.startswith(SIP_STREAM_MAGIC):
        raise ValueError(
            "decrypted SocksIP payload is neither VER7, VER8 nor Java Object Serialization"
        )

    parsed = _JavaObjectReader(plaintext).read()
    if not isinstance(parsed, dict):
        raise ValueError("SocksIP Java payload did not decode to an object")

    parsed.pop("__class__", None)
    return parsed


def run(file_bytes: bytes) -> str:
    try:
        profile = decode_profile(file_bytes)
    except UnsupportedSocksIPVersion as exc:
        return f"SocksIP Tunnel: unsupported profile version\n{exc}"

    return json.dumps(profile, ensure_ascii=False, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode a SocksIP .sip configuration")
    parser.add_argument("file", type=Path, help="Path to the .sip file")
    args = parser.parse_args()

    try:
        output = run(args.file.read_bytes())
    except Exception as exc:
        parser.exit(1, f"SocksIP decode error: {exc}\n")

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

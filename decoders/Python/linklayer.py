#!/usr/bin/env python3
"""Offline LinkLayer VPN VER6 decoder. CLI: python linklayer.py input.lnk.

Verified against LinkLayer 3.11.2 (93) and an authorized real export.
Only PyCryptodome is required. Output preserves Go field names and zero values.
The original format has no MAC; schema checks are not cryptographic integrity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

MAX_INPUT_SIZE = 8 * 1024 * 1024
MAX_STRING_SIZE = 1024 * 1024
IV = bytes.fromhex("a7734f9c12ac1b01a415f2c1fc78e66b")
XOR_SALT = b"sH3CIVoF#rWLtJo6"


class DecodeError(ValueError):
    """A configuration could not be decoded; messages contain no input values."""


class UnsupportedFormatError(DecodeError):
    pass


class UnsupportedVersionError(DecodeError):
    pass


class TruncatedFileError(DecodeError):
    pass


class InvalidConfigurationError(DecodeError):
    pass


class UnsupportedSchemaError(DecodeError):
    pass


class DependencyError(DecodeError):
    pass


# Primitive Go gob ids: bool=1, int=2, string=6. Nested struct ids vary.
SCHEMA = {
    "BlockAll": 1, "BlockPayloadSNI": 1, "BlockAuth": 1, "BlockServer": 1,
    "StartWithHWID": 1, "BlockRoot": 1, "BlockSniffer": 1, "OnlyCarrier": 6,
    "ExpireTimeConfig": 2, "MessageConfig": 6, "DeviceHWID": 6,
    "Username": 6, "Password": 6, "TypeAccount": 2, "TypeLayer": 2,
    "SSL": {"Single": 1, "Sni": 6, "Host": 6},
    "HTTP": {"Single": 1, "Payload": 6, "Host": 6},
    "HTTPSSL": {"Single": 1, "Host": 6, "SNI": 6, "Payload": 6},
    "WS": {"EnableHTTP": 1, "EnableTrue": 1, "SNI": 6, "Domain": 6, "Host": 6},
    "DNSTT": {"Domain": 6, "Pubkey": 6, "Timeout": 6, "Udp": 6},
    "UDPHysteria": {"Server": 6, "UdpPortRange": 6, "Obfs": 6,
                    "Up_mbps": 2, "Down_mbps": 2, "Insecure": 1,
                    "EnableInterval": 1, "Interval": 2},
    "HTTPDual": {"Host": 6, "Domain": 6, "SplitRequest": 1, "SNI": 6,
                 "EnableSSLTLS": 1, "Nchunks": 2, "Nparalels": 2, "Version": 6},
    "SSH": {"SSHLayer": 2, "SSHServer": 6, "SSHPayload": 6, "SSHProxy": 6,
            "SSHSni": 6, "SSHDNSPkey": 6, "SSHDomain": 6, "SSHDNSServer": 6},
    "IndexHTTPort": 2, "IndexSSLPort": 2,
}


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or size > len(self.data) - self.pos:
            raise TruncatedFileError("Truncated Go gob data.")
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def uint(self) -> int:
        first = self.take(1)[0]
        if first < 128:
            return first
        size = 256 - first
        if size > 8:
            raise InvalidConfigurationError("Invalid Go gob integer width.")
        return int.from_bytes(self.take(size), "big")

    def sint(self) -> int:
        number = self.uint()
        return ~(number >> 1) if number & 1 else number >> 1

    def string(self) -> str:
        size = self.uint()
        if size > MAX_STRING_SIZE:
            raise InvalidConfigurationError("Go gob string exceeds size limit.")
        try:
            return self.take(size).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidConfigurationError("Invalid UTF-8 configuration string.") from exc

    def expect(self, expected: int) -> None:
        if self.uint() != expected:
            raise InvalidConfigurationError("Invalid Go gob type definition.")

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise InvalidConfigurationError("Trailing Go gob message data.")


def _read_type(reader: _Reader, type_id: int) -> tuple[str, list[tuple[str, int]]]:
    # wireType.StructT -> structType.CommonType -> Name, Id -> Field slice.
    if reader.uint() != 3:
        raise UnsupportedSchemaError("Only NativeConfig struct types are supported.")
    reader.expect(1)
    reader.expect(1)
    name = reader.string()
    reader.expect(1)
    if reader.sint() != type_id:
        raise InvalidConfigurationError("Go gob type id mismatch.")
    reader.expect(0)
    reader.expect(1)
    count = reader.uint()
    if not 1 <= count <= 64:
        raise InvalidConfigurationError("Invalid Go gob field count.")
    fields = []
    for _ in range(count):
        reader.expect(1)
        field_name = reader.string()
        reader.expect(1)
        field_type = reader.sint()
        reader.expect(0)
        fields.append((field_name, field_type))
    reader.expect(0)
    reader.expect(0)
    if len({field for field, _ in fields}) != count:
        raise InvalidConfigurationError("Duplicate Go gob field names.")
    return name, fields


def _validate_schema(types: dict, root_id: int) -> None:
    seen = set()

    def visit(type_id, expected, depth):
        if depth > 8 or type_id in seen or type_id not in types:
            raise UnsupportedSchemaError("Invalid NativeConfig type graph.")
        seen.add(type_id)
        _, fields = types[type_id]
        if [name for name, _ in fields] != list(expected):
            raise UnsupportedSchemaError("Unsupported NativeConfig fields.")
        for name, field_id in fields:
            wanted = expected[name]
            if isinstance(wanted, dict):
                visit(field_id, wanted, depth + 1)
            elif field_id != wanted:
                raise UnsupportedSchemaError("Unsupported NativeConfig field type.")

    if root_id not in types or types[root_id][0] != "NativeConfig":
        raise UnsupportedSchemaError("NativeConfig root type was not found.")
    visit(root_id, SCHEMA, 0)
    if seen != set(types):
        raise UnsupportedSchemaError("Unexpected Go gob type definitions.")


def _read_value(reader: _Reader, types: dict, type_id: int):
    if type_id == 1:
        value = reader.uint()
        if value not in (0, 1):
            raise InvalidConfigurationError("Invalid Go gob boolean.")
        return bool(value)
    if type_id == 2:
        return reader.sint()
    if type_id == 6:
        return reader.string()
    _, fields = types[type_id]

    def zero(field_id):
        if field_id == 1:
            return False
        if field_id == 2:
            return 0
        if field_id == 6:
            return ""
        return {name: zero(tid) for name, tid in types[field_id][1]}

    result = zero(type_id)
    index = -1
    while (delta := reader.uint()):
        index += delta
        if index >= len(fields):
            raise InvalidConfigurationError("Invalid Go gob field index.")
        name, field_id = fields[index]
        result[name] = _read_value(reader, types, field_id)
    return result


def decode_gob(data: bytes) -> dict:
    """Decode only the bounded NativeConfig schema verified in LinkLayer 3.11.2."""
    if len(data) > MAX_INPUT_SIZE:
        raise InvalidConfigurationError("Go gob data exceeds size limit.")
    stream = _Reader(data)
    types = {}
    result = None
    while stream.pos < len(data):
        message = _Reader(stream.take(stream.uint()))
        type_id = message.sint()
        if result is not None:
            raise InvalidConfigurationError("Unexpected additional Go gob message.")
        if type_id < 0:
            if -type_id < 65 or -type_id in types or len(types) >= 16:
                raise InvalidConfigurationError("Invalid Go gob type id or count.")
            types[-type_id] = _read_type(message, -type_id)
        else:
            _validate_schema(types, type_id)
            result = _read_value(message, types, type_id)
        message.finish()
    if result is None:
        raise InvalidConfigurationError("No NativeConfig value in Go gob data.")
    return result


def decrypt_gob(data: bytes) -> bytes:
    """Reproduce configuration.d in libgojni.so; return its Go gob payload."""
    if len(data) > MAX_INPUT_SIZE:
        raise InvalidConfigurationError("Configuration exceeds 8 MiB size limit.")
    if len(data) < 4:
        raise TruncatedFileError("Configuration header is truncated.")
    if data[:4] != b"VER6":
        if data[:3] == b"VER":
            raise UnsupportedVersionError("Only LinkLayer VER6 is supported.")
        raise UnsupportedFormatError("Expected a LinkLayer VER6 configuration.")
    if len(data) < 355:
        raise TruncatedFileError("VER6 container is truncated.")
    try:
        from Crypto.Cipher import AES, Blowfish, CAST, Salsa20
    except ImportError as exc:
        raise DependencyError("Install dependency: python -m pip install pycryptodome") from exc

    def cfb(cipher, key, content):
        size = cipher.block_size
        return cipher.new(key, cipher.MODE_CFB, iv=IV[:size],
                          segment_size=size * 8).decrypt(content)

    # VER6 | Blowfish-CFB(data | 72-byte AES-key material) | 8-byte Blowfish key.
    outer = cfb(Blowfish, data[-8:], data[4:-8])
    material = outer[-72:]
    aes_key = material[:16] + material[-16:][::-1]
    salsa_container = cfb(AES, aes_key, outer[:-72])
    if len(salsa_container) < 76:
        raise TruncatedFileError("Salsa20 container is truncated.")
    # The appended reversed 32-byte trailer is not used by NewSalsa20BlockCrypt.
    reversed_packet = salsa_container[32:-32][::-1]
    packet = reversed_packet[:8] + Salsa20.new(
        key=salsa_container[:32], nonce=reversed_packet[:8]
    ).decrypt(reversed_packet[8:])
    length = int.from_bytes(packet[8:12], "big")
    blocks = packet[12:]
    if length < 75 or len(blocks) != length * 3:
        raise InvalidConfigurationError("Invalid CAST5 segment length.")
    middle = blocks[length:2 * length]
    inner = cfb(CAST, middle[-16:], middle[:-16])
    flag, inner = inner[0], inner[1:]
    if flag == 1:
        split = len(inner) // 2
        inner = inner[split:][::-1] + inner[:split]
    elif flag != 0:
        raise InvalidConfigurationError("Invalid CAST5 ordering flag.")
    # The application XORs at most 1500 bytes, not a repeated 32-byte key.
    mask = hashlib.pbkdf2_hmac("sha1", inner[:16], XOR_SALT, 32, 1500)
    wrapped = bytearray(inner[16:])
    for index in range(min(len(wrapped), len(mask))):
        wrapped[index] ^= mask[index]
    key = bytearray(wrapped[-32:])
    key[0], key[-1] = key[-1], key[0]
    encrypted = bytes(wrapped[-42:-32]) + bytes(wrapped[:-42][::-1])
    return cfb(AES, bytes(key), encrypted)


def decode(data: bytes) -> dict:
    """Return all 60 NativeConfig leaf fields, including omitted Go zero values."""
    return decode_gob(decrypt_gob(data))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="LinkLayer VER6 .lnk file")
    args = parser.parse_args(argv)
    try:
        with args.input.open("rb") as source:
            data = source.read(MAX_INPUT_SIZE + 1)
        result = decode(data)
    except (DecodeError, OSError) as exc:
        print(f"LinkLayer decode error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import sys

sys.dont_write_bytecode = True

import struct
import json
import ctypes
import binascii
from pathlib import Path
from argparse import ArgumentParser
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

PASSWORDS = {
    '.tnl': [
        'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
        'A^ST^f6ASG6AS5asd'
    ]
}

_OT_KEY = bytes([
    0xbd, 0x56, 0x1d, 0x5a, 0x60, 0x91, 0x8c, 0xcd,
    0xe6, 0x42, 0x09, 0x1e, 0xdd, 0x0f, 0x75, 0x4c,
    0x33, 0x46, 0xec, 0xf0, 0xd6, 0x09, 0xf1, 0x61,
    0x81, 0x1f, 0x8c, 0x26, 0xc1, 0x30, 0xe2, 0x87,
])

_OPL_SECRET = 'f3a91c4e2d7b05869e4f1a3c8d2e6b07a5c9f2e14d8b3a76e0f5c1d9b4a72e3f'

_OPL_MAGIC = bytes([0x4f, 0x50, 0x4c, 0x02])

_OPL_LEN_XOR = ctypes.c_uint32(-1481390639).value


def _password_list_for_ext(ext):
    val = PASSWORDS.get(ext)
    if val is None:
        return []
    return val if isinstance(val, (list, tuple)) else [val]


def _decrypt_opl_binary(raw_bytes):
    if len(raw_bytes) < 12:
        return None
    if raw_bytes[:4] != _OPL_MAGIC:
        return None

    enc_len = struct.unpack('<I', raw_bytes[4:8])[0] ^ _OPL_LEN_XOR
    crc32_stored = struct.unpack('<I', raw_bytes[8:12])[0]

    if enc_len < 0 or enc_len > len(raw_bytes) - 12:
        return None

    encrypted = raw_bytes[12:12 + enc_len]

    layer1 = bytearray(enc_len)
    for i in range(enc_len):
        r = i % 8
        mask = 195 if r == 0 else ((195 >> (8 - r)) | (195 << r)) & 255
        layer1[i] = (encrypted[i] ^ mask) ^ (i & 255)

    if binascii.crc32(bytes(layer1)) & 0xFFFFFFFF != crc32_stored:
        return None

    try:
        text = bytes(layer1).decode('utf-8').strip()
        parts = text.split('.')
        if len(parts) != 3:
            return None
        salt = b64decode(parts[0])
        nonce = b64decode(parts[1])
        ciphertext = b64decode(parts[2])
        key = PBKDF2(_OPL_SECRET, salt, 32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
    except Exception:
        return None


def _decrypt_aes_gcm(encrypted_text, ext):
    try:
        salt, nonce, ciphertext = map(b64decode, encrypted_text.split('.'))
    except Exception:
        return None

    for password in _password_list_for_ext(ext):
        try:
            key = PBKDF2(password, salt, hmac_hash_module=SHA256)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
        except Exception:
            continue

    return None


def _decrypt_opentunnel(b64_data):
    try:
        raw = b64decode(b64_data.strip())
    except Exception:
        return None

    if len(raw) < 8:
        return None

    seed = struct.unpack('>I', raw[0:4])[0]
    data_length = struct.unpack('>I', raw[4:8])[0]

    if data_length > 0x7FFFFFFF or data_length > len(raw) - 8:
        return None

    cipher_data = raw[8:8 + data_length]
    result = bytearray(data_length)

    for i in range(data_length):
        shift = (i * 8) & 0x18
        seed_byte = (seed >> shift) & 0xFF
        scramble = (7 * i + 13) & 0xFF
        xored = cipher_data[i] ^ scramble
        rotated = ((xored >> 3) | (xored << 5)) & 0xFF
        result[i] = (_OT_KEY[i % 32] ^ seed_byte ^ rotated) & 0xFF

    return bytes(result)


def decrypt_file(file_path):
    try:
        raw_bytes = Path(file_path).read_bytes()
        ext = Path(file_path).suffix
    except Exception:
        exit(1)

    result = _decrypt_opl_binary(raw_bytes)
    if result is not None:
        return result

    try:
        encrypted_data = raw_bytes.decode('utf-8', errors='replace').strip()
    except Exception:
        exit(1)

    if '.' in encrypted_data:
        result = _decrypt_aes_gcm(encrypted_data, ext)
        if result is not None:
            return result

    result = _decrypt_opentunnel(encrypted_data)
    if result is not None:
        return result

    exit(1)


def output_json(decrypted_data):
    config = decrypted_data.decode('utf-8', 'ignore')

    ignored_keys = {
        "file.proteger",
        "file.msg",
        "file.appVersionCode",
        "file.validade",
        "file.pedirLogin",
        "file.VersionCode",
        "file.protection",
        "file.validate",
        "file.askLogin",
    }

    configdict = {}
    lines = config.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i].strip()

        if line.startswith('<entry'):
            key_start = line.find('key="') + 5
            key_end = line.find('"', key_start)
            key = line[key_start:key_end].strip()

            if not key or key in ignored_keys:
                i += 1
                continue

            content_start = line.find('">') + 2

            if content_start > 1:
                current_line = line[content_start:]

                if "</entry>" in current_line:
                    content = current_line.split("</entry>")[0]
                else:
                    content = current_line
                    i += 1

                    while i < len(lines) and "</entry>" not in lines[i]:
                        content += "\n" + lines[i]
                        i += 1

                    if i < len(lines):
                        content += "\n" + lines[i].split("</entry>")[0]

                content = content.strip()

                if not content:
                    i += 1
                    continue

                if key == "proxyPayload":
                    key = "Payload"

                if key.lower() == "v2rayjson" and content.startswith("{"):
                    try:
                        parsed = json.loads(content)
                        configdict[key] = parsed
                    except json.JSONDecodeError:
                        configdict[key] = content
                else:
                    configdict[key] = content

        i += 1

    if configdict:
        print(json.dumps(configdict, indent=2, ensure_ascii=False))


def main():
    parser = ArgumentParser()
    parser.add_argument('file', help='file to decrypt')
    args = parser.parse_args()

    decrypted_contents = decrypt_file(args.file)
    output_json(decrypted_contents)


if __name__ == '__main__':
    try:
        main()
    except (FileNotFoundError, PermissionError, KeyboardInterrupt, ValueError, KeyError, IndexError):
        exit(1)

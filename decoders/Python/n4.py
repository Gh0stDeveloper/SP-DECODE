#!/usr/bin/env python3
"""Standalone SP-DECODE Telegram bot decoder, adapted from authorized 66.py.

No Telegram handlers, network access, or third-party requests are performed.
This engine is imported on demand by the bot's central extension registry.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import logging
import re
import struct
import zlib
from pathlib import Path
import sys
from typing import Any
from xml.etree import ElementTree as ET
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
logger = logging.getLogger(__name__)
MAX_INPUT_BYTES = 2 * 1024 * 1024

# ============ TABEL KARAKTER ============
TABLE1 = "ۦᜑᜐᜏᜎᜌᜈᜇᜆᜂᜁᜀᜋᜊᜉᜅᜄ"  # Untuk main
TABLE2 = "′\':‽,·ထ\u200cယငခပဆအနတမ"      # Untuk N4User/N4Pass
TABLE3 = "′\':‽,·難手火水日山田金中大"      # Untuk ServerIP/ProxyIP
TABLE4 = "           ​‌‍‎‏"              # Untuk Payload/SNI/v2rayjson

N4_IV = b"\x00" * 16

# ============ MORSE CODE ============
MORSE_MAP = {
    'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".",
    'F': "..-.", 'G': "--.", 'H': "....", 'I': "..", 'J': ".---",
    'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.", 'O': "---",
    'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-",
    'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--",
    'Z': "--..", '0': "n4vpn", '1': "n", '2': "n4", '3': "n4.",
    '4': "p.p", '5': "n7.", '6': "pro", '7': "L.W", '8': "n4.v",
    '9': "v.p.n", '.': ".-.-.-", ',': "--..--", '?': "..--..",
    '!': "-.-.--", ' ': "/"
}
REVERSE_MORSE = {v: k for k, v in MORSE_MAP.items()}

def n4_decrypt_morse(text):
    if not text: return ""
    result = []
    try:
        for word in text.split(' / '):
            for char in word.split(' '):
                result.append(REVERSE_MORSE.get(char, ''))
            result.append(' ')
        return ''.join(result).strip()
    except:
        return text

# ============ GENERIC AES DECRYPT ============
def n4_hex_upper(text: str) -> str:
    return text.encode("utf-8").hex().upper()

def n4_decode_chars(encoded: str, table: str) -> bytes:
    if len(encoded) % 2 != 0:
        raise ValueError("Ciphertext length harus genap")
    
    out = bytearray()
    for i in range(0, len(encoded), 2):
        try:
            hi = table.index(encoded[i])
            lo = table.index(encoded[i + 1])
            out.append((hi << 4) | lo)
        except ValueError:
            raise ValueError(f"Karakter tidak ditemukan di table: {encoded[i]}{encoded[i+1]}")
    
    return bytes(out)

def n4_decrypt_aes(password: str, ciphertext: str, table: str) -> str:
    """
    Dekripsi AES dengan custom table karakter
    """
    if not ciphertext or len(ciphertext) < 2:
        return ciphertext
    
    try:
        # 1. Hash password
        key = hashlib.sha256(n4_hex_upper(password).encode("utf-8")).digest()
        
        # 2. Decode karakter khusus -> bytes
        b64_bytes = n4_decode_chars(ciphertext, table)
        
        # 3. Base64 decode
        encrypted = base64.b64decode(b64_bytes)
        
        # 4. AES CBC decrypt
        cipher = AES.new(key, AES.MODE_CBC, N4_IV)
        plaintext = unpad(cipher.decrypt(encrypted), AES.block_size)
        
        return plaintext.decode("utf-8")
    except Exception as e:
        return ciphertext

# ============ DECRYPT ALL ============
def n4_decrypt_all(data):
    """Dekripsi semua data"""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            if key == "ServerPort":
                result[key] = n4_decrypt_morse(value) if isinstance(value, str) else value
            elif key in ["isSSL", "isPayloadSSL", "isDirect", "isSSLRp", "isInject", 
                        "isUdp", "isV2ray", "isSlow", "isOvpn", "isHwid", "isReward"]:
                result[key] = value
            elif isinstance(value, str) and value:
                # Pilih table berdasarkan key
                if key in ["N4User", "N4Pass"]:
                    result[key] = n4_decrypt_aes("modmkk", value, TABLE2)
                elif key in ["ServerIP", "ProxyIP"]:
                    result[key] = n4_decrypt_aes("modmkk", value, TABLE3)
                elif key in ["Payload", "SNI", "v2rayjson", "ovpn_config"]:
                    result[key] = n4_decrypt_aes("modmkk", value, TABLE4)
                else:
                    # Coba semua table
                    decrypted = value
                    for table in [TABLE2, TABLE3, TABLE4]:
                        temp = n4_decrypt_aes("modmkk", value, table)
                        if temp != value:
                            decrypted = temp
                            break
                    result[key] = decrypted
            else:
                result[key] = n4_decrypt_all(value)
        return result
    elif isinstance(data, list):
        return [n4_decrypt_all(item) for item in data]
    return data

# ============ DECRYPT LAYER 1 ============
def n4_decrypt_layer1(data):
    """Dekripsi layer pertama dengan password 'jdk'"""
    try:
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='ignore')
        data = "".join(data.split())
        PASSWORD = "jdk"
        key = hashlib.sha256(PASSWORD.encode("utf-8")).digest()
        enc = base64.b64decode(data)
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(enc)
        plain = unpad(dec, AES.block_size)
        return plain.decode('utf-8')
    except Exception as e:
        raise Exception(f"Gagal decrypt layer 1: {e}")

def decrypt_n4_file(file_data: bytes) -> dict:
    """
    فك تشفير ملفات .n4 (N4 VPN PRO)
    
    Args:
        file_data (bytes): محتوى الملف المشفر
        
    Returns:
        dict: البيانات المفككة أو None في حالة الفشل
    """
    try:
        if not file_data:
            return None
        
        # Layer 1: Decrypt with "jdk"
        decrypted_data = n4_decrypt_layer1(file_data)
        
        # Parse JSON
        json_data = json.loads(decrypted_data)
        
        # Layer 2: Decrypt all values
        decrypted = n4_decrypt_all(json_data)
        
        return decrypted
        
    except Exception as e:
        logger.error(f"N4 VPN decryption error: {e}")
        return None
def run(file_bytes: bytes) -> str | None:
    if not isinstance(file_bytes, bytes) or not file_bytes or len(file_bytes) > MAX_INPUT_BYTES:
        return None
    result = decrypt_n4_file(file_bytes)
    return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, dict) else None

EXTENSIONS = (".n4",)

def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python n4.py <configuration-file>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if path.suffix.lower() not in EXTENSIONS:
        print("Unsupported n4 extension", file=sys.stderr)
        return 2
    try:
        result = run(path.read_bytes())
    except (OSError, ValueError) as exc:
        print(f"Unable to read configuration: {exc}", file=sys.stderr)
        return 1
    if result is None:
        print("Unable to decrypt n4 configuration", file=sys.stderr)
        return 1
    print(result)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

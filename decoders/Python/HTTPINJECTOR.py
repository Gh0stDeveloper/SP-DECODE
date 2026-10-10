import struct
import base64
import json
import hashlib
import io
import contextlib
from typing import Optional, Dict, Any

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Util.Padding import unpad as crypto_unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    AES = None
    ChaCha20_Poly1305 = None
    crypto_unpad = None
    PYCRYPTODOME_AVAILABLE = False

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


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


def _chacha20_poly1305_decrypt(
    ciphertext: bytes,
    tag: bytes,
    key: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    if PYCRYPTODOME_AVAILABLE:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)

    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)


def _format_top_level_json(data):
    """Formatea solo las claves del JSON raíz.

    Los valores que ya son objetos/listas JSON se conservan como un único valor
    JSON serializado, sin recorrer ni reordenar sus claves internas. Las cadenas
    que contienen JSON se dejan intactas para poder copiarlas y pegarlas tal cual.
    """
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
            # Importante: una cadena que contiene otro JSON NO se vuelve a parsear.
            rendered = str(value)

        lines.append(f"│[۞] {key}: {rendered}")

    return "\n".join(lines)


class EHIConstants:
    """Master artifacts and cryptographic constants."""
    L1_KEY: bytes = bytes.fromhex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
    L2_KEY_STATIC: bytes = bytes.fromhex("b2bc617c32d8b9eb1943a5ffa8051eea")
    EOO_MASTER_KEY: bytes = b"null=V5kU5+FFrY\x00"
    BYPASS_IVS = (
        bytes.fromhex("221d572349555f1d112133236b1f4a3f"),
        bytes.fromhex("5543494c53443e3f4a6a4539384e776a"),
        bytes.fromhex("374c2541575e4d531a3c327b75431e5f")
    )
    STANDARD_IVS = (
        bytes.fromhex("2c5d1147bbad422b3b334d4d235f1a53"),
        bytes.fromhex("522b01433a5e8b2fc7549e1ad368e541"),
        bytes.fromhex("337a1035aaedf3458ca167e92d74b839")
    )

    STD_ALPHABET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    CUSTOM_ALPHABET: str = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
    TRANSLATION_TABLE = str.maketrans(CUSTOM_ALPHABET, STD_ALPHABET)
class EHIDecryptor:
    
    @staticmethod
    def _custom_b64_decode(
        encoded_str: str,
        custom_alphabet: str = EHIConstants.CUSTOM_ALPHABET,
    ) -> bytes:
        clean_str = encoded_str.replace("?", "")
        if rem := len(clean_str) % 4:
            clean_str += "=" * (4 - rem)
        translation_table = str.maketrans(
            custom_alphabet,
            EHIConstants.STD_ALPHABET,
        )
        return base64.b64decode(
            clean_str.translate(translation_table),
            validate=True,
        )

    @staticmethod
    def _decrypt_xor_layer(
        ciphertext_str: str,
        key: str,
        custom_alphabet: str = EHIConstants.CUSTOM_ALPHABET,
    ) -> Optional[str]:
        if not ciphertext_str or not ciphertext_str.strip():
            return ciphertext_str
            
        with contextlib.suppress(Exception):
            hex_bytes_raw = EHIDecryptor._custom_b64_decode(
                ciphertext_str[::-1],
                custom_alphabet,
            )
            hex_string = hex_bytes_raw.decode('ascii')
            
            if len(hex_string) % 2 != 0: 
                hex_string = f"0{hex_string}"
            
            raw_bytes = bytes.fromhex(hex_string)
            key_len = len(key)
            
            decrypted_bytes = bytearray(
                b ^ ord(key[i % key_len]) for i, b in enumerate(raw_bytes) if (b ^ ord(key[i % key_len])) != 0
            )
                    
            plaintext = decrypted_bytes.decode('utf-8')
            
            if plaintext and (sum(1 for c in plaintext if ord(c) < 32 and ord(c) not in (9, 10, 13)) / len(plaintext)) > 0.5:
                return None
                
            return plaintext
        return None

    @staticmethod
    def _decode_config_message(ciphertext_str: str) -> str:
        if not ciphertext_str or not ciphertext_str.strip():
            return ciphertext_str
            
        with contextlib.suppress(Exception):
            padded_str = ciphertext_str + "=" * ((4 - len(ciphertext_str) % 4) % 4)
            raw_bytes = base64.b64decode(padded_str)
            
            utf16_bytes = raw_bytes.decode('utf-8', errors='replace').encode('utf-16-be', errors='surrogatepass')
            num_chars = len(utf16_bytes) // 2
            
            java_chars = struct.unpack(f'>{num_chars}H', utf16_bytes)
            key_chars = [ord(c) for c in "EHIMSG"]
            key_len = len(key_chars)
            
            xored_chars = [jc ^ key_chars[i % key_len] for i, jc in enumerate(java_chars)]
            xored_bytes = struct.pack(f'>{num_chars}H', *xored_chars)
            
            return xored_bytes.decode('utf-16-be', errors='surrogatepass').encode('utf-16', 'surrogatepass').decode('utf-16')
        return ciphertext_str

    @staticmethod
    def _decode_inner_fields(parsed_json: Dict[str, Any], salt_key: str) -> Dict[str, Any]:
        cleaned_json = {}
        
        for k, v in parsed_json.items():
            if isinstance(v, str) and v.strip():
                decrypted_val = EHIDecryptor._decode_config_message(v) if k == "configMessage" else EHIDecryptor._decrypt_xor_layer(v, salt_key)
                    
                # Some HTTP Injector exporters keep individual fields as
                # plaintext or use a newer, unrecognized field encoding.
                # Retain those exact strings; silently discarding a key
                # produces incomplete JSON in Android and in the bot.
                cleaned_json[k] = v if decrypted_val is None else decrypted_val
            else:
                cleaned_json[k] = v
        return cleaned_json

    @staticmethod
    def _xxtea_decrypt(data: bytes, key: bytes) -> bytes:
        if not data: 
            return b""
        if rem := len(data) % 4: 
            data += b'\x00' * (4 - rem)
            
        k = struct.unpack('<4I', key.ljust(16, b'\x00')[:16])
        n = len(data) // 4
        v = list(struct.unpack(f'<{n}I', data))
        
        delta = 0x9e3779b9
        sum_val = ((6 + 52 // n) * delta) & 0xffffffff
        y = v[0]
        
        while sum_val != 0:
            e = (sum_val >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z))
                y = v[p] = (v[p] - mx) & 0xffffffff
            
            z = v[n - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(0 & 3) ^ e] ^ z))
            y = v[0] = (v[0] - mx) & 0xffffffff
            sum_val = (sum_val - delta) & 0xffffffff
            
        decrypted = struct.pack(f'<{n}I', *v)
        length = v[-1]
        return decrypted[:length] if 0 < length <= n * 4 else decrypted.rstrip(b'\x00')

    @staticmethod
    def _parse_ehi_bytes(file_bytes: bytes) -> Optional[bytes]:
        try:
            f = io.BytesIO(file_bytes)
            
            def r_utf() -> str:
                if len(l_bytes := f.read(2)) < 2: return ""
                return f.read(struct.unpack('>H', l_bytes)[0]).decode('utf-8', errors='ignore')
            
            r_utf(); f.read(8); r_utf(); f.read(8)
            if len(p_len_bytes := f.read(4)) < 4: 
                return None
            
            p_len = struct.unpack('>I', p_len_bytes)[0]
            f.read(8)
            return f.read(p_len)
        except struct.error:
            return None

    @staticmethod
    def _generate_master_key(config: Dict[str, Any]) -> bytes:
        payload = "".join(str(p) for p in (
            config.get("configAesKey", ""),           
            config.get("configIdentifier", ""),       
            config.get("configSalt", ""),             
            str(config.get("configTimestamp", 0)),                                     
            str(config.get("configExpiryTimestamp", 0)),                                    
            config.get("lockModes", ""),              
            config.get("lockModesHash", ""),          
            config.get("configHwid", ""),             
            config.get("configLockMobileOperatorId", "") 
        ) if p)
        return hashlib.sha256(payload.encode('utf-8')).digest()

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not ARGON2_AVAILABLE:
            return None

        payload = cls._parse_ehi_bytes(file_bytes)
        if not payload:
            return None

        config, matched_iv = None, None

        # Deep Validation IV Decryption Loop
        for iv in EHIConstants.BYPASS_IVS + EHIConstants.STANDARD_IVS:
            with contextlib.suppress(Exception):
                l1_text = _aes_cbc_decrypt(
                    payload,
                    EHIConstants.L1_KEY,
                    iv,
                ).decode('utf-8')
                
                if (parts := l1_text.split(":")) and len(parts) >= 3:
                    garbage = _aes_cbc_decrypt(
                        base64.b64decode(parts[2]),
                        EHIConstants.L2_KEY_STATIC,
                        base64.b64decode(parts[0]),
                    )

                    final_raw = cls._xxtea_decrypt(garbage, EHIConstants.EOO_MASTER_KEY)
                    if (start := final_raw.find(b'{')) != -1:
                        config = json.loads(final_raw[start:].decode('utf-8', errors='ignore'))
                        matched_iv = iv
                        break 

        if not config:
            return None 

        target_salt = config.get('configSalt', "EVZJNI")

        if matched_iv in EHIConstants.BYPASS_IVS:
            parsed_final = config
        else:
            target_data = config.get('configData')
            if not target_data or not (aaa_result := cls._decrypt_xor_layer(target_data, target_salt)):
                return None

            raw_payload = base64.b64decode(aaa_result)
            if len(raw_payload) <= 50:
                return None 

            try:
                argon_key = hash_secret_raw(
                    secret=cls._generate_master_key(config), 
                    salt=raw_payload[0x0a:0x1a], 
                    time_cost=int.from_bytes(raw_payload[1:5], "little"),
                    memory_cost=int.from_bytes(raw_payload[5:9], "little"), 
                    parallelism=raw_payload[9],
                    hash_len=32, 
                    type=Type.ID
                )

                decrypted_json_bytes = _chacha20_poly1305_decrypt(
                    raw_payload[0x32:-16],
                    raw_payload[-16:],
                    argon_key,
                    raw_payload[0x1a:0x32],
                    raw_payload[:0x1a],
                )
                parsed_final = json.loads(decrypted_json_bytes.decode('utf-8', errors='ignore'))
            except Exception:
                return None
        cleaned_final_json = cls._decode_inner_fields(parsed_final, target_salt)
        
        # Los campos que contienen otro JSON (por ejemplo v2rRawJson) se dejan
        # como cadenas. No se vuelven a parsear para mantenerlos copiables tal cual.


        return (
            f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
            f"{_format_top_level_json(cleaned_final_json)}\n\n"
            f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
        )


def run(file_bytes: bytes) -> Optional[str]:
    return EHIDecryptor.execute(file_bytes)


def main() -> int:
    """CLI: python SCRIPT.py \"archivo.ext\"."""
    import sys
    from pathlib import Path

    # Evita errores al imprimir los caracteres Unicode del formato de salida,
    # especialmente en terminales de Windows con una codificación heredada.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if len(sys.argv) != 2:
        print(f'Uso: {Path(sys.argv[0]).name} \"archivo\"', file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"No se encontró el archivo: {input_path}", file=sys.stderr)
        return 2

    try:
        file_bytes = input_path.read_bytes()
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    try:
        result = run(file_bytes)
    except Exception as exc:
        print(f"Error al ejecutar el decodificador: {exc}", file=sys.stderr)
        return 1

    if not result:
        print("No se pudo decodificar el archivo o su formato no es válido.", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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

    if len(nonce) == 24:
        key = _hchacha20(key, nonce[:16])
        nonce = bytes(4) + nonce[16:]
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """XChaCha subkey; lets the existing cryptography fallback use nonce24."""
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("clave o nonce HChaCha20 inválidos")
    v = list(struct.unpack('<4I', b'expand 32-byte k') +
             struct.unpack('<8I', key) + struct.unpack('<4I', nonce16))
    def rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    def quarter(a, b, c, d):
        v[a] = (v[a] + v[b]) & 0xffffffff
        v[d] = rotate(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & 0xffffffff
        v[b] = rotate(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b]) & 0xffffffff
        v[d] = rotate(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & 0xffffffff
        v[b] = rotate(v[b] ^ v[c], 7)
    for _ in range(10):
        quarter(0, 4, 8, 12); quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14); quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15); quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13); quarter(3, 4, 9, 14)
    return struct.pack('<8I', *(v[i] for i in (0, 1, 2, 3, 12, 13, 14, 15)))


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


def _format_ehi_document(document):
    return (
        f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
        f"{_format_top_level_json(document)}\n\n"
        f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
    )


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
        """Decode field-local known XOR/configMessage wrappers at every JSON depth.

        The historical decoder only inspected the root dictionary. Some current
        profiles put encrypted scalar fields inside arrays/objects. Preserve every
        key and original string when the known scheme cannot authenticate/parse
        the value. Never reinterpret random-looking strings or invent a cipher.
        """
        def visit(value: Any, name: str = "", depth: int = 0) -> Any:
            if depth > 32:
                return value
            if isinstance(value, dict):
                return {key: visit(item, key if isinstance(key,str) else "", depth+1)
                        for key,item in value.items()}
            if isinstance(value, list):
                return [visit(item,"",depth+1) for item in value]
            if not isinstance(value,str) or not value.strip():
                return value
            decoded = (EHIDecryptor._decode_config_message(value)
                       if name == "configMessage"
                       else EHIDecryptor._decrypt_xor_layer(value,salt_key))
            return value if decoded is None else decoded

        return visit(parsed_json)

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
            def read_exact(n: int) -> bytes:
                value = f.read(n)
                if len(value) != n:
                    raise ValueError("contenedor EHI truncado")
                return value
            
            def r_utf() -> str:
                length = struct.unpack('>H', read_exact(2))[0]
                return read_exact(length).decode('utf-8')
            
            if r_utf() != 'ehi':
                return None
            read_exact(8); r_utf(); read_exact(8)
            p_len = struct.unpack('>I', read_exact(4))[0]
            read_exact(8)
            if not p_len or p_len % 16:
                return None
            return read_exact(p_len)
        except (struct.error, ValueError, UnicodeError):
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
    def decode(cls, file_bytes: bytes, audit: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Return complete typed JSON. Audit describes transformations, not guesses.

        Unchanged strings may be literal text, identifiers or unsupported wrappers;
        their appearance never proves encryption or successful decryption.
        """
        if audit is not None:
            audit.clear()
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

        if not isinstance(config, dict) or not config:
            return None 

        target_salt = config.get('configSalt', "EVZJNI")

        if matched_iv in EHIConstants.BYPASS_IVS:
            parsed_final = config
        else:
            if not ARGON2_AVAILABLE:
                return None
            target_data = config.get('configData')
            if not target_data or not (aaa_result := cls._decrypt_xor_layer(target_data, target_salt)):
                return None

            try:
                raw_payload = base64.b64decode(aaa_result, validate=True)
                if len(raw_payload) < 66:
                    return None
                passes = int.from_bytes(raw_payload[1:5], 'little')
                memory_kib = int.from_bytes(raw_payload[5:9], 'little')
                lanes = raw_payload[9]
                # Parameters come from the file; bound resource use before Argon2.
                if not (1 <= passes <= 16 and 1 <= lanes <= 16 and
                        8 * lanes <= memory_kib <= 262144):
                    return None
                argon_key = hash_secret_raw(
                    secret=cls._generate_master_key(config), 
                    salt=raw_payload[0x0a:0x1a], 
                    time_cost=passes,
                    memory_cost=memory_kib,
                    parallelism=lanes,
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
        if not isinstance(parsed_final, dict):
            return None
        cleaned_final_json = cls._decode_inner_fields(parsed_final, target_salt)
        if audit is not None:
            bypass = matched_iv in EHIConstants.BYPASS_IVS
            ivs = EHIConstants.BYPASS_IVS if bypass else EHIConstants.STANDARD_IVS
            transformed, untouched = [], []
            def inspect(before, after, path=''):
                if isinstance(before, dict):
                    for k, v in before.items():
                        inspect(v, after[k], path + '/' + k.replace('~', '~0').replace('/', '~1'))
                elif isinstance(before, list):
                    for i, v in enumerate(before):
                        inspect(v, after[i], path + '/' + str(i))
                elif isinstance(before, str) and before.strip():
                    (transformed if before != after else untouched).append(path)
            inspect(parsed_final, cleaned_final_json)
            audit.update({
                'input_sha256': hashlib.sha256(file_bytes).hexdigest(),
                'profile': ('bypass' if bypass else 'standard') + '-' + str(ivs.index(matched_iv) + 1),
                'authenticated': not bypass,
                'top_level_fields': len(cleaned_final_json),
                'transformed_fields': transformed,
                'untransformed_strings': untouched,
                'note': 'Sin transformación no significa cifrado: puede ser texto literal o un formato no reconocido.',
            })
        return cleaned_final_json

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        cleaned_final_json = cls.decode(file_bytes)
        if cleaned_final_json is None:
            return None
        return _format_ehi_document(cleaned_final_json)


def run(file_bytes: bytes) -> Optional[str]:
    return EHIDecryptor.execute(file_bytes)


def decode_ehi(file_bytes: bytes, audit: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    return EHIDecryptor.decode(file_bytes, audit)


def main() -> int:
    """Legacy text by default; --json gives lossless typed JSON, --audit a report."""
    import argparse
    import sys
    from pathlib import Path

    # Evita errores al imprimir los caracteres Unicode del formato de salida,
    # especialmente en terminales de Windows con una codificación heredada.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(description='HTTP Injector EHI: texto del bot o JSON completo.')
    parser.add_argument('archivo', type=Path)
    parser.add_argument('--json', action='store_true', help='imprimir JSON con tipos y todos los campos')
    parser.add_argument('-o', '--output', type=Path, help='guardar el resultado')
    parser.add_argument('--audit', type=Path, help='guardar diagnóstico sin valores de configuración')
    args = parser.parse_args()
    input_path = args.archivo
    paths = [p.resolve() for p in (input_path, args.output, args.audit) if p is not None]
    if len(set(paths)) != len(paths):
        print('La entrada, la salida y el informe deben tener rutas diferentes.', file=sys.stderr)
        return 2
    if not input_path.is_file():
        print(f"No se encontró el archivo: {input_path}", file=sys.stderr)
        return 2

    try:
        file_bytes = input_path.read_bytes()
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    try:
        audit = {} if args.audit else None
        document = decode_ehi(file_bytes, audit) if args.json or args.audit else None
        if args.json:
            result = json.dumps(document, ensure_ascii=False, indent=2) if document is not None else None
        elif args.audit:
            # Keep the historic bot text exactly; only format the decoded document.
            result = _format_ehi_document(document) if document is not None else None
        else:
            result = run(file_bytes)
    except Exception as exc:
        print(f"Error al ejecutar el decodificador: {exc}", file=sys.stderr)
        return 1

    if not result:
        print("No se pudo decodificar el archivo o su formato no es válido.", file=sys.stderr)
        return 1

    try:
        if args.output:
            args.output.write_text(result + '\n', encoding='utf-8')
        else:
            print(result)
        if args.audit:
            args.audit.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    except OSError as exc:
        print(f'No se pudo guardar el resultado: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


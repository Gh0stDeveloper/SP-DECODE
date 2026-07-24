#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import sys
from argparse import ArgumentParser
from pathlib import Path

try:
    from Crypto.Cipher import AES as _CryptoAES
except ImportError:  # pragma: no cover - se prueba la ruta alternativa localmente
    _CryptoAES = None

sys.dont_write_bytecode = True

# Clave AES-256 obtenida del método actual de TLS Tunnel.
AES_KEY = bytes.fromhex(
    "6b303068c2acc2b9c2b221352473c2b0c2b725c2a824614b674433c2b0467856"
)


def _decrypt_aes_gcm(ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
    """Descifra AES-GCM con PyCryptodome o con cryptography como respaldo."""
    if _CryptoAES is not None:
        cipher = _CryptoAES.new(AES_KEY, _CryptoAES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(AES_KEY).decrypt(nonce, ciphertext + tag, None)


def fix_b64_padding(b64_str: str) -> str:
    """Completa el padding Base64 sin modificar el contenido útil."""
    if not b64_str:
        return ""
    return b64_str + "=" * ((4 - len(b64_str) % 4) % 4)


def decode_internal_b64(b64_str: str) -> str:
    """Decodifica los campos Base64 contenidos dentro de la configuración."""
    if not b64_str:
        return ""
    try:
        return base64.b64decode(fix_b64_padding(b64_str)).decode(
            "utf-8", errors="ignore"
        )
    except Exception:
        return ""


def safe_int(val: str) -> int:
    """Convierte un valor a entero sin abortar por campos vacíos o inválidos."""
    try:
        return int(val) if val else 0
    except (TypeError, ValueError):
        return 0


def decrypt_tls_payload(encrypted_b64: str) -> dict:
    """Descifra el contenedor actual de TLS Tunnel.

    Flujo reproducido del método suministrado:
    1. elimina un sufijo separado por ``:`` si existe;
    2. invierte el Base64 exterior;
    3. reconstruye los dos fragmentos del ciphertext y del nonce;
    4. invierte cada fragmento individual;
    5. verifica y descifra AES-256-GCM;
    6. convierte la cadena delimitada por ``:`` a un diccionario.
    """
    encrypted_b64 = encrypted_b64.split(":", 1)[0].strip()
    if not encrypted_b64:
        raise ValueError("Payload TLS vacío")

    reversed_b64 = encrypted_b64[::-1]
    padded_b64 = fix_b64_padding(reversed_b64)
    raw_bytes = base64.b64decode(padded_b64)

    i4_len = len(raw_bytes)
    # El contenedor reserva 132 bytes fuera del ciphertext reconstruido:
    # 12 iniciales + 18/18 de nonce + 84 finales.
    if i4_len < 148:
        raise ValueError("Contenedor TLS demasiado corto")

    half_math = ((i4_len - 96) - 36) // 2
    if half_math < 0:
        raise ValueError("Longitud TLS inválida")

    c1 = raw_bytes[12 : half_math + 12]
    iv1 = raw_bytes[half_math + 12 : half_math + 30]
    c2 = raw_bytes[half_math + 30 : i4_len - 102]
    iv2 = raw_bytes[i4_len - 102 : i4_len - 84]

    if len(iv1) != 18 or len(iv2) != 18:
        raise ValueError("Nonce TLS incompleto")

    c1 = c1[::-1]
    iv1 = iv1[::-1]
    c2 = c2[::-1]
    iv2 = iv2[::-1]

    stitched_ciphertext = c1 + c2
    stitched_iv = iv1 + iv2

    if len(stitched_ciphertext) < 16:
        raise ValueError("Ciphertext TLS sin etiqueta GCM completa")

    actual_ciphertext = stitched_ciphertext[:-16]
    mac_tag = stitched_ciphertext[-16:]

    decrypted_bytes = _decrypt_aes_gcm(actual_ciphertext, mac_tag, stitched_iv)

    decrypted_str = decrypted_bytes.decode("utf-8")
    parts = decrypted_str.split(":")

    config = {
        "tlsvpnVersion": safe_int(parts[0]) if len(parts) > 0 else 0,
        "server": safe_int(parts[1]) if len(parts) > 1 else 0,
        "port": safe_int(parts[2]) if len(parts) > 2 else 0,
        "pserver": parts[3].lower() == "true" if len(parts) > 3 else False,
        "sshuser": decode_internal_b64(parts[4] if len(parts) > 4 else ""),
        "sshpass": decode_internal_b64(parts[5] if len(parts) > 5 else ""),
        "sshhost": decode_internal_b64(parts[6] if len(parts) > 6 else ""),
        "server_port": decode_internal_b64(parts[7] if len(parts) > 7 else ""),
        "sshport": decode_internal_b64(parts[9] if len(parts) > 9 else ""),
        "metodo": safe_int(parts[10] if len(parts) > 10 else ""),
        "upayload": parts[11].lower() == "true" if len(parts) > 11 else False,
        "payload": decode_internal_b64(parts[12] if len(parts) > 12 else ""),
        "usnihost": parts[13].lower() == "true" if len(parts) > 13 else False,
        "snihost": decode_internal_b64(parts[14] if len(parts) > 14 else ""),
        "upayloadat": parts[15].lower() == "true" if len(parts) > 15 else False,
        "payloadat": decode_internal_b64(parts[16] if len(parts) > 16 else ""),
        "uproxy": parts[17].lower() == "true" if len(parts) > 17 else False,
        "prxhost": decode_internal_b64(parts[18] if len(parts) > 18 else ""),
        "prxport": decode_internal_b64(parts[19] if len(parts) > 19 else ""),
        "legacy_dns_mode": safe_int(parts[20] if len(parts) > 20 else ""),
        "dnsP": decode_internal_b64(parts[21] if len(parts) > 21 else ""),
        "dns_port": decode_internal_b64(parts[22] if len(parts) > 22 else ""),
        "nameserver": decode_internal_b64(parts[23] if len(parts) > 23 else ""),
        "public_key": decode_internal_b64(parts[24] if len(parts) > 24 else ""),
        "bloqmc": parts[25].lower() == "true" if len(parts) > 25 else False,
        "mensagem": decode_internal_b64(parts[27] if len(parts) > 27 else "")
        .replace("Ѻ", "\n")
        .replace("ѻ", "\r"),
    }

    # Se conserva el comportamiento del método original: solo se eliminan
    # cadenas vacías. Los valores 0 y False son datos válidos del formato.
    return {key: value for key, value in config.items() if value != ""}


def run(file_bytes: bytes) -> str | None:
    """Punto de entrada compartido para archivos .tls y mensajes tls://."""
    try:
        raw_input = file_bytes.decode("utf-8", errors="ignore").strip()
        if not raw_input:
            return None

        if "://" in raw_input:
            raw_input = raw_input.split("://", 1)[1]

        raw_input = "".join(raw_input.split())
        config_dict = decrypt_tls_payload(raw_input)
        if not config_dict:
            return None

        return (
            "TLS Tunnel\n"
            f"{'=' * 30}\n\n"
            f"{json.dumps(config_dict, indent=4, ensure_ascii=False)}\n\n"
            f"{'=' * 30}"
        )
    except Exception:
        return None


def main() -> int:
    parser = ArgumentParser(description="Decodificador de configuraciones TLS Tunnel")
    parser.add_argument("file", help="Archivo .tls a descifrar")
    args = parser.parse_args()

    try:
        file_bytes = Path(args.file).read_bytes()
    except (OSError, PermissionError) as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    result = run(file_bytes)
    if not result:
        print("No se pudo descifrar la configuración TLS Tunnel.", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

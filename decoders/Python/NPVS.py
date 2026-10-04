"""Inspect the framed NPV Tunnel .npvs v5 format without disclosing its contents.

The export in NPV Tunnel 124.0.37 uses an authenticated, signed envelope.
Its content key is wrapped for a passphrase, a recipient device, or an app key.
The APK contains the opening algorithm, but not the exporter's passphrase or a
recipient device's private key. This module intentionally does not claim that
parsing the frame decrypts or verifies it.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"NPVS"
VERSION = 5
SIGNATURE_SIZE = 64
NONCE_SIZE = 12
MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_HEADER_SIZE = 1024 * 1024


class NPVSFormatError(ValueError):
    pass


@dataclass(frozen=True)
class Envelope:
    version: int
    header_length: int
    header_codec: int
    body_length: int
    body_marker: str | None
    signature_length: int


def inspect(data: bytes) -> Envelope:
    """Check frame boundaries. Signature and AEAD tags are NOT verified."""
    if len(data) > MAX_FILE_SIZE:
        raise NPVSFormatError("El archivo supera el límite de 32 MiB.")
    if len(data) < 89:
        raise NPVSFormatError("El archivo es demasiado corto para ser un NPVS.")
    if data[:4] != MAGIC:
        raise NPVSFormatError("La cabecera NPVS no está presente.")

    version = data[4]
    if version != VERSION:
        raise NPVSFormatError(
            f"Versión NPVS {version} sin analizar; este script reconoce la versión {VERSION}."
        )

    header_length = struct.unpack_from(">I", data, 5)[0]
    if not 1 <= header_length <= MAX_HEADER_SIZE:
        raise NPVSFormatError("La longitud de la cabecera está fuera de rango.")

    header_end = 9 + header_length
    body_length_offset = header_end + NONCE_SIZE
    if body_length_offset + 4 + 16 + SIGNATURE_SIZE > len(data):
        raise NPVSFormatError("Cabecera, nonce o cuerpo truncado.")
    header_codec = data[9]
    body_length = struct.unpack_from(">I", data, body_length_offset)[0]
    if body_length < 16:
        raise NPVSFormatError("El cuerpo cifrado es demasiado corto.")
    body_start = body_length_offset + 4
    signature_start = body_start + body_length
    if signature_start + SIGNATURE_SIZE != len(data):
        raise NPVSFormatError("Longitud del cuerpo o firma incorrecta; hay datos faltantes o sobrantes.")

    marker = "NPF1" if data[body_start : body_start + 4] == b"NPF\x01" else None
    return Envelope(
        version=version,
        header_length=header_length,
        header_codec=header_codec,
        body_length=body_length,
        body_marker=marker,
        signature_length=SIGNATURE_SIZE,
    )


def describe(envelope: Envelope) -> str:
    marker = envelope.body_marker or "no identificada"
    return (
        "SP-DECODE — diagnóstico de NPV Tunnel .npvs\n"
        f"Formato: NPVS v{envelope.version}\n"
        f"Cabecera: {envelope.header_length} bytes (codificación {envelope.header_codec})\n"
        f"Cuerpo: {envelope.body_length} bytes (marca {marker})\n"
        f"Firma: {envelope.signature_length} bytes (sin verificar)\n\n"
        "Estado: contenido cifrado; no se han recuperado configuraciones. "
        "Para abrirlo se necesita la contraseña del exportador, la clave privada "
        "de un destinatario autorizado o la clave local de la aplicación, según "
        "cómo se compartió el archivo. Ninguna está contenida en la APK."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnostica archivos .npvs v5 cifrados.")
    parser.add_argument("file", type=Path, help="Archivo .npvs")
    args = parser.parse_args(argv)
    try:
        if args.file.stat().st_size > MAX_FILE_SIZE:
            raise NPVSFormatError("El archivo supera el límite de 32 MiB.")
        print(describe(inspect(args.file.read_bytes())))
    except (OSError, NPVSFormatError) as exc:
        print(f"NPVS: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

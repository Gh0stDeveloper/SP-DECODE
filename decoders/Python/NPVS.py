"""Inspect the compact NPV Tunnel v5 import envelope.

Generation 2 appKey derivation occurs in the APK's native libnpvtunnel.so,
using assets/rt.dat. An optional exporter password gates usage after import;
it does not derive the key needed to read this appKey export.
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
COMPACT_PREFIX_SIZE = 53
APP_KEY_RECORD_SIZE = 78


class NPVSFormatError(ValueError):
    pass


@dataclass(frozen=True)
class AppKeyRecord:
    generation: int
    salt: bytes
    wrapped_document_key: bytes


@dataclass(frozen=True)
class CompactHeader:
    codec: int
    config_id: bytes
    creator_public_key: bytes
    recipient_kind: int
    passphrase_length: int
    app_key: AppKeyRecord | None
    encrypted_metadata: bytes


@dataclass(frozen=True)
class Envelope:
    version: int
    header_length: int
    header_codec: int
    body_length: int
    body_marker: str | None
    signature_length: int
    compact_header: CompactHeader | None = None


def parse_compact_header(raw: bytes) -> CompactHeader:
    """Read the fields consumed by parseCompactHeader in libgojni.so."""
    if len(raw) < COMPACT_PREFIX_SIZE + 4:
        raise NPVSFormatError("Cabecera compacta truncada.")
    if raw[0] != 1:
        raise NPVSFormatError(f"Códec de cabecera compacta {raw[0]} desconocido.")
    config_id = raw[1:17]
    creator_public_key = raw[17:50]
    recipient_kind = raw[50]
    passphrase_length = int.from_bytes(raw[51:53], "big")
    if recipient_kind > 2 or passphrase_length > 1024:
        raise NPVSFormatError("Selector de destinatario o longitud no válida.")
    if recipient_kind == 0 and passphrase_length == 0:
        raise NPVSFormatError("La cabecera carece de destinatario.")

    cursor = COMPACT_PREFIX_SIZE + passphrase_length
    if cursor > len(raw):
        raise NPVSFormatError("Datos de destinatario truncados.")
    app_key = None
    if recipient_kind == 2:
        if cursor + APP_KEY_RECORD_SIZE > len(raw):
            raise NPVSFormatError("Registro appKey truncado.")
        generation = int.from_bytes(raw[cursor : cursor + 2], "big")
        salt = raw[cursor + 2 : cursor + 18]
        wrap = raw[cursor + 18 : cursor + APP_KEY_RECORD_SIZE]
        app_key = AppKeyRecord(generation, salt, wrap)
        cursor += APP_KEY_RECORD_SIZE

    if cursor + 4 > len(raw):
        raise NPVSFormatError("Longitud de metadatos ausente.")
    metadata_length = int.from_bytes(raw[cursor : cursor + 4], "big")
    cursor += 4
    if metadata_length < 16 or metadata_length != len(raw) - cursor:
        raise NPVSFormatError("Longitud de metadatos cifrados incorrecta.")
    return CompactHeader(
        codec=1,
        config_id=config_id,
        creator_public_key=creator_public_key,
        recipient_kind=recipient_kind,
        passphrase_length=passphrase_length,
        app_key=app_key,
        encrypted_metadata=raw[cursor:],
    )


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
    header_raw = data[9:header_end]
    header_codec = header_raw[0]
    compact_header = parse_compact_header(header_raw) if header_codec == 1 else None
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
        compact_header=compact_header,
    )


def describe(envelope: Envelope) -> str:
    marker = envelope.body_marker or "no identificada"
    lines = [
        "SP-DECODE — análisis de NPV Tunnel .npvs",
        f"Formato: NPVS v{envelope.version}",
        f"Cabecera: {envelope.header_length} bytes (códec {envelope.header_codec})",
        f"Cuerpo: {envelope.body_length} bytes (marca {marker})",
        f"Firma: {envelope.signature_length} bytes (sin verificar)",
    ]
    header = envelope.compact_header
    if header is not None:
        if header.app_key is not None:
            lines.append(f"Importación: appKey, generación {header.app_key.generation}")
        else:
            lines.append(f"Importación: destinatario tipo {header.recipient_kind}")
        lines.append(f"Metadatos cifrados: {len(header.encrypted_metadata)} bytes")
    lines.extend((
        "",
        "Estado: contenido cifrado; no se han recuperado configuraciones.",
        "La contraseña personalizada de uso no interviene en la importación. "
        "La generación 2 deriva la clave dentro de libnpvtunnel.so con assets/rt.dat "
        "y después abre el documento NPF1; este script aún no implementa esas rutas.",
    ))
    return "\n".join(lines)


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

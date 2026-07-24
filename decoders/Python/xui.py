#!/usr/bin/env python3
"""Decoder for current XUI Tunnel .xui profiles."""

from __future__ import annotations

import sys
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional

try:
    from ._noobcrypt import decrypt_profile, format_result
except ImportError:  # ejecución directa por ruta
    from _noobcrypt import decrypt_profile, format_result

sys.dont_write_bytecode = True


def run(file_bytes: bytes) -> Optional[str]:
    try:
        payload = decrypt_profile(file_bytes, "xui")
    except Exception:
        return None
    return format_result("XUI Tunnel", ".xui", payload)


def main() -> int:
    parser = ArgumentParser(description="Decodificador de perfiles XUI Tunnel")
    parser.add_argument("file", help="Archivo .xui")
    args = parser.parse_args()
    try:
        file_bytes = Path(args.file).read_bytes()
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2
    result = run(file_bytes)
    if result is None:
        print("No se pudo descifrar el perfil XUI Tunnel.", file=sys.stderr)
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

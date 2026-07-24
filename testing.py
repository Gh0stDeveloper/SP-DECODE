#!/usr/bin/env python3
"""Ejemplo opcional de la API de Cuty sin credenciales incrustadas."""

from __future__ import annotations

import os
import random
import string

import requests


def generate_random_alias() -> str:
    lowercase = random.choices(string.ascii_lowercase, k=3)
    uppercase = random.choices(string.ascii_uppercase, k=3)
    return "".join(lowercase + uppercase)


def main() -> int:
    api_token = os.getenv("CUTY_API_TOKEN", "").strip()
    long_url = os.getenv("CUTY_LONG_URL", "https://example.com").strip()
    if not api_token:
        print("Define CUTY_API_TOKEN para ejecutar este ejemplo.")
        return 2

    response = requests.get(
        "https://cuty.io/api",
        params={"api": api_token, "url": long_url, "alias": generate_random_alias()},
        timeout=20,
    )
    response.raise_for_status()
    result = response.json()
    if result.get("status") == "error":
        print(result.get("message", "La API devolvió un error."))
        return 1

    print(result.get("shortenedUrl", "La respuesta no incluyó una URL."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""NetMod (.nm) decoder.

Current decoder method with compatibility for known legacy NetMod keys.
Usage:
    python nms.py "file.nm"
"""

import sys

sys.dont_write_bytecode = True

from pathlib import Path
from argparse import ArgumentParser
from base64 import b64decode
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


PASSWORDS = {
    ".nm": [
        b"<n3t5yn4^n3tm0d>",
        b"_netsyna_netmod_",
        b"nicetrybuddygoon",
    ]
}

OMIT_KEYS = {"Opts", "Note", "Remark"}


def print_error(msg=""):
    if msg:
        print(msg, file=sys.stderr)
    raise SystemExit(1)


def print_warning(msg=""):
    if msg:
        print(msg, file=sys.stderr)
    raise SystemExit(1)


def decrypt_file(file_path):
    try:
        ext = Path(file_path).suffix.lower()
        file_keys = PASSWORDS[ext]
        encrypted_text = Path(file_path).read_text(encoding="utf-8").strip()
        encrypted_data = b64decode(encrypted_text)

        for file_key in file_keys:
            try:
                cipher = AES.new(file_key, AES.MODE_ECB)
                decrypted_bytes = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                return decrypted_bytes
            except Exception:
                continue

        print_error("No se pudo descifrar el archivo .nm con ninguna clave conocida.")
    except KeyError:
        print_error(f"Extensión no soportada: {Path(file_path).suffix}")
    except Exception as exc:
        print_error(f"Error al leer o descifrar el archivo: {exc}")


def output_json(decrypted_data):
    try:
        config = decrypted_data.decode("utf-8", "ignore")
        data = json.loads(config)

        if not data:
            print_error("La configuración descifrada está vacía.")

        flat = {}

        def add_entry(key, value):
            if key not in flat:
                flat[key] = []
            flat[key].append(value)

        def process_item(item_key, item_value):
            if item_key in OMIT_KEYS or item_value in [None, "", [], {}]:
                return

            if isinstance(item_value, dict) and "Value" in item_value:
                if str(item_value["Value"]).strip():
                    add_entry(item_key, item_value["Value"])
                for sub_key, sub_value in item_value.items():
                    if sub_key != "Value":
                        process_item(sub_key, sub_value)
                return

            if isinstance(item_value, (str, int, float)) and str(item_value).strip():
                add_entry(item_key, item_value)
            elif isinstance(item_value, list):
                for list_item in item_value:
                    if isinstance(list_item, dict):
                        for dict_key, dict_value in list_item.items():
                            process_item(dict_key, dict_value)
            elif isinstance(item_value, dict):
                for dict_key, dict_value in item_value.items():
                    process_item(dict_key, dict_value)

        for top_key, top_value in data.items():
            process_item(top_key, top_value)

        output = {}
        for key, values in flat.items():
            output[key] = values if len(values) > 1 else values[0]

        print(json.dumps(output, indent=2, ensure_ascii=False))

    except Exception as exc:
        print_error(f"No se pudo procesar el JSON descifrado: {exc}")


def main():
    parser = ArgumentParser()
    parser.add_argument("file", help="file to decrypt")
    args = parser.parse_args()

    file_path = Path(args.file)
    file_ext = file_path.suffix.lower()

    if file_ext not in PASSWORDS:
        print(
            f"Unsupported file extension: {file_ext}\nSupported: {', '.join(PASSWORDS)}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    decrypted_contents = decrypt_file(file_path)
    output_json(decrypted_contents)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        print_error(str(exc))

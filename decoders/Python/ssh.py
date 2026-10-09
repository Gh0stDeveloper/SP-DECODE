import sys
import re
import random
import os
import binascii
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad
from base64 import b64decode

unlockKeys = {
    "cproxyRemoto": "",
    "sslProxy": "",
    "dnsKey": "",
    "cchaveKey": "",
    "cserverNameKey": "",
    "cdnssshUser": "",
    "cdnssshPass": ""
}

def ssh_injector(file):
    key = b'263386285977449155626236830061505221752'
    text = b64decode(open(file, 'rb').read())
    iv = b'\x00\x01\x02\x03\x04\x05\x06\x07'
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = cipher.decrypt(text)
    decrypt_text = unpad(plaintext, Blowfish.block_size).decode()  # remove pkcs#7

    principio_result_str = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ssh)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"

    # Proceso de extracción de datos
    extracted_data = re.findall(r'<entry key="([^"]+)">([^"]+)</entry>', decrypt_text)
    
    # Lista de emojis
    emojis = ["💠", "🔵", "💀", "🤖",  "😈", "🔥", "🚀", "🔐"]

    # Elegir un emoji aleatorio
    # An explicit TEST-ONLY environment switch stabilizes the decorative
    # glyph for a byte-exact Linux CLI golden. Normal app/bot behavior remains
    # random as before. No decryption logic or field content is altered.
    selector = random.Random(0) if os.environ.get("SPDECODE_SSH_GOLDEN_TEST") == "1" else random
    random_emoji = selector.choice(emojis)

    result_message = []

    for key, value in extracted_data:
        # Verificar si la clave está presente en unlockKeys o contiene el texto "unlockKeys"
        if key not in unlockKeys and "unlockKeys" not in key:
            # Usar el mismo emoji para todas las entradas
            result_message.append(f"│[{random_emoji}] {key} : {value}")

    # Ordenar los datos extraídos
    sorted_result = sorted(result_message, key=lambda x: x.split(':')[0].strip())

    # Manejar los datos de unlockKeys
    unlock_keys_message = [f"│[{random_emoji}] unlockKeys 🔽"]
    for key, value in unlockKeys.items():
        if value:
            unlock_keys_message.append(f"│[{random_emoji}] {key}: {value}")
        else:
            unlock_keys_message.append(f"│[{random_emoji}] {key}: ***")

    # Agregar los datos de unlockKeys debajo del encabezado correspondiente
    result_str = principio_result_str + '\n'.join(sorted_result[:6]) + '\n' + '\n'.join(unlock_keys_message) + '\n' + '\n'.join(sorted_result[6:]) + f"\n├───────────────\n│[{random_emoji}] 𝗚𝗥𝗢𝗨𝗣 : CodeBreakersHub\n├───────────────\n│[{random_emoji}] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"

    return result_str

def main() -> int:
    if len(sys.argv) != 2:
        print("Uso: python ssh.py file.ssh", file=sys.stderr)
        return 2

    try:
        result = ssh_injector(sys.argv[1])
    except (OSError, ValueError, UnicodeError, binascii.Error) as exc:
        # Corrupt or missing files must not dump a Python traceback or
        # accidentally produce a positive-looking decrypted profile.
        print(f"SSH Injector decode error: {type(exc).__name__}", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
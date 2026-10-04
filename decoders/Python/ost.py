#!/usr/bin/env python3
import sys
import os
from Crypto.Cipher import DES
import base64
from base64 import b64decode, b64encode

PASSWORDS = {
    '.ost': base64.b64decode(b'4pyF2Y5PU1Q='), # OUSS Tunnel
   
    '.sbr': b'cinbdf66', #SBR Injector
}

def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text

def decrypt_des(encrypted_bytes, key_bytes, file_extension):
    key_bytes = key_bytes.decode('utf-8').encode('utf-8')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return decrypted_bytes.decode('utf-8', errors='ignore').strip()

def apply_filter(contents, file_extension):
    filtered_contents = "\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.tnl)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
    lines = contents.split('\n')
    for line in lines:
        if line.strip().startswith("<entry"):
            key_value = line.strip().replace("<entry key=\"", "").replace("</entry>", "").replace('"/>', '').split("\">")
            if len(key_value) > 1:
                key, value = key_value
                filtered_contents += f"│[۞] {key}: {value}\n"
    filtered_contents += f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
    return filtered_contents

def decrypt_file(input_file, passwords):
    with open(input_file, 'rb') as f:
        encrypted_bytes = f.read()

    file_extension = os.path.splitext(input_file)[1]

    if file_extension in passwords:
        key_bytes = passwords[file_extension]
        try:
            decrypted_text = decrypt_des(encrypted_bytes, key_bytes, file_extension)
            filtered_text = apply_filter(decrypted_text, file_extension)
            print(filtered_text)
        except Exception as e:
            print(f"Error decrypting: {e}")

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 script.py <archivo>")
        sys.exit(1)

    input_file = sys.argv[1]
    decrypt_file(input_file, PASSWORDS)

if __name__ == "__main__":
    main()
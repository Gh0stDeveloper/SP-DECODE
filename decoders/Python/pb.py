import os
import time
import zlib
import base64
from time import sleep
from shutil import which
from sys import stdin, stdout, stderr
from argparse import ArgumentParser
from pathlib import Path
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import unpad
from base64 import b64decode
from urllib.parse import unquote
import re
import sys

DEFAULT_FILE_EXTENSION = '.tmt'

KEY_LABELS = {
    "sshServer": "SSH Server",
    "sshPort": "SSH Port",
    "sshUser": "SSH User",
    "sshPass": "SSH Password",
    "sshPortLocal": "Local Port",
    "proxyPayload": "Proxy Payload",
    "sslHost": "SSL Host",
    "proxyRemotePort": "Remote Proxy",
    "proxyRemote": "Remote Proxy Port",
    "proxyuser": "Proxy User",
    "proxypass": "Proxy Password",
    "sslProtocol": "SSL Protocol",
    "sniHost": "SNI Host",
    "cUUID": "UUID",
    "dnspu": "PublicKey",
    "dnsnameserver": "DNS Name Server",
    #ziv
    "sshAllinOne": "SSH Field",
    "nameServer": "NameServer",
    "publickey": "PublicKey",
    "udpserver": "UDP Server",
    "dnsResolver": "Primary DNS",
    "udpResolver": "UDPGW",
    #pcx
    "up_mbps": "Upload Mbps",
    "down_mbps": "Download Mbps",
    "udpwindow": "QUIC Windows",
    "udpauth": "Authentication",
    "udpobfs": "Obfuscate",
    "sshPortaLocal": "Local Port",
}

PASSWORDS = {
    '.ziv': b'fubvx788b46v',
    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
    '.pb': b'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e',
    '.hqp': b'Ed',
    '.hq': b'Ed',
    '.bdi': b'@technore 2022',
    '.NT': b'0x0',
    '.pcx': b'cinbdf665$4'
}

def error(error_msg='Corrupted/unsupported file.'):
    stderr.write(f'\033[41m\033[30m X \033[0m {error_msg}\n')
    stderr.flush()
    exit(1)

def warn(warn_msg):
    stderr.write(f'\033[43m\033[30m ! \033[0m {warn_msg}\n')
    stderr.flush()

def ask(prompt):
    stderr.write(f'\033[104m\033[30m ? \033[0m {prompt} ')
    stderr.flush()
    return input()

def human_bool_to_bool(human_bool):
    return 'y' in human_bool

def main():
    parser = ArgumentParser()
    parser.add_argument('file', help='file to decrypt')

    output_args = parser.add_mutually_exclusive_group()
    output_args.add_argument('--output', '-o', help='file to output to')
    output_args.add_argument('--stdout', '-O', action='store_true', help='output to stdout', default=True)

    args = parser.parse_args()

    encrypted_contents = open(args.file, 'rb').read()

    file_ext = Path(args.file).suffix

    if file_ext not in PASSWORDS:
        print(f'Unknown file extension, defaulting to {DEFAULT_FILE_EXTENSION}')
        file_ext = DEFAULT_FILE_EXTENSION

    split_base64_contents = encrypted_contents.split(b'.')

    split_contents = list(map(b64decode, split_base64_contents))

    decryption_key = PBKDF2(PASSWORDS[file_ext], split_contents[0], hmac_hash_module=SHA256)

    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
    decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

    if args.stdout:
        config = decrypted_contents.decode('utf-8', 'ignore')
        message = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.pb)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n" 
        configdict = {}
        for line in config.split('\n'):
            if line.startswith('<entry'):
                line = line.replace('<entry key="', '')
                line = line.replace('</entry', '')
                line = line.split('">')
                if len(line) > 1:
                    configdict[line[0]] = line[1].strip(">")
                else:
                    configdict[line[0].strip('"/>')] = ""

        for key, label in KEY_LABELS.items():
            if key in configdict:
                value = configdict[key].strip()
                if value != "" and value != "0" and value != "*******":
                    message += f"│[۞] {label}: {value}\n"

        message += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"
        print(message)

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        print(f'Error: {err}')
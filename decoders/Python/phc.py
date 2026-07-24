import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import os

def print_cyan(text):
    print(text) 
dd_ssff = '667562767837383862343676'
def decrypt_content(encrypted_contents, password):
    try:
        split_base64_contents = encrypted_contents.split('.')
        split_contents = list(map(base64.b64decode, split_base64_contents))
        decryption_key = PBKDF2(password, split_contents[0], hmac_hash_module=SHA256)
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
        decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])
        return decrypted_contents.decode('utf-8', 'ignore')
    except ValueError as e:
        print("Error decrypting file:", str(e))
        return None
    except Exception as e:
        print("Unexpected error:", str(e))
        return None
def read_file(filepath):
    try:
        with open(filepath, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        print("File not found.")
        return None
    except Exception as e:
        print("Error reading file:", e)
        return None
def print_result(config, file_extension, file_name):
    result_str = f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.phc)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
    configdict = {}
    for line in config.split('\n'):
        if line.startswith('<entry'):
            line = line.replace('<entry key="', '')
            line = line.replace('</entry', '')
            line = line.split('">')
            if len(line) > 1:
                key = line[0]
                value = line[1].strip(">")
                configdict[key] = value
            else:
                key = line[0].strip('"/>')
                value = " ***"
                configdict[key] = value

    for key, value in configdict.items():
        result_str += f"│[۞] {key}: {value}\n"
    result_str += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"
    return result_str 
def decrypt_and_print_cyan(input_filepath):
    encrypted_contents = read_file(input_filepath)   
    if encrypted_contents is not None:
        encrypted_contents = encrypted_contents.decode('utf-8')
        password = bytes.fromhex(dd_ssff).decode('utf-8')
        decrypted_contents = decrypt_content(encrypted_contents, password)       
        if decrypted_contents is not None:
            filtered_contents = decrypted_contents.encode('utf-8', 'ignore').decode('utf-8')
            result = print_result(filtered_contents, 'PHC', 'sample_file')
            print_cyan(result)
if len(sys.argv) < 2:
    print("Usage: python phc.py <file_path>")
    sys.exit(1)
encrypted_filepath = sys.argv[1]
decrypt_and_print_cyan(encrypted_filepath)
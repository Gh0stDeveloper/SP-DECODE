import sys
from Crypto.Cipher import DES
import base64

PASSWORDS = {
    '.v2i': b'cinbdf66', #V2 Injector + Bee Inject
    '.ost': base64.b64decode(b'4pyF2Y5PU1Q='), # OUSS Tunnel
    '.agn': b'letsmake', # Agn Injector
    '.vpc': b'cinbdf66', #VPN Custom
    '.Fɴ': b'cinbdf66', # FN Injector
    '.Fɴ': b'cinbdf66', #CLAY Custom
    '.jvi': b'cinbdf66', #    
    '.jvc': b'agstgfoh', # JV CUSTOM   
}

def decrypt_des(encrypted_bytes, key_text):
    key_bytes = key_text.encode('utf-8')
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return decrypted_bytes.decode('utf-8')

def apply_filter(contents):
    filtered_contents = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 \n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
    lines = contents.split('\n')
    for line in lines:
        if line.strip().startswith("<entry"):
            key_value = line.strip().replace("<entry key=\"", "").replace("</entry>", "").replace('"/>', '').split("\">")
            if len(key_value) > 1:
                key, value = key_value
                filtered_contents += f"│[۞] [{key}]: {value}\n"
            else:
                key = key_value[0]
                filtered_contents += f"│[۞] [{key}]: ***\n"
    filtered_contents += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"
    return filtered_contents

def decrypt_file(input_file, passwords):
    with open(input_file, 'rb') as f:
        encrypted_bytes = f.read()

    for key, value in passwords.items():
        try:
            decrypted_text = decrypt_des(encrypted_bytes, value.decode('utf-8'))
            filtered_text = apply_filter(decrypted_text)
            print(filtered_text)
            break
        except Exception as e:
            print(f"")

def main():
    if len(sys.argv) != 2:
        print("Penggunaan: python script.py <input_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]

    decrypt_file(input_file, PASSWORDS)

if __name__ == "__main__":
    main()



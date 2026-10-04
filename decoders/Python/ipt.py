import base64
import sys
import json

ipt = "QEFkZWRheW8ncyBXZVR1bm5lbA=="
ipt_password = base64.b64decode(ipt).decode('utf-8')

KEY_LABELS = {
    "PSInstall": "PS Install",
    "DeviceID": "Device ID",
    "RootBlock": "Root Block",
    "isBlockVPN": "Block VPN",
    "isXposed": "Xposed",
    "isBlockAppList": "Block App List",
    "ConfigAppBlockList": "Config App Block List",
    "MobileData": "Mobile Data",
    "ExpireDate": "Expire Date",
    "Message": "Message",
    "Config": "Config",
    "Flag": "Flag",
    "Payload": "Payload",
    "SNIHost": "SNI Host",
    "DNSAddress": "DNS Address",
    "Type": "Type",
    "ProxyHost": "Proxy Host",
    "ProxyPort": "Proxy Port",
    "Server": "Server", 
    "Name": "Name",
    "Flag": "Flag",
    "Payload": "Payload",
    "SNIHost": "SNI Host",
    "DNSAddress": "DNS Address",
    "Type": "Type",
    "ProxyHost": "Proxy Host",
    "ProxyPort": "Proxy Port"
}

def decrypt(ciphertext, password):
    if len(ciphertext) == 0:
        return ""
    v = str_to_longs(base64.b64decode(ciphertext))
    k = str_to_longs(password[:16].encode('utf-8'))
    n = len(v)
    z = v[n - 1]
    y = v[0]
    delta = -0x658C6C4C
    mx = 0
    q = 6 + 52 // n
    sum = q * delta

    while sum != 0:
        e = (sum >> 2) & 3
        for p in range(n - 1, -1, -1):
            z = v[p - 1] if p > 0 else v[n - 1]
            mx = (z >> 5 ^ (y << 2)) + (y >> 3 ^ (z << 4)) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z)
            y = (v[p] - mx) & 0xffffffff
            v[p] = y
        sum -= delta

    plaintext = longs_to_str(v)
    plaintext = plaintext.rstrip('\x00')

    return plaintext

def str_to_longs(data):
    l = []
    for i in range(0, len(data), 4):
        a = data[i] if i < len(data) else 0
        b = (data[i + 1] << 8) if i + 1 < len(data) else 0
        c = (data[i + 2] << 16) if i + 2 < len(data) else 0
        d = (data[i + 3] << 24) if i + 3 < len(data) else 0
        l.append(a + b + c + d)
    return l

def longs_to_str(l):
    s = ''
    for num in l:
        s += chr(num & 0xFF)
        s += chr((num >> 8) & 0xFF)
        s += chr((num >> 16) & 0xFF)
        s += chr((num >> 24) & 0xFF)
    return s

def decrypt_ipt_file(file_content, password):
    try:
        
        decrypted_text = decrypt(file_content, password)
        decrypted_text = decrypted_text.rstrip('N')
        return decrypted_text
    except Exception as e:
        return f"Error: {e}"

def format_decrypted_json(decrypted_text):
    try:
        start_index = decrypted_text.find('{')
        end_index = decrypted_text.rfind('}') + 1
        extracted_data = decrypted_text[start_index:end_index]
        decrypted_json = json.loads(extracted_data)
        sorted_json = dict(sorted(decrypted_json.items()))
        formatted_text = ""  
        for key, label in sorted(KEY_LABELS.items()):
            if key in sorted_json:
                value = sorted_json[key]
                formatted_text += f"│[۞] {label}: {value}\n"
        inicio = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ipt)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
        final = "\n├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"

        formatted_output = inicio + formatted_text + final
        return formatted_output
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ipt.py <file.ipt>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path, "r") as file:
            encrypted_file_content = file.read().strip()
        decrypted_text = decrypt_ipt_file(encrypted_file_content, ipt_password)
        if "Error" not in decrypted_text:
            formatted_output = format_decrypted_json(decrypted_text)
            print(formatted_output)
        else:
            print(decrypted_text)
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
    except Exception as e:
        print(f"Error: {e}")
#Fungsi tools untuk apk cloudy Inject dan secondvpnlite

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json
import sys

def decrypt_and_filter(file_path, key_base64, iv_base64):
    try:
        # Read the encrypted text from the file
        with open(file_path, 'r') as file:
            encrypted_base64 = file.read()

        # Decode Base64 and decrypt
        encrypted = base64.b64decode(encrypted_base64)
        key = base64.b64decode(key_base64)
        iv = base64.b64decode(iv_base64)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        plaintext = unpad(decrypted, AES.block_size)

        try:
            decrypted_text = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            decrypted_text = plaintext.decode('latin-1')  # Try decoding using latin-1 encoding

        # Parse decrypted JSON content
        data = json.loads(decrypted_text)

        # Filter and format the desired information
        filtered_info = "\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.aro)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
        for key, value in data.items():
            filtered_info += f"│[۞] {key} : {value}\n"
        filtered_info += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"
        print(filtered_info)

    except FileNotFoundError:
        print("File not found.")
    except json.JSONDecodeError:
        print("Invalid JSON format.")
    except Exception as e:
        print("An error occurred:", e)

# Check if the correct number of command-line arguments is provided
if len(sys.argv) != 2:
    print("Usage: python script.py <file_path>")
    sys.exit(1)

# Get the file path from the command-line argument
file_path = sys.argv[1]

# Define your key and initialization vector (IV)
key_base64 = "LCdfvh2u/dKiiMEqc5IgI94kPacAy0WccVaWA6MCt9c="
iv_base64 = "G3z+oWcWTxe+Ggap/TvBhw=="

# Call the function to decrypt the encrypted text, filter JSON data, and write to a file
decrypt_and_filter(file_path, key_base64, iv_base64)

import base64
import json
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Fungsi dekripsi AES ECB
def aes_ecb_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)

# Fungsi XOR
def xor(b64text, key='**rVg7EkL~c2`D[aNn'): 
    def handle_unicode(text, index): 
        try: 
            left = ord(text)
            if left > 127: 
                key_length = len(key)

                # Mendapatkan dua karakter dari kunci untuk XOR
                first_right = ord(key[index % key_length])
                second_right = ord(key[(index + 1) % key_length])

                # Menghitung nilai high dan low surrogate
                high_surrogate = ((ord(text) - 0x10000) // 0x400) + 0xD800
                low_surrogate = ((ord(text) - 0x10000) % 0x400) + 0xDC00
                print("left: ",high_surrogate, "right: ",first_right)
                print("left: ",low_surrogate, "right: ",second_right)

                # Melakukan XOR pada setiap surrogate
                high_surrogate_xor = high_surrogate ^ first_right
                low_surrogate_xor = low_surrogate ^ second_right

                # Menggabungkan kedua hasil XOR, mengenkod ulang ke UTF-16, dan mendekod ulang ke karakter UTF-8
                char_surrogate_xor_pair = chr(high_surrogate_xor) + chr(low_surrogate_xor)
                unicode_char = char_surrogate_xor_pair.encode("utf-16", "surrogatepass").decode("utf-16")

                return unicode_char   
        except: 
            pass

        return None     

    plaintext = base64.b64decode(b64text).decode()
    key_length = len(key)
    
    cipherAscii = ""
    j = 0
    for i in range(len(plaintext)): 
        right = ord(key[j % key_length])
        left = ord(plaintext[i])

        surrogate_result = handle_unicode(plaintext[i], j)

        if surrogate_result: 
            cipherAscii += surrogate_result
            j += 2
        else: 
            print("left: ",left, "right: ", right)
            ascii_char = chr(left ^ right)
            cipherAscii += ascii_char
            j += 1

    return cipherAscii


def print_decrypted_hat_profile_info(file_content): 
    def get_decrypted_config(dec_args): 
        decrypted_text = aes_ecb_decrypt(**dec_args).decode("utf-8")
        decrypted_config = json.loads(decrypted_text)
        return decrypted_config
    
    dec_args = dict()
    dec_args["data"] = base64.b64decode(file_content)
    dec_args["key"] = base64.b64decode('zbNkuNCGSLivpEuep3BcNA==')
    
    config = get_decrypted_config(dec_args)

    #Profile Info Mapping
    profile_info = config["profilev5"]

    profile_info['connection_mode'] = xor(profile_info['connection_mode'])
    profile_info['custom_payload'] = xor(profile_info['custom_payload'])
    # sys.exit()
    profile_info['custom_sni'] = xor(profile_info['custom_sni'])
    profile_info['custom_host'] = xor(profile_info['custom_host'])

    #Protextras Mapping
    protextras = config["protextras"]

    decrypted_info = ''
    decrypted_info += "\n┌─[ https://t.me/enzodecode_bot ]─[~]\n└──╼[ Powered by: ~ ENZO ~SnifferProject ~]\n===============================\n"   

    for key, value in list(profile_info.items()) + list(protextras.items()):
        decrypted_info += f"[</>] [{key}] : {value}\n"
    
    decrypted_info += "===============================\n"

    return decrypted_info

# Fungsi untuk mendekripsi file .hat dan mengirimkan hasilnya ke pengguna
def decrypt_hat_file(file_content):
    decrypted_info = print_decrypted_hat_profile_info(file_content)
    return decrypted_info

if __name__ == "__main__": 
    file_p = open("./test1.hat", "r")
    file_content = file_p.read()
    file_p.close()

    decrypted_file = decrypt_hat_file(file_content)
    print(decrypted_file)
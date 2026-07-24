import sys
import base64
import json

class BaseZh_Encoder:
    @staticmethod
    def decode(string):
        decoded_string = ""
        for i, char in enumerate(string):
            i2 = i % 4
            if i2 == 0:
                decoded_string += chr(30482 ^ ord(char))
            elif i2 == 1:
                decoded_string += chr(14551 ^ ord(char))
            elif i2 == 2:
                decoded_string += chr(22566 ^ ord(char))
            else:
                decoded_string += chr(ord(char) ^ 0xFFFF)
        return decoded_string

def decode_and_add_18(encoded_string):
    decoded_modified_string = base64.b64decode(encoded_string)
    decoded_modified_string = bytes((x + 18) % 256 for x in decoded_modified_string)
    return decoded_modified_string

def safe_base64_decode(s):
    try:
        return base64.b64decode(s).decode('latin-1')
    except:
        return s

def decode_all_base64_values(config):
    for key, value in config.items():
        if isinstance(value, str):
            if value == "":
                config[key] = "enzo pro" 
            else:
                try:
                    decoded_value = base64.b64decode(safe_base64_decode(value)).decode('latin-1')
                    config[key] = decoded_value
                except:
                    pass
        elif isinstance(value, dict):
            decode_all_base64_values(value)


def main():
    if len(sys.argv) != 2:
        print("Usage: python ar.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        with open(file_path, 'r') as file:
            encoded_string = file.read()
                       
        decrypted_json = decode_and_add_18(encoded_string)

        # Parse JSON
        config = json.loads(decrypted_json)
               
        # Decrypt and decode values in the CONFIG object
        decode_all_base64_values(config)
        
    
        print("\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.aro)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────")

        try:
            server_config = json.loads(config["CONFIG"]["Server"])
            for key, value in server_config.items():
                decrypted_value = BaseZh_Encoder.decode(value)
                server_config[key] = decrypted_value
            config["CONFIG"]["Server"] = json.dumps(server_config)
        except:
            pass

        try:
            ps_install_config = json.loads(config["CONFIG"]["PSInstall"])
            for key, value in ps_install_config.items():
                # Lakukan pemrosesan yang diperlukan di sini
                pass
            config["CONFIG"]["PSInstall"] = json.dumps(ps_install_config)
        except:
            pass

        for key, value in config["CONFIG"].items():
            print(f"│[۞] {key}: {value}")

        print("├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n")  

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()


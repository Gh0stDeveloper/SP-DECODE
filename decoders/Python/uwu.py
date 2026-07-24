import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import sys

# Contraseña para la desencriptación
key_password = 'Ed'

# Función para desencriptar el archivo uwu
def decrypt_uwu_file(encrypted_uwu, password):
    try:
        # Verifica si el contenido es una cadena, si es así convierte a bytes
        if isinstance(encrypted_uwu, str):
            encrypted_uwu = encrypted_uwu.encode('utf-8')

        # Separa el contenido en secciones base64 y lo decodifica
        split_base64_contents = encrypted_uwu.split(b'.')
        split_contents = list(map(base64.b64decode, split_base64_contents))
        
        # Genera la clave de desencriptación usando PBKDF2
        decryption_key = PBKDF2(password.encode('utf-8'), split_contents[0], hmac_hash_module=SHA256)
        
        # Crea un cifrador AES en modo GCM con la nonce correcta
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
        
        # Desencripta el contenido y verifica la integridad
        decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])
        
        # Retorna el contenido desencriptado como texto UTF-8
        return decrypted_contents.decode('utf-8', 'ignore')
    except ValueError as e:
        print("Error decrypting file:", str(e))
        return None
    except Exception as e:
        print("Unexpected error:", str(e))
        return None

# Función para filtrar el contenido uwu
def filter_uwu_content(contents):
    try:
        filtered_contents = "\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.tnl)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
        lines = contents.split('\n')
        for line in lines:
            if line.strip().startswith("<entry"):
                key_value = line.strip().replace("<entry key=\"", "").replace("</entry>", "").replace('"/>', '').split("\">")
                if len(key_value) > 1:
                    key, value = key_value
                    filtered_contents += f"│[۞] {key}: {value}\n"
                else:
                    key = key_value[0]
                    filtered_contents += f"│[۞] {key}: ***\n"
        filtered_contents += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"
        return filtered_contents
    except Exception as e:
        return f"Error: {e}"

# Ejecución principal
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python uwu.py <archivo.uwu>")
        sys.exit(1)

    # Lee el archivo uwu proporcionado
    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as file:
            encrypted_content = file.read()

        # Desencripta el contenido usando la contraseña
        decrypted_content = decrypt_uwu_file(encrypted_content, key_password)
        
        if decrypted_content:
            # Filtra el contenido desencriptado
            filtered_content = filter_uwu_content(decrypted_content)
            print(filtered_content)
        else:
            print("No se pudo desencriptar el archivo.")

    except FileNotFoundError:
        print(f"Error: El archivo '{file_path}' no existe.")
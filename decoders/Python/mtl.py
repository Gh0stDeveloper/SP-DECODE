import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Clave de descifrado (puedes cambiar esta clave según sea necesario)
DECRYPTION_KEY = "Ed"

# Función para descifrar archivos MTL
def decrypt_mtl_file(encrypted_mtl, password):
    try:
        # Verificar que el input es un objeto byte
        if isinstance(encrypted_mtl, str):
            encrypted_mtl = encrypted_mtl.encode('utf-8')

        # Separar el contenido cifrado en partes
        split_base64_contents = encrypted_mtl.split(b'.')
        split_contents = list(map(base64.b64decode, split_base64_contents))
        
        # Construir la clave de descifrado usando PBKDF2
        decryption_key = PBKDF2(password.encode('utf-8'), split_contents[0], hmac_hash_module=SHA256)
        
        # Crear el objeto cipher AES con modo GCM y nonce adecuado
        cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
        
        # Realizar descifrado y verificación
        decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])
        
        # Devolver el resultado descifrado en formato texto UTF-8
        return decrypted_contents.decode('utf-8', 'ignore')
    except ValueError as e:
        print("Error decrypting file:", str(e))
        return None
    except Exception as e:
        print("Unexpected error:", str(e))
        return None

# Función para filtrar contenido MTL
def filter_mtl_content(contents):
    try:
        filtered_contents = "\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 \n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────"
        lines = contents.split('\n')
        for line in lines:
            if not line.strip().startswith("</properties>") and not line.strip().startswith("<?xml") and not line.strip().startswith("<!DOCTYPE") and not line.strip().startswith("<properties>"):
                if "<entry" in line and "{" in line and "}" in line:
                    # Exclude lines containing '<entry>' and JSON-like content from filtering
                    filtered_contents += line + "\n"
                elif "<entry" in line:
                    key_value = line.strip().replace("<entry key=\"", "").replace("</entry>", "").replace('"/>', '').split("\">")
                    if len(key_value) > 1:
                        key, value = key_value
                        filtered_contents += f"│[۞] {key}: {value}\n"
                    else:
                        key = key_value[0]
                        filtered_contents += f"│[۞] {key}: ***\n"
                elif "Arquivo de Configuração" not in line:  # Excluir líneas que contengan "Arquivo de Configuração"
                    filtered_line = line.replace("<comment/>", "").replace("</entry>", "")  # Eliminar '<comment/>' y '</entry>'
                    filtered_contents += filtered_line + "\n"
        filtered_contents += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"           
        return filtered_contents
    except Exception as e:
        return f"Error: {e}"

# Función principal
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python decrypt_mtl.py <encrypted_mtl_file>")
        sys.exit(1)

    encrypted_mtl_file = sys.argv[1]

    with open(encrypted_mtl_file, 'rb') as f:
        encrypted_mtl = f.read()

    decrypted_content = decrypt_mtl_file(encrypted_mtl, DECRYPTION_KEY)
    if decrypted_content:
        filtered_content = filter_mtl_content(decrypted_content)
        print(filtered_content)
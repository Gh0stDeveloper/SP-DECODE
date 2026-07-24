import sys
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Random import get_random_bytes
import json

class CriptografiaAES:
    alvo = bytes([0]*16)

    @staticmethod
    def decodificar_base64(s):
        resultado = base64.b64decode(s).decode('utf-8')
        return resultado

    @staticmethod
    def decodificar_bytes(barray):
        caracteres = "¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
        resultado = ""
        for b in barray:
            resultado += caracteres[(b & 240) >> 4]
            resultado += caracteres[b & 15]
        return resultado

    @staticmethod
    def decodificar_hexadecimal(barray):
        caracteres = "0123456789ABCDEF"
        resultado = ""
        for b in barray:
            resultado += caracteres[(b & 240) >> 4]
            resultado += caracteres[b & 15]
        return resultado

    @staticmethod
    def bytes_para_hexadecimal(bArr):
        caracteres = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
        caracteres2 = [' '] * (len(bArr) * 2)
        for i in range(len(bArr)):
            i2 = bArr[i] & 255
            i3 = i * 2
            caracteres2[i3] = caracteres[i2 >> 4]
            caracteres2[i3 + 1] = caracteres[i2 & 15]
        return ''.join(caracteres2)

    def codificar_ja(self, s):
        resultado = self.decodificar_bytes(bytes(s, encoding="utf8"))
        return resultado

    def codificar_ja_chaves(self, s):
        resultado = self.decodificar_hexadecimal(bytes(s, encoding="utf8"))
        return resultado

    @staticmethod
    def gerar_string(input_str):
        caracteres = "¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
        lista_caracteres = list(input_str)
        comprimento = len(input_str) // 2
        bArr = bytearray(comprimento)
        for i in range(comprimento):
            i2 = i * 2
            bArr[i] = (caracteres.index(lista_caracteres[i2]) * 16 + caracteres.index(lista_caracteres[i2 + 1])) & 255
        return bArr.decode('utf-8')

    @staticmethod
    def criar_digesto_sha256(input_str):
        message_digest = hashlib.sha256()
        message_digest.update(input_str.encode('utf-8'))
        digest = message_digest.digest()
        return digest

    @staticmethod
    def decifrar_bytes_chave_secreta(chave_secreta, iv, texto_cifrado):
        cipher = AES.new(key=chave_secreta, mode=AES.MODE_CBC, iv=iv)
        dados_decifrados = cipher.decrypt(texto_cifrado)
        return unpad(dados_decifrados, AES.block_size)

    def decifrar_string(self, str1, str2):
        string_gerada = self.gerar_string(str2)
        chave_ja = self.codificar_ja_chaves(str1)
        chave_secreta = self.criar_digesto_sha256(chave_ja)
        decifrar = base64.b64decode(string_gerada)
        descifrado = self.decifrar_bytes_chave_secreta(chave_secreta, self.alvo, decifrar)
        str3 = str(descifrado, encoding="utf8")
        return str3

    @staticmethod
    def cifrar_bytes_chave_secreta(chave_secreta, iv, texto):
        cipher = AES.new(chave_secreta, AES.MODE_CBC, iv)
        dados_padronizados = pad(texto, AES.block_size)
        dados_cifrados = cipher.encrypt(dados_padronizados)
        return dados_cifrados

    def cifrar_string(self, str1, str2):
        chave_ja = self.codificar_ja_chaves(str1)
        chave_secreta = self.criar_digesto_sha256(chave_ja)
        cifrar = self.cifrar_bytes_chave_secreta(chave_secreta, self.alvo, bytes(str2, encoding='utf-8'))
        encode = base64.b64encode(cifrar).decode('utf-8')
        codificar_ja = self.codificar_ja(encode)
        return codificar_ja
        
#AESKE2        
class AESCrypt:
    AES_MODE = AES.MODE_CBC
    AES_BLOCK_SIZE = 16
    HASH_ALGORITHM = 'SHA-256'
    IV = b'\x00' * AES_BLOCK_SIZE

    @staticmethod
    def generate_key(password):
        hashed_key = hashlib.sha256(password.encode()).digest()
        return hashed_key

    @staticmethod
    def pad_message(message):
        padding_length = AESCrypt.AES_BLOCK_SIZE - (len(message) % AESCrypt.AES_BLOCK_SIZE)
        padded_message = message + bytes([padding_length] * padding_length)
        return padded_message

    @staticmethod
    def unpad_message(padded_message):
        padding_length = padded_message[-1]
        return padded_message[:-padding_length]

    @staticmethod
    def decrypt(password, encoded_ciphertext):
        key = AESCrypt.generate_key(password)
        cipher = AES.new(key, AES.MODE_CBC, AESCrypt.IV)
        ciphertext = base64.b64decode(encoded_ciphertext)
        decrypted_message = cipher.decrypt(ciphertext)
        unpadded_message = AESCrypt.unpad_message(decrypted_message)
        return unpadded_message.decode()

def nm(file_path):
    # Pastikan indentasi yang benar untuk blok kode
    with open(file_path, 'r') as file:
        content = file.read()
    return content
    
if len(sys.argv) != 2:
    print("Usage: python script.py <file_path>")
    sys.exit(1)

# Get the file path from the command-line argument
file_path = sys.argv[1]

# Define the function fazer_requisicao(url) to read the content of the file
def fazer_requisicao(file_path):
    try:
        return nm(file_path)
    except FileNotFoundError:
        print("File not found.")
        return None

# Key and max attempts are defined as before
chave = "SimeliFamilyForLifeTime"
max_tentativas = 3
tentativa_atual = 1
entrada = None

# Attempt to read the content of the file
while tentativa_atual <= max_tentativas and entrada is None:
    entrada = fazer_requisicao(file_path)
    tentativa_atual += 1

if entrada is None:
    print("Failed after multiple attempts.")
    exit()

testes = CriptografiaAES()
res = testes.decifrar_string(chave, entrada)

# Hasil dekripsi pertama menggunakan CriptografiaAES
result_from_first_decryption = res  # res adalah hasil dekripsi pertama

# Dekripsi nilai-nilai dalam string JSON menggunakan AESCrypt kedua
aes_crypt = AESCrypt()
password = "new#Pa$$wd#4#Maky,sim?2024tech&(.);#@980well*..smk.now"  # P      

# Decrypt the values in the JSON string
# Dekripsi nilai-nilai dalam string JSON menggunakan AESCrypt kedua
decrypted_values = {}

for key in ["UDPServerIP", "ServerIP", "Payload", "Bug", "SNI", "ServerUser", "UDPServerUser", "UDPServerPass", "chaveKey", "serverNameKey", "dnsKey"]:
    encrypted_value = json.loads(result_from_first_decryption)[key]  # Ambil nilai yang sudah didekripsi dari hasil pertama
    decrypted_value = aes_crypt.decrypt(password, encrypted_value)  # Menggunakan AESCrypt kedua
    decrypted_values[key] = decrypted_value

# Print decrypted values
print("\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.sut)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────")
for key, value in decrypted_values.items():
    print(f"│[۞] [{key}]: {value}")

# Print additional values
additional_keys = ["TunnelType", "isMsg", "Message", "HardwareID", "Remind", "Exp", "mExp"]
for key in additional_keys:
    value = json.loads(result_from_first_decryption).get(key)
    if value is not None:
        print(f"│[۞] [{key}]: {value}")
print("├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n")  
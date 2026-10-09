import base64
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

IV = bytes([0] * 16)

def build_map(obfuscated, clear):
    mapping = {}
    for o, c in zip(obfuscated, clear):
        if o != c:
            mapping[o] = c
    return mapping
    
obf = "主tt畫s://u畫땬둣t二日s的为.xyz/u畫就的둣땬s/日s的为/小듌둣딨들둣中二天大듌く天中女大天땬둣듽.日s的为与没딸当国땀山"

clear = "https://updatejson.xyz/uploads/json/f5ac7a6e015406210da3.jsongibkm98"

CHAR_MAP = build_map(obf, clear)

def deobfuscate(text):
    for k, v in CHAR_MAP.items():
        text = text.replace(k, v)
    return text

TRANS_TABLE = str.maketrans(CHAR_MAP)

def deobfuscate(text):
    return text.translate(TRANS_TABLE)
     

def generate_key(password: str) -> bytes:
    """
    Equivalent Java:
    SHA-256(password)
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


def decrypt(password: str, data_b64: str) -> str:
    key = generate_key(password)
    #print(data_b64)
    try:
        encrypted = base64.b64decode(data_b64)
        cipher = AES.new(key, AES.MODE_CBC, IV)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    except Exception as e:
        print(e)
        #print(" - > " + data_b64)
        return data_b64

    return decrypted.decode("utf-8")

def recursive_decrypt(data, key):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and len(v) > 20 and "=" in v:
                dec = decrypt(key, v)
                if dec: data[k] = deobfuscate(dec)
            elif isinstance(v, (dict, list)): recursive_decrypt(v, key)
    elif isinstance(data, list):
        for item in data: recursive_decrypt(item, key)
    return data
    
def encrypt(password: str, plaintext: str) -> str:
    key = generate_key(password)

    cipher = AES.new(key, AES.MODE_CBC, IV)

    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))

    return base64.b64encode(encrypted).decode()

def decrypt_file(password: str, filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as f:
        data_b64 = f.read().strip()

    return decrypt(password, data_b64)
    
def stylize_math(text: str) -> str:
    """Compatibility fallback for missing historical banner helper."""
    return text


def dec_gold(config):
    password = "goldtunnel"
    decrypted = decrypt(password, config)
    
    data = json.loads(decrypted)
    data["network"] = json.loads(data["network"].replace("\\\"", "\"").replace("ALUKt53Zd7wN6SoBNpv2lw==", ""))
    decrypted = recursive_decrypt(data, password)
    
    return f"""╔━━━━━━━━━━━━━━━═╗
╠▸ ◉ *{stylize_math("Universal Decodez Bot")}* ◉
╠━━━━━━━━━━━━━━━ ★
╠▸ Code by : `𝕭𝖔𝖓𝖞 𝕸𝕷 🇨🇩`
╠▸ 𝑇𝑒𝑙𝑒𝑔𝑟𝑎𝑚 : `t.me/+vrk0HxI_av9iNDg0`
╚━━━━━━━━━━━━━━━═╝

╔━━━━━༺ - ༻━━━━━╗
╠▸ App Name : `Gold Tunnel`
╚━━━━━༺ - ༻━━━━━╝

{decrypted}"""

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        from pathlib import Path
        gold = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
    elif len(sys.argv) == 1:
        gold = input("Gold config : ")
    else:
        raise SystemExit("Usage: gold.py [file.gold]")
    print(dec_gold(gold))

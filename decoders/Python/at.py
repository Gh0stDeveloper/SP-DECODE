# ASH tunnel, Code by @bonyml (.at)

from Crypto.Cipher import AES
from binascii import unhexlify
import json

STATIC = b"AF4nnvvn10XpsrrR"

def dec(hex_data):
    data = unhexlify(hex_data)

    seed = data[:16]

    key1 = seed + STATIC

    nonce1 = data[16:28]
    blob1  = data[28:]

    gcm1 = AES.new(key1, AES.MODE_GCM, nonce=nonce1)

    tmp = gcm1.decrypt(blob1[:-16])
    # tag = blob1[-16:]

    key2 = seed

    nonce2 = tmp[:12]
    blob2  = tmp[12:]

    gcm2 = AES.new(key2, AES.MODE_GCM, nonce=nonce2)

    plain = gcm2.decrypt(blob2[:-16])

    return plain.decode()
    
def recursive_decrypt(data, key = ""):
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and len(v) > 10: #and "=" in v:
                try:
                    decr = dec(v)
                    #print(v)
                    if decr: data[k] = decr
                    else: data[k] = "" 
                except Exception as e:
                    pass
                    #print(e)
            elif isinstance(v, (dict, list)): recursive_decrypt(v)
            #else: print(v)
    elif isinstance(data, list):
        for item in data: recursive_decrypt(item, key)
    return data
    
def ash_dec(config):
    file = dec(config)
    js = json.loads(file)
    rc = recursive_decrypt(js)
    
    return rc


# Offline file adapter for the existing ASH Tunnel algorithm.
# The decoder's decrypt logic is intentionally unchanged.
def run(file_bytes: bytes):
    try:
        decoded = ash_dec(file_bytes.decode("ascii").strip())
        return json.dumps(decoded, indent=2, ensure_ascii=False)
    except (ValueError, UnicodeError, KeyError, TypeError):
        return None


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Decode an offline .at profile")
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        output = run(args.file.read_bytes())
    except OSError as exc:
        parser.exit(2, f"File read error: {exc}\n")
    if not output:
        parser.exit(1, "Could not decode .at file\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

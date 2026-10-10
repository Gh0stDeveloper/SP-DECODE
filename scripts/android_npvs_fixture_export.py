#!/usr/bin/env python3
"""Export a synthetic, signed NPVS v5 file and the original Python golden JSON."""
import argparse
import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from decoders.Python.npvs import _whitebox_block, _canonical, decode_npvs

def seal(key,nonce,plain,aad):
    cipher=ChaCha20_Poly1305.new(key=key,nonce=nonce)
    cipher.update(aad)
    enc,tag=cipher.encrypt_and_digest(plain)
    return enc+tag

def url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def key(dek,context,label,id):
    return HKDF(dek,32,context,SHA256,context=b"NPV-fields-v1/"+label+b"/"+struct.pack(">H",id))

def export(folder:Path):
    private=ECC.generate(curve="P-256")
    pub=private.public_key().export_key(format="SEC1",compress=True)
    assert len(pub)==33
    cid=bytes(range(16))
    salt=bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce=bytes.fromhex("00112233445566778899aabb")
    dek=bytes(range(32))
    kdk=hashlib.sha256(b"npvtunnel/appkey/v2 "+_whitebox_block(salt)+cid).digest()
    wrapped_nonce=bytes.fromhex("0a0b0c0d0e0f101112131415")
    wrapped=wrapped_nonce+seal(kdk,wrapped_nonce,dek,salt)
    prefix=b"\x01"+cid+pub+b"\x02"+b"\x00\x00"+b"\x00\x02"+salt+wrapped
    assert len(prefix)==131
    policy={"onlyMobileNetwork":False,"attestationLevel":"",
            "expiresAt":None,"displayMessage":"","customServerMessage":"",
            "configVersion":1}
    metadata={"issuedAt":"2026-10-09","policy":policy}
    mkey=HKDF(dek,32,nonce,SHA256,context=b"NPVS-v5/metadata")
    plaintext=json.dumps(metadata,ensure_ascii=False,separators=(",",":")).encode()
    ciphertext=seal(mkey,nonce,plaintext,prefix)
    header=prefix+struct.pack(">I",len(ciphertext))+ciphertext
    source={"v":5,"configId":url(cid),"issuedAt":metadata["issuedAt"],
            "creator":{"fp":url(hashlib.sha256(pub).digest()),"pk":url(pub)},
            "policy":policy,"recipients":None}
    context=hashlib.sha256(b"NPVS-v5/source-fields-v1/"+_canonical(source)+nonce).digest()
    body=bytearray(b"NPF\x01"+context+struct.pack(">H",3))
    for id,value in [(1,"example.invalid"),(2,443),
                     (65535,{"configs":[{"server":1,"port":2}]})]:
        clear=json.dumps(value,separators=(",",":")).encode()
        aad=b"NPV-fields-v1/record/"+context+struct.pack(">HI",id,len(clear))
        payload=seal(key(dek,context,b"field",id),bytes(12),clear,aad)
        body+=struct.pack(">HI",id,len(payload))+payload
    body+=hmac.new(key(dek,context,b"inventory",0),body,hashlib.sha256).digest()
    unsigned=b"NPVS"+b"\x05"+struct.pack(">I",len(header))+header+nonce+struct.pack(">I",len(body))+body
    signature=DSS.new(private,"deterministic-rfc6979",encoding="binary").sign(SHA256.new(unsigned))
    profile=unsigned+signature
    expected={"metadata":metadata,"document":{"configs":[{"server":"example.invalid","port":443}]}}
    assert decode_npvs(profile)==expected
    folder.mkdir(parents=True,exist_ok=True)
    (folder/"npvs-v5-appkey.npvs").write_bytes(profile)
    (folder/"npvs-v5-appkey.json").write_text(json.dumps(expected,ensure_ascii=False,indent=2)+"\n","utf-8")
    print("NPVS signed reference fixture:",len(profile),"bytes")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",required=True,type=Path)
    export(parser.parse_args().output_dir)

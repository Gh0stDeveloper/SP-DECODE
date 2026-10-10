"""Positive vectors for WyrLite, WyrVPN, IntVPN, FTHP, AR Pro, EC, XOR and text."""
from __future__ import annotations
import base64
import hashlib
import json
import os
import struct
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

from decoders.Python import (
    wyrlite, wyrvpn, intvpn, fthp, ar_pro, ec, xor_family,
    falcon_links, npvt_links, happ_links
)


def b64(content: bytes) -> str:
    return base64.b64encode(content).decode("ascii")


def ec_encrypt(clear: bytes) -> bytes:
    """Standard XXTEA encrypt with little-endian original-length trailer."""
    key = ec.KEY[:16].ljust(16, b"\x00")
    length=len(clear)
    padded=clear+b"\x00"*((-length)%4)+struct.pack("<I",length)
    v=list(struct.unpack("<%dI"%(len(padded)//4),padded))
    k=struct.unpack("<4I",key)
    mask=0xffffffff
    n=len(v)-1
    total=0
    for _ in range(6+52//(n+1)):
        total=(total+ec.DELTA)&mask
        e=(total>>2)&3
        z=v[n]
        for p in range(n):
            y=v[p+1]
            mx=(((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((total^y)+(k[(p&3)^e]^z))
            v[p]=(v[p]+mx)&mask
            z=v[p]
        y=v[0]
        mx=(((z>>5)^(y<<2))+((y>>3)^(z<<4))) ^ ((total^y)+(k[(n&3)^e]^z))
        v[n]=(v[n]+mx)&mask
    return struct.pack("<%dI"%len(v),*v)


class BatchCryptoSecondSix(unittest.TestCase):
    def test_wyrlite_chacha_and_aes_gcm(self):
        doc={"host":"wyrl.example","port":443}
        plaintext=json.dumps(doc).encode()
        nonce=bytes(range(12))
        c=ChaCha20_Poly1305.new(key=wyrlite.V2_HARDCODED_KEY,nonce=nonce)
        ciphertext,tag=c.encrypt_and_digest(plaintext)
        token=b64(nonce+tag+ciphertext)
        self.assertEqual(json.loads(wyrlite.run(("wyrlite://"+token).encode())),doc)

        key=hashlib.pbkdf2_hmac("sha256",b"acf54cb87cb8bca0",b"",10000,32)
        g=AES.new(key,AES.MODE_GCM,nonce=nonce)
        body,tag=g.encrypt_and_digest(plaintext)
        self.assertEqual(json.loads(wyrlite.run(b64(nonce+tag+body).encode())),doc)

    def test_wyrvpn_and_recursive_gcm(self):
        nonce=bytes(range(12))
        key=wyrvpn.KEY.encode()
        inside=AES.new(key,AES.MODE_GCM,nonce=nonce)
        cipher,tag=inside.encrypt_and_digest(b"nested.host")
        embedded=b64(b"v01"+nonce+cipher+tag)
        doc={"server":"wyr.example","sni":embedded,"port":443}
        cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
        body,tag=cipher.encrypt_and_digest(json.dumps(doc).encode())
        text="wyrvpn://"+b64(b"v01"+nonce+body+tag)
        decoded=json.loads(wyrvpn.run(text.encode()))
        self.assertEqual(decoded["server"],"wyr.example")
        self.assertEqual(decoded["sni"],"nested.host")

    def test_intvpn_nested(self):
        nonce=bytes(range(12))
        key=intvpn.K
        inside=AES.new(key,AES.MODE_GCM,nonce=nonce)
        ct,tag=inside.encrypt_and_digest(b"nested.int")
        nested="djAx"+b64(nonce)+b64(ct+tag)
        document={"Server":"int.example","Nested":{"sni":nested}}
        g=AES.new(key,AES.MODE_GCM,nonce=nonce)
        ct,tag=g.encrypt_and_digest(json.dumps(document).encode())
        link="intvpn://djAx"+b64(nonce)+b64(ct+tag)
        decoded=json.loads(intvpn.run(link.encode()))
        self.assertEqual(decoded["Server"],"int.example")
        self.assertEqual(decoded["Nested"]["sni"],"nested.int")

    def test_fthp_both_key_variants(self):
        for password in fthp.FTHP_KEYS:
            with self.subTest(password=password):
                salt=bytes(range(16))
                nonce=bytes(range(12))
                key=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,1000,16)
                c=AES.new(key,AES.MODE_GCM,nonce=nonce)
                encrypted,tag=c.encrypt_and_digest(b'{"host":"fthp.example"}')
                raw=".".join(map(b64,(salt,nonce,encrypted+tag))).encode()
                self.assertEqual(json.loads(fthp.run(raw)),{"host":"fthp.example"})

    def test_ar_pro_nested_field_and_msy(self):
        doc={"Server":"ar.example","Port":22}
        encrypted_field=AES.new(ar_pro.FIELD_KEY.key,AES.MODE_CFB,
                iv=ar_pro.FIELD_KEY.iv,segment_size=128).encrypt(b"nested.sni")
        doc["SNIHost"]=b64(encrypted_field)
        c=AES.new(ar_pro.MAIN_KEY.key,AES.MODE_CBC,ar_pro.MAIN_KEY.iv)
        raw=b64(c.encrypt(pad(json.dumps(doc).encode(),16)))
        decoded=json.loads(ar_pro.run(("msy://"+raw).encode()))
        self.assertEqual(decoded["Server"],"ar.example")
        self.assertEqual(decoded["SNIHost"],"nested.sni")

    def test_ec_standard_xxtea(self):
        document={"Server":"ec.example","Enabled":False,"Port":443}
        raw=b64(ec_encrypt(json.dumps(document).encode()))
        self.assertEqual(json.loads(ec.run(raw.encode())),document)

    def test_xor_and_all_nine_schemes(self):
        doc={"host":"xor.example","enabled":True}
        clear=json.dumps(doc).encode()
        encrypted=bytes(c ^ xor_family.XORDecoder.XOR_KEY[i%len(xor_family.XORDecoder.XOR_KEY)]
                        for i,c in enumerate(clear)).hex()
        self.assertEqual(json.loads(xor_family.run(encrypted.encode())),doc)
        for prefix in xor_family.SCHEMES:
            with self.subTest(prefix=prefix):
                self.assertEqual(json.loads(xor_family.decode_text(prefix+encrypted)),doc)

    def test_falcon_and_npvt_npvs1(self):
        doc={"Server":"falcon.example"}
        link=falcon_links.PREFIX+b64(json.dumps(doc).encode())
        self.assertEqual(json.loads(falcon_links.decode_text(link)),doc)
        encoded=b64(b'{"server":"nested.npvs1"}')
        outer={"Server":"npvt.example","Profile":"npvs1:"+encoded}
        text="npvt-ssh://"+b64(json.dumps(outer).encode())
        result=json.loads(npvt_links.decode_text(text))
        self.assertEqual(result["Profile"]["server"],"nested.npvs1")
        self.assertEqual(json.loads(npvt_links.decode_text(
            "dns://"+b64(json.dumps(outer).encode())))["Server"],"npvt.example")

    def test_happ_rsa_injected_local_keys_no_http(self):
        key=RSA.generate(1024)
        doc={"mode":"happ","Server":"happ.example"}
        c=PKCS1_v1_5.new(key.public_key())
        link="happ://crypt/"+b64(c.encrypt(json.dumps(doc).encode()))
        pem=key.export_key().decode("ascii")
        with patch.dict(os.environ,{"SPDECODE_HAPP_KEYS_JSON":json.dumps({"crypt":pem})}):
            self.assertEqual(json.loads(happ_links.decode_text(link)),doc)
        with patch.dict(os.environ,{"SPDECODE_HAPP_KEYS_JSON":"{}"}):
            self.assertIsNone(happ_links.decode_text(link))


if __name__=="__main__":
    unittest.main()

"""Synthetic encrypted profiles for Sentinel, ITV, EUT, V2Box, SlipNet, Juan."""
from __future__ import annotations
import base64
import gzip
import hashlib
import hmac
import json
import os
import struct
import unittest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from decoders.Python import sentinel, itv, eut, v2box_export, slipnet, juanscript


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class BatchCryptoFirstSix(unittest.TestCase):
    def test_sentinel_outer_xor_reverse_inner_authenticated(self):
        key_salt=bytes(range(16))
        key=hashlib.sha256(sentinel.KEY_A+key_salt).digest()
        iv=bytes(range(12))
        document={"Server":"sentinel.example","Port":22,"Username":"ghost"}
        gcm=AES.new(key,AES.MODE_GCM,nonce=iv)
        ciphertext,tag=gcm.encrypt_and_digest(json.dumps(document).encode())
        raw=ciphertext+tag
        signature=hmac.digest(key,iv+raw,"sha256")
        outer={"version":1,"name":"Synthetic","configData":{
          "keySalt":b64(key_salt),"iv":b64(iv),"hmac":b64(signature),"data":b64(raw)}}
        clear=b"STCF"+bytes([1])+json.dumps(outer).encode()
        arr=bytearray(x ^ sentinel.KEY_A[i%32] for i,x in enumerate(clear))
        for i in range(0,((len(arr)-1)//32)*32+1,32):
            if i+16<len(arr):
                arr[i:i+16]=arr[i:i+16][::-1]
        decoded=json.loads(sentinel.run(bytes(arr)))
        self.assertEqual(decoded["configData"]["Server"],"sentinel.example")
        self.assertIn("name",decoded)
        arr[-1]^=1
        self.assertIsNone(sentinel.run(bytes(arr)))

    def test_itv_xml_fields_from_source_container(self):
        key=bytes(range(32))
        iv=bytes(range(12))
        clear=b'<entry key="Host">itv.example</entry><entry key="Enable">true</entry>'
        ciphertext=AES.new(key,AES.MODE_GCM,nonce=iv).encrypt(clear)
        output=itv.run(key+iv+ciphertext)
        self.assertIsNotNone(output)
        self.assertIn("Host = itv.example",output)
        self.assertIn("Enable = true",output)

    def test_eut_nested_aes_cbc_config(self):
        key=eut.EUTDecoder.pad_key(eut.EUTDecoder.AES_KEY)
        iv=bytes(range(16))
        inner_plain=json.dumps({"host":"eut.example","port":443}).encode()
        inner_b64=b64(AES.new(key,AES.MODE_CBC,iv).encrypt(pad(inner_plain,16)))+":"+b64(iv)
        wrapper=json.dumps({"settings":inner_b64}).encode()
        body=b64(AES.new(key,AES.MODE_CBC,iv).encrypt(pad(wrapper,16)))+":"+b64(iv)
        decoded=json.loads(eut.run(("eut-settings://"+body).encode()))
        self.assertEqual(decoded["settings"]["host"],"eut.example")
        self.assertEqual(decoded["settings"]["port"],443)

    def test_v2box_unlocked_and_password_variant(self):
        config={"host":"v2box.example","port":443}
        for password in (None,"user selected password"):
            with self.subTest(protected=password is not None):
                key=v2box_export.V2BOX_KEY if password is None else hashlib.sha256(password.encode()).digest()
                nonce=bytes(range(12))
                gcm=AES.new(key,AES.MODE_GCM,nonce=nonce)
                ct,tag=gcm.encrypt_and_digest(json.dumps(config).encode())
                payload={"magic":"v2box_export","nonce":b64(nonce),"tag":b64(tag),
                         "ciphertext":b64(ct),"isPasswordProtected":password is not None}
                file_data=b64(json.dumps(payload).encode()).encode()
                decoded=v2box_export.decode_file(file_data,password=password)
                self.assertEqual(decoded,config)
                if password is not None:
                    self.assertTrue(v2box_export.decode_file(file_data)["__need_password__"])
                    self.assertIsNone(v2box_export.decode_file(file_data,password="wrong"))
                else:
                    self.assertEqual(json.loads(v2box_export.run(file_data)),config)

    def test_slipnet_authenticated_skip_byte_and_regular_header(self):
        parts=[""]*44
        parts[0]="3"
        parts[1]="SSH"
        parts[2]="Profile"
        parts[3]="slip.example"
        parts[14]="user"
        parts[15]="password"
        clear="|".join(parts).encode()
        for first_byte in (False,True):
            with self.subTest(first_byte=first_byte):
                nonce=bytes(range(12))
                gcm=AES.new(bytes.fromhex(
                  "214f052025b2f949605a5429ec3d5fa80c2022c168ad946e68852d447214dbd3"),
                  AES.MODE_GCM,nonce=nonce)
                encrypted,tag=gcm.encrypt_and_digest(clear)
                packed=(b"\x01" if first_byte else b"")+nonce+encrypted+tag
                decoded=json.loads(slipnet.run(("slipnet-enc://"+b64(packed)).encode()))
                self.assertEqual(decoded["ssh_user"],"user")
                self.assertEqual(decoded["domain"],"slip.example")

    def test_juan_mobi_gzip_and_checksum(self):
        document={"server":"juan.example","port":443}
        salt=bytes(range(16))
        nonce=bytes(range(12))
        key=hashlib.pbkdf2_hmac("sha256",juanscript.DEFAULT_PASSWORD.encode(),
                               salt,120000,dklen=32)
        cipher=AES.new(key,AES.MODE_GCM,nonce=nonce)
        body,tag=cipher.encrypt_and_digest(gzip.compress(json.dumps(document).encode()))
        encoded=struct.pack(">I",16)+salt+struct.pack(">I",12)+nonce+body+tag
        token=base64.b64encode(encoded).decode().rstrip("=")
        digest=hashlib.sha256(token.encode()).hexdigest()[:16]
        for prefix in ("juanscript://","mobi://",""):
            result=juanscript.run((prefix+"2:"+token+"."+digest).encode())
            self.assertEqual(json.loads(result),document)


if __name__=="__main__":
    unittest.main()

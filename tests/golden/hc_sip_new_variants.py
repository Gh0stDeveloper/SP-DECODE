"""Authorized synthetic fixtures for HTTP Custom HCCFG and SocksIP VER8.

No real third-party configurations, HWIDs, passwords or user tokens.
Positive self-roundtrips here are NOT third-party exporter certification.
"""
from __future__ import annotations

import base64
import json
import struct
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad

from decoders.Python import _hc_hccfg as hc
from decoders.Python.sockip import SIP_AES_KEY, SIP_VER8_KEY
from tests.golden.a23_batch6 import sip_file
from tests.golden.a23_generators import httpcustom_bytes

NONCE_MAIN=bytes(range(24))
NONCE_PROFILE=bytes(range(24,48))
NONCE_OUTER=bytes(range(48,72))
NONCE_SIP=b"spdecodev8!!"
S4_SYNTHETIC_PASSWORD="Synthetic-S4-HCCFG-Test-Only"


def aead(key: bytes, nonce: bytes, aad: bytes, plain: bytes) -> bytes:
    c=ChaCha20_Poly1305.new(key=key,nonce=nonce)
    c.update(aad)
    ct,tag=c.encrypt_and_digest(plain)
    return ct+tag


def hpc1() -> bytes:
    def txt(value: str) -> bytes:
        raw=value.encode("utf-8")
        return struct.pack(">I", len(raw))+raw
    return (b"HPC1"+struct.pack(">I", 11)+
        txt("Synthetic HCCFG")+txt("ssh")+txt("example.org")+
        struct.pack(">I",443)+txt("demo")+txt("dummy")+
        txt("GET / HTTP/1.1")+txt('{"sni":"example.org"}')+
        struct.pack(">I",3)+struct.pack(">Q",1700000000000)+txt("ssh"))


def hccfg_file(schema: int=1,schedule: str="n1",password: str | None=None) -> bytes:
    assert schema in (1,2,5,7)
    assert schedule in ("n1","n7")
    env={
        "a":"HCCFG","b":schema,
        "c":"XCHACHA20P1305" if schema==1 else "s1",
        "d":"NATIVE-HKDF-SHA256" if schema==1 else "h1",
        "e":schedule,"f":["tcp"],"g":bytes(range(32)).hex(),
        "h":int(password is not None),"n":864,
    }
    if password is not None:
        env.update({"k":"ARGON2ID13","l":2,"m":8*1024*1024})
    key,aad=hc._derive(env,password,None)
    env["i"]={
        "a":"m0","b":NONCE_MAIN.hex(),
        "c":aead(key,NONCE_MAIN,aad+b"\x00m0",
                 b'{"g":{"a":"free","m":false}}').hex()
    }
    env["j"]=[{
        "a":"s0","b":NONCE_PROFILE.hex(),
        "c":aead(key,NONCE_PROFILE,aad+b"\x00s0",hpc1()).hex()
    }]
    return (NONCE_OUTER+
        aead(hc._outer_key(),NONCE_OUTER,hc.OUTER_AAD,
             json.dumps(env,separators=(",",":")).encode("utf-8")))


# All values below are artificial, never derived from real files or device IDs.
SYNTHETIC_HWID = "A" * 32
NONCE_SLOT = bytes(range(72,96))
NONCE_HPR = bytes(range(96,120))


def hccfg_hwid_file(password: str | None = None) -> bytes:
    """Synthetic HTTP Custom 7.11.19 stream-v3 with HWID or dual lock.

    Builds the wrapping key independently from _derive(), then verifies it
    using the reference decoder; no production export is embedded.
    """
    import hashlib
    import hmac
    env = {
        "a":"HCCFG", "b":7, "c":"s1", "d":"h1", "e":"n8",
        "f":["ssh","profiles"], "g":bytes(range(32)).hex(),
        "h":int(password is not None), "n":885,
    }
    if password is not None:
        env.update({"k":"ARGON2ID13","l":2,"m":8*1024*1024})
    seed=bytes.fromhex(env["g"])
    hw=SYNTHETIC_HWID.encode("utf-8")
    transcript=(b"HCCFG\\0"+hc.PKG+b"\\0"+b"1\\0"+b"ssh,profiles\\0"+
                b"885\\0"+b"hwid\\0"+hw+b"\\0"+seed)
    intermediate=hmac.new(hc.N7_HMAC_KEY,
        b"\\xd3"+hc.C0_PREFIX[:32]+transcript,hashlib.sha256).digest()
    protection=b"|0"
    if password is not None:
        from argon2.low_level import Type, hash_secret_raw
        intermediate+=hash_secret_raw(password.encode(),seed[:16],time_cost=2,
            memory_cost=8192,parallelism=1,hash_len=32,type=Type.ID,version=19)
        protection=b"|1|ARGON2ID13|2|8388608"
    info=b"app-config|n8|"+hc.PKG+b"|1|ssh,profiles|885|hwid|"+hw
    wrapped_key=hc._hkdf(intermediate,seed,info)
    aad=(b"HCCFG|7|XCHACHA20P1305|NATIVE-HKDF-SHA256|n8|"+
         hc.PKG+b"|1|ssh,profiles"+protection+b"|885")
    section_key=bytes(reversed(range(32)))
    env["o"]=[{
        "a":NONCE_SLOT.hex(),
        "b":aead(wrapped_key,NONCE_SLOT,aad+b"\\x00w",section_key).hex(),
    }]
    env["i"]={"a":"m0","b":NONCE_MAIN.hex(),
        "c":aead(section_key,NONCE_MAIN,aad+b"\\x00m0",
            b'{"g":{"a":"free","m":false}}').hex()}
    payload=b"HPR1"+NONCE_HPR+aead(section_key,NONCE_HPR,
        aad+b"\\x00s0:r",hpc1())
    env["j"]=[{"a":"s0","b":NONCE_PROFILE.hex(),
        "c":aead(section_key,NONCE_PROFILE,aad+b"\\x00s0",payload).hex()}]
    body=json.dumps(env,separators=(",",":")).encode("utf-8")
    logical=NONCE_OUTER+hc._stream_xor(body,hc.OUTER_KEY_V3,NONCE_OUTER)+bytes(16)
    return logical.decode("latin-1").encode("utf-8")


def sip_ver8_file() -> bytes:
    # Reuse the historically supported Java Object Serialization baseline.
    enc=base64.b64decode(sip_file())
    java=unpad(AES.new(SIP_AES_KEY,AES.MODE_ECB).decrypt(enc),16)
    c=AES.new(SIP_VER8_KEY,AES.MODE_GCM,nonce=NONCE_SIP)
    ciphertext,tag=c.encrypt_and_digest(java)
    return base64.b64encode(AES.new(SIP_AES_KEY,AES.MODE_ECB)
        .encrypt(pad(b"VER8"+NONCE_SIP+ciphertext+tag,16)))


def export_android(output_dir):
    from pathlib import Path
    output_dir=Path(output_dir)
    output_dir.mkdir(parents=True,exist_ok=True)
    for filename,raw in {
        "variant-hc-hccfg.hc":hccfg_file(),
        "variant-hc-hccfg-n7.hc":hccfg_file(7,"n7"),
        "variant-hc-hccfg-password.hc":hccfg_file(password=S4_SYNTHETIC_PASSWORD),
        "variant-hc-hccfg-hwid.hc":hccfg_hwid_file(),
        "variant-hc-hccfg-dual.hc":hccfg_hwid_file(password=S4_SYNTHETIC_PASSWORD),
        "variant-hc-legacy.hc":httpcustom_bytes(),
        "variant-sip-ver8.sip":sip_ver8_file(),
        "variant-sip-legacy.sip":sip_file(),
    }.items():
        (output_dir/filename).write_bytes(raw)

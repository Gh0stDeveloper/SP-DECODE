"""Batch 7 — ten deterministic synthetic inputs; no real accounts or exports.

The only source cryptographic material used is already present in SP-DECODE.
The input bytes are NOT evidence of current vendor export compatibility.
NPV whitebox is loaded from the fixed legacy embedded blob (pickle risk).
"""
from __future__ import annotations
import base64
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from Crypto.Cipher import AES, Blowfish
from Crypto.Util.Padding import pad

ROOT=Path(__file__).resolve().parents[2]
SUFFIXES=("ehi","epro","gold","npv2","npv4","npvt","roy","sut","tvt","xtp")
SCRIPTS={
 "ehi":"decoders/Python/HTTPINJECTOR.py","epro":"decoders/JavaScript/modulepro.js",
 "gold":"decoders/Python/gold.py","npv2":"decoders/JavaScript/chicosp.js",
 "npv4":"decoders/Python/NPVTUNNEL.py","npvt":"decoders/Python/NPVTUNNEL.py",
 "roy":"decoders/Python/xtproy.py","sut":"decoders/Python/sut.py",
 "tvt":"decoders/JavaScript/rez.js","xtp":"decoders/Python/xtproy.py"}
RUNTIMES={s:("node" if s in ("epro","npv2","tvt") else "python") for s in SUFFIXES}
CASE_SUFFIXES={"batch7-"+s:s for s in SUFFIXES}
EXAMPLE={"Host":"example.org","Port":443}

def _compact(obj):
    return json.dumps(obj,separators=(",",":"),ensure_ascii=False)

def _xxtea_encrypt(plain:bytes,key:bytes)->bytes:
    """Inverse of the audited EHI _xxtea_decrypt, length word included."""
    n0=(len(plain)+3)//4
    v=list(struct.unpack("<%dI"%n0,plain.ljust(n0*4,b"\0"))) + [len(plain)]
    n=len(v)
    k=struct.unpack("<4I",key.ljust(16,b"\0")[:16])
    delta=0x9e3779b9; q=6+52//n; su=0;z=v[-1];mask=0xffffffff
    while q:
        q-=1;su=(su+delta)&mask;e=(su>>2)&3
        for p in range(n-1):
            y=v[p+1]
            mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((su^y)+(k[(p&3)^e]^z)))&mask
            v[p]=(v[p]+mx)&mask;z=v[p]
        y=v[0]
        mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^((su^y)+(k[((n-1)&3)^e]^z)))&mask
        v[-1]=(v[-1]+mx)&mask;z=v[-1]
    return struct.pack("<%dI"%n,*v)

def ehi_bytes():
    from decoders.Python.HTTPINJECTOR import EHIConstants as C
    raw=_compact({"overwriteServerData":"example.org","Port":443}).encode()
    raw2=_xxtea_encrypt(raw,C.EOO_MASTER_KEY)
    iv=bytes(range(16))
    l2=AES.new(C.L2_KEY_STATIC,AES.MODE_CBC,iv).encrypt(pad(raw2,16))
    envelope=base64.b64encode(iv).decode()+":synthetic:"+base64.b64encode(l2).decode()
    l1=AES.new(C.L1_KEY,AES.MODE_CBC,C.BYPASS_IVS[0]).encrypt(pad(envelope.encode(),16))
    name=b"ehi";extra=b"offline"
    return (struct.pack(">H",len(name))+name+bytes(8)+
        struct.pack(">H",len(extra))+extra+bytes(8)+
        struct.pack(">I",len(l1))+bytes(8)+l1)

def npv_bytes(suffix):
    from decoders.Python.NPVTUNNEL import load_whitebox_state,whitebox_encrypt_block
    p2,p3,p4,p5=load_whitebox_state()
    iv=bytearray(bytes(range(16)))
    data=_compact({"Server":"example.org","Port":443}).encode()
    out=bytearray()
    for i,b in enumerate(data):
        if i%16==0:
            key=whitebox_encrypt_block(iv,p2,p3,p4,p5)
            for j in range(15,-1,-1):
                iv[j]=(iv[j]+1)&255
                if iv[j]:break
        out.append(b^key[i%16])
    body=base64.b64encode(bytes(range(16))+out)
    return (b"NPVT1" if suffix=="npv4" else b"NPVTSUB1")+b"synthetic,"+body

def _xtp_encode(clear:str,password="tekidoer"):
    alpha="¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
    encoded=password.encode().hex().upper().encode()
    key=hashlib.sha256(encoded).digest()
    cipher=AES.new(key,AES.MODE_CBC,bytes(16)).encrypt(pad(clear.encode(),16))
    b64=base64.b64encode(cipher)
    return "".join(alpha[b>>4]+alpha[b&15] for b in b64).encode("utf-8")

def royal_bytes():return _xtp_encode(_compact(EXAMPLE))

def sut_bytes():
    keys=("UDPServerIP","ServerIP","Payload","Bug","SNI","ServerUser",
          "UDPServerUser","UDPServerPass","chaveKey","serverNameKey","dnsKey")
    pw="new#Pa$$wd#4#Maky,sim?2024tech&(.);#@980well*..smk.now"
    key=hashlib.sha256(pw.encode()).digest()
    values={s:base64.b64encode(AES.new(key,AES.MODE_CBC,bytes(16)).encrypt(
       pad(("example.org" if s=="ServerIP" else "dummy").encode(),16))).decode() for s in keys}
    values["TunnelType"]="A23 synthetic"
    return _xtp_encode(_compact(values),"SimeliFamilyForLifeTime")

def gold_bytes():
    key=hashlib.sha256(b"goldtunnel").digest()
    content={"network":_compact({"Host":"example.org","Port":443}),"name":"A23 synthetic"}
    return base64.b64encode(AES.new(key,AES.MODE_CBC,bytes(16)).encrypt(
      pad(_compact(content).encode(),16)))

def epro_bytes():
    keyfile=json.loads((ROOT/"cfg/keyFile.json").read_text())
    p=keyfile["ePro"][0][0].encode()
    key=hashlib.sha1(p).digest()[:16]
    raw="[splitConfig]".join(("GET example.org","example.org:443","false",
       "false","0","false","A23 synthetic","dummy@example.org"))
    return AES.new(key,AES.MODE_ECB).encrypt(pad(raw.encode(),16))

def npv2_bytes():
    # The historical decoder subtracts the key character code from every
    # UTF-8 decoded character. ASCII-only inputs avoid Unicode normalization.
    keys=json.loads((ROOT/"cfg/keyFile.json").read_text())["npv2"]
    raw=_compact({"vmess":{"configType":0,"address":"example.org",
       "port":443,"remarks":"A23 synthetic"}})
    # Use a SOURCE-specific small Node helper for JS code-unit parity.
    script=r"""
const fs=require('fs');
const k=JSON.parse(fs.readFileSync('cfg/keyFile.json','utf8')).npv2[0];
const text=process.argv[1];let out='';
for(let i=0;i<text.length;i++)out+=String.fromCharCode(text.charCodeAt(i)+k.charCodeAt(i%k.length));
process.stdout.write(out);
"""
    return subprocess.check_output(["node","-e",script,raw],cwd=ROOT,timeout=8)

def tvt_bytes():
    # Historical TEA self-roundtrip using the SOURCE implementation.
    return subprocess.check_output(["node",str(ROOT/"tests/golden/a23_batch5_rez.cjs")],
                                   cwd=ROOT,timeout=12)

GENERATORS={
 "batch7-ehi":ehi_bytes,"batch7-epro":epro_bytes,"batch7-gold":gold_bytes,
 "batch7-npv2":npv2_bytes,"batch7-npv4":lambda:npv_bytes("npv4"),
 "batch7-npvt":lambda:npv_bytes("npvt"),
 "batch7-roy":royal_bytes,"batch7-sut":sut_bytes,
 "batch7-tvt":tvt_bytes,"batch7-xtp":royal_bytes,
}

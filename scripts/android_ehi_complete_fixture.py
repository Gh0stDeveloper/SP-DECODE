#!/usr/bin/env python3
"""Regression for previously missing .ehi plaintext fields and multiline JSON.

Synthetic bypass-IV HTTP Injector profile. Source encryption is the exact
legacy reference; the fixture is NOT user-exported and carries no credentials.
"""
from __future__ import annotations

import argparse
import base64
import json
import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from decoders.Python.HTTPINJECTOR import EHIConstants as C, run
from tests.golden.a23_batch7 import _xxtea_encrypt
from scripts.android_ehi_standard_fixture import encode_field


def make() -> tuple[bytes, str, dict]:
    salt="EVZJNI"
    profile={
        "configSalt":salt,
        "serverHost":encode_field("primary.example.invalid",salt),
        "plaintextHost":"backup.example.invalid",
        "httpPayload":"GET /api HTTP/1.1\r\nHost: sni.example.invalid\r\n\r\nsynthetic body",
        "unknownFormat":"plain:synthetic-profile-not-custom-base64",
        "overwriteServerData":{
            "servers":[{"host":"edge.example.invalid","port":443},
                       {"host":"backup.example.invalid","port":8443}],
            "metadata":{"active":True,"nested":{"mode":"tls","retries":0}}
        },
        "serverPort":443,
        "enabled":False,
        "nullable":None,
        "finalField":"LAST_FIELD_MUST_SURVIVE"
    }
    raw=json.dumps(profile,separators=(",",":"),ensure_ascii=False).encode("utf-8")
    inner=_xxtea_encrypt(raw,C.EOO_MASTER_KEY)
    inner_iv=bytes(range(16))
    inner_cipher=AES.new(C.L2_KEY_STATIC,AES.MODE_CBC,inner_iv).encrypt(pad(inner,16))
    envelope=base64.b64encode(inner_iv).decode()+":synthetic:"+base64.b64encode(inner_cipher).decode()
    first=AES.new(C.L1_KEY,AES.MODE_CBC,C.BYPASS_IVS[0]).encrypt(pad(envelope.encode("utf-8"),16))
    def ju(v:bytes)->bytes:return struct.pack(">H",len(v))+v
    output=ju(b"ehi")+bytes(8)+ju(b"offline")+bytes(8)+struct.pack(">I",len(first))+bytes(8)+first
    text=run(output)
    if text is None:raise AssertionError("Original Python HTTP Injector cannot decode sample")
    for required in ("primary.example.invalid","backup.example.invalid",
                     "GET /api HTTP/1.1","Host: sni.example.invalid",
                     "LAST_FIELD_MUST_SURVIVE","unknownFormat: plain:synthetic"):
        if required not in text:raise AssertionError("Source dropped essential data: "+required)
    expected={
        "configSalt":salt,
        "serverHost":"primary.example.invalid",
        "plaintextHost":profile["plaintextHost"],
        "httpPayload":profile["httpPayload"],
        "unknownFormat":profile["unknownFormat"],
        "overwriteServerData":profile["overwriteServerData"],
        "serverPort":443,
        "enabled":False,
        "nullable":None,
        "finalField":profile["finalField"]
    }
    return output,text+"\n",expected

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output-dir",type=Path,required=True)
    args=p.parse_args()
    raw,text,expected=make()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    (args.output_dir/"ehi-complete-fields.ehi").write_bytes(raw)
    (args.output_dir/"ehi-complete-fields.txt").write_text(text,encoding="utf-8")
    (args.output_dir/"ehi-complete-fields.json").write_text(
        json.dumps(expected,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("[EHI] preserved plaintext, multiline payload, nested array and final key")

if __name__=="__main__":
    main()

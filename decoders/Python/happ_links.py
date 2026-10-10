#!/usr/bin/env python3
"""HAPP RSA PKCS#1 v1.5 text decoder.

Private keys must be configured locally via SPDECODE_HAPP_KEYS_JSON:
a JSON mapping from version ('crypt', 'crypt2', 'crypt3', 'crypt4')
to the PEM private key for that version. No private keys are published
in GitHub and no decrypted URL is automatically fetched.
"""
from __future__ import annotations
import base64
import json
import os
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

VERSIONS = ("crypt", "crypt2", "crypt3", "crypt4")
SCHEMES = tuple(f"happ://{version}/" for version in VERSIONS)

def decode_text(text: str) -> str | None:
    if not isinstance(text,str) or len(text)>2*1024*1024:
        return None
    prefix=next((p for p in SCHEMES if text.lower().startswith(p)),None)
    if prefix is None:
        return None
    try:
        raw_keys=json.loads(os.environ.get("SPDECODE_HAPP_KEYS_JSON","{}"))
        if not isinstance(raw_keys,dict):
            return None
        candidate=text[len(prefix):].strip().replace("-","+").replace("_","/")
        candidate+="="*(-len(candidate)%4)
        encrypted=base64.b64decode(candidate,validate=True)
        version=prefix[len("happ://"):-1]
        for candidate_version in (version,)+tuple(v for v in VERSIONS if v!=version):
            pem=raw_keys.get(candidate_version)
            if not isinstance(pem,str):
                continue
            try:
                rsa=RSA.import_key(pem)
                length=rsa.size_in_bytes()
                if not encrypted or len(encrypted)%length:
                    continue
                cipher=PKCS1_v1_5.new(rsa)
                pieces=[]
                for i in range(0,len(encrypted),length):
                    output=cipher.decrypt(encrypted[i:i+length],None)
                    if output is None:
                        raise ValueError("Invalid RSA block")
                    pieces.append(output)
                decoded=b"".join(pieces).decode("utf-8")
                try:
                    parsed=json.loads(decoded)
                    return json.dumps(parsed,ensure_ascii=False,indent=2)
                except ValueError:
                    return decoded
            except (ValueError,TypeError):
                continue
    except (ValueError,TypeError):
        return None
    return None

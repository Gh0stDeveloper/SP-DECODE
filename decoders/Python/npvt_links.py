#!/usr/bin/env python3
"""NPVT SSH and DNS/npvs1 legacy *text* representations, not NPVS v5 files."""
from __future__ import annotations
import base64
import json
import re

_SCHEMES = ("npvt-ssh://","dns://")

def _b64(value: str) -> str:
    payload=re.sub(r"\s+","",value).replace("-","+").replace("_","/")
    payload+="="*(-len(payload)%4)
    return base64.b64decode(payload,validate=True).decode("utf-8")

def decode_npvs1(value, depth: int = 0):
    if depth>12:
        return value
    if isinstance(value, dict):
        return {k:decode_npvs1(v,depth+1) for k,v in value.items()}
    if isinstance(value,list):
        return [decode_npvs1(v,depth+1) for v in value]
    if isinstance(value,str) and value.startswith("npvs1:"):
        try:
            result=_b64(value[6:])
            if result.strip().startswith(("{","[")):
                return decode_npvs1(json.loads(result),depth+1)
            return result
        except (ValueError,UnicodeError):
            return value
    return value

def decode_text(text: str):
    if not isinstance(text,str) or not text or len(text)>2*1024*1024:
        return None
    candidate=text.strip()
    if candidate.startswith("npvs1:"):
        decoded=decode_npvs1(candidate)
        return json.dumps(decoded,ensure_ascii=False,indent=2) if isinstance(decoded,(dict,list)) else (decoded if decoded!=candidate else None)
    prefix=next((prefix for prefix in _SCHEMES if candidate.lower().startswith(prefix)),None)
    if prefix is None:
        return None
    try:
        data=json.loads(_b64(candidate[len(prefix):]))
        if not isinstance(data,(dict,list)):
            return None
        return json.dumps(decode_npvs1(data),ensure_ascii=False,indent=2)
    except (ValueError,UnicodeError):
        return None

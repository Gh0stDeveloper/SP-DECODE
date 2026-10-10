#!/usr/bin/env python3
"""Decode Falcon Tunnel import links; local URL-safe Base64 + JSON only."""
from __future__ import annotations
import base64
import json

PREFIX = "falcontunnel://import/"

def decode_text(text: str):
    if not isinstance(text,str) or not text.lower().startswith(PREFIX) or len(text)>2*1024*1024:
        return None
    payload=text[len(PREFIX):].strip()
    if not payload:
        return None
    try:
        payload += "="*(-len(payload)%4)
        data=json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (ValueError,UnicodeDecodeError):
        return None
    return json.dumps(data,ensure_ascii=False,indent=2) if isinstance(data,(dict,list)) else None

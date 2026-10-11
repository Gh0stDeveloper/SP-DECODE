#!/usr/bin/env python3
"""Generate independent source-derived TLS Tunnel 8.5.0 / legacy parity.

Only synthetic placeholders; no user TLS files or credentials are committed.
The 8.5.0 real-file authentication is documented in the separate research branch.
"""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
from Crypto.Cipher import AES
from decoders.Python import TLS


def pack(plaintext: bytes, key: bytes) -> bytes:
    # TLS Tunnel's unusual 36-byte nonce and per-fragment byte reversal.
    nonce = bytes(range(36))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    authenticated = ciphertext + tag
    half = len(authenticated) // 2
    raw = (bytes(12) + authenticated[:half][::-1] + nonce[:18][::-1]
           + authenticated[half:][::-1] + nonce[18:][::-1] + bytes(84))
    return (base64.b64encode(raw).decode("ascii").rstrip("=")[::-1] + ":::::"
            ).encode("utf-8")


def samples():
    for profile, key in enumerate(TLS.CONFIG_KEYS, 1):
        fields = [""] * (28 if profile == 6 else 58)
        fields[:4] = ["516" if profile != 6 else "300", "1", "443", "true"]
        fields[4] = base64.b64encode("demo-user".encode()).decode()
        fields[5] = base64.b64encode("demo-pass".encode()).decode()
        fields[6] = base64.b64encode(b"node.example.invalid").decode()
        fields[12] = base64.b64encode(b"GET / HTTP/1.1\r\nHost: example.invalid").decode()
        fields[24] = "@@unmapped@@" if profile != 6 else base64.b64encode(b"key").decode()
        fields[27] = base64.b64encode("demo".encode()).decode()
        if profile != 6:
            fields[20:24] = ["true", "false", "true", "false"]
            fields[-1] = "future-data"
        else:
            fields[20] = "2"
        plain = ":".join(fields).encode("utf-8")
        raw = pack(plain, key)
        decoded = TLS.decrypt_tls_payload(raw.decode())
        assert decoded["_tls"]["authenticated"]
        assert decoded["_tls"]["key_profile"] == profile
        assert ":".join(item["raw"] for item in decoded["_tls"]["fields"]).encode() == plain
        if profile != 6:
            assert "legacy_dns_mode" not in decoded
        else:
            assert decoded["legacy_dns_mode"] == 2
        text = TLS.run(raw)
        assert text
        # Profile 6 preserves the frozen historical result text, while the
        # 8.5.0 keys include all positional metadata for new schema fields.
        assert ('"_tls": {' in text) == (profile != 6)
        yield f"tls850-profile-{profile}", raw, text


def export(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for name, data, text in samples():
        (outdir / f"{name}.tls").write_bytes(data)
        (outdir / f"{name}.txt").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    export(args.output_dir)
    print("TLS 8.5.0: 5 modern + 1 legacy authenticated Python reference profiles")

#!/usr/bin/env python3
"""Build extra synthetic Dark Tunnel MessagePack parity cases from the Python source.

Only fictitious example.invalid data is used. These fixtures are not vendor
exports; real-world verification requires authorized private samples.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import msgpack
from Crypto.Cipher import AES

from decoders.Python.DARKTUNNEL import DTConstants, run


def _cfb_encrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CFB, iv=DTConstants.IV, segment_size=128).encrypt(data)


def _build(inner: dict, outer_meta: dict) -> bytes:
    encrypted_inner = _cfb_encrypt(msgpack.packb(inner, use_bin_type=True), DTConstants.KEY_192)
    outer = {
        "EncryptedLockedConfig": encrypted_inner,
        **outer_meta,
    }
    encrypted_outer = _cfb_encrypt(msgpack.packb(outer, use_bin_type=True), DTConstants.KEY_256)
    envelope = {
        "name": "Synthetic Dark Tunnel",
        "encryptedLockedConfig": base64.b64encode(encrypted_outer).decode("ascii"),
        "enabled": True,
    }
    return base64.b64encode(json.dumps(envelope, ensure_ascii=False).encode("utf-8"))


def export(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    cases = {
        "dark-second-profile": _build(
            {
                "EncryptedHost": _cfb_encrypt(b"node.example.invalid", DTConstants.KEY_192),
                "SampleBinary": b"\x00\x7f\xff\x03",
                "RetainJsonText": '{"token":"not-to-be-parsed"}',
                "nested": {"EncryptedPayload": _cfb_encrypt(b"hello\r\nworld", DTConstants.KEY_192)},
            },
            {"Enabled": False, "ProfileName": "second-profile"},
        ),
        "dark-scalar-map-key": _build(
            {2: "numeric-key", "EncryptedHost": _cfb_encrypt(b"demo.example.invalid", DTConstants.KEY_192)},
            {"ProfileName": "third-profile", "Count": 3},
        ),
    }
    for filename, raw in cases.items():
        original = run(raw)
        assert original and "EncryptedLockedConfig" in original
        (outdir / (filename + ".dark")).write_bytes(raw)
        (outdir / (filename + ".txt")).write_text(original, encoding="utf-8")
    print("Generated 2 synthetic Dark Tunnel cases with exact Python output")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    export(parser.parse_args().output_dir)

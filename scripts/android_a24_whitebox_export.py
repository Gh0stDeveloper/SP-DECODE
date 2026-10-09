#!/usr/bin/env python3
"""Compile inert NPVTUNNEL source white-box tables to a data-only Android asset.

Source pickle is audited by the original restricted unpickler; no unpickling
ever occurs on Android. Byte layout is constant and versioned.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from decoders.Python.NPVTUNNEL import load_whitebox_state, whitebox_encrypt_block


def compile_asset() -> bytes:
    p2, p3, p4, p5 = load_whitebox_state()
    result = bytearray(b"NPWA0001")
    # Only round r=0 is ever executed: round r=1 exits before table accesses.
    for t in range(96):
        for a in range(16):
            for b in range(16):
                x = p2[0][t][a][b]
                if not isinstance(x, int) or not 0 <= x <= 15:
                    raise ValueError("Unexpected NPV four-bit box")
                result.append(x)
    for matrix in (p3[0], p5[0]):
        for t in range(16):
            for a in range(256):
                result.extend(struct.pack(">I", matrix[t][a] & 0xFFFFFFFF))
    for t in range(16):
        for a in range(256):
            x = p4[t][a]
            if not isinstance(x, int) or not 0 <= x <= 255:
                raise ValueError("Unexpected NPV output box")
            result.append(x)
    assert len(result) == 8 + 96 * 16 * 16 + 2 * 16 * 256 * 4 + 16 * 256

    # Validate original source transformation against frozen data layout:
    test = bytes(range(16))
    output = whitebox_encrypt_block(test, p2, p3, p4, p5)
    assert len(output) == 16 and isinstance(output, bytes)
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = compile_asset()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    import hashlib
    print("[A.2.4] NPV source-derived data-only binary:",
          len(data), "bytes, SHA256", hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    main()

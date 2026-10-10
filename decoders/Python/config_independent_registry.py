"""Additional independent bot-only engines extracted from the owner's 66.py.

Keep decoders.json unchanged: Android has its own explicit source catalog.
Each set of aliases shares one Python module and source-derived cryptography.
"""
from __future__ import annotations

INDEPENDENT_DECODERS = {
    "IZPH VPN Pro": ("decoders/Python/izph.py", (".izph",)),
    "FlexNet": ("decoders/Python/flex.py", (".flex", ".flexnet")),
    "N4 VPN Pro": ("decoders/Python/n4.py", (".n4",)),
    "CREV": ("decoders/Python/crev.py", (".crev", ".cer", ".cerv")),
    "KTR": ("decoders/Python/ktr.py", (".ktr",)),
    "Zoba VPN": ("decoders/Python/zoba.py", (".zoba",)),
    "LTM Tunnel": ("decoders/Python/ltm.py", (".ltm", ".lt")),
    "DEV VPN": ("decoders/Python/dev.py", (".dev",)),
    "VN7": ("decoders/Python/vn7.py", (".vn7",)),
}


def independent_file_decoder_specs() -> dict[str, tuple[str, str]]:
    aliases = {}
    for name, (path, suffixes) in INDEPENDENT_DECODERS.items():
        for suffix in suffixes:
            if suffix in aliases:
                raise ValueError(f"Duplicate independent decoder alias: {suffix}")
            aliases[suffix] = (name, path)
    return aliases

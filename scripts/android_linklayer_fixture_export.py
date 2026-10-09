#!/usr/bin/env python3
"""Generate only PUBLIC synthetic VER6 fixtures for Android parity testing."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from decoders.Python.linklayer import decode
from tests.test_linklayer_ver6 import LinkLayerTests, _export, _gob, _zero
from decoders.Python.linklayer import SCHEMA


def export(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    LinkLayerTests.setUpClass()
    long_config = _zero(SCHEMA)
    # Cross the entire 1500-byte PBKDF2 XOR-mask boundary: long gob values
    # must decode identically in Kotlin and Python after mask exhaustion.
    long_config["MessageConfig"] = "prefix:" + ("Long-Go-gob-🇲🇽-" * 350)
    cases = {
        "linklayer-ver6.lnk": LinkLayerTests.fixture,
        "linklayer-ver6-reordered.lnk": _export(LinkLayerTests.gob, flag=1),
        "linklayer-ver6-long.lnk": _export(_gob(long_config), flag=1),
    }
    for filename, data in cases.items():
        assert decode(data) == LinkLayerTests.expected
        (directory / filename).write_bytes(data)
        (directory / filename.removesuffix(".lnk").__add__(".json")).write_text(
            json.dumps(decode(data), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    (directory / "linklayer-ver6.gob").write_bytes(LinkLayerTests.gob)
    (directory / "linklayer-ver6-truncated.lnk").write_bytes(LinkLayerTests.fixture[:354])
    broken = bytearray(LinkLayerTests.fixture)
    broken[0:4] = b"VER7"
    (directory / "linklayer-ver6-unknown.lnk").write_bytes(broken)
    print("Generated 3 valid + 2 invalid synthetic LinkLayer VER6 fixtures (no real secrets)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    export(parser.parse_args().output_dir)

#!/usr/bin/env python3
"""Generate only PUBLIC synthetic VER6 fixtures for Android parity testing."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from decoders.Python.linklayer import decode
from tests.test_linklayer_ver6 import LinkLayerTests, _export


def export(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    LinkLayerTests.setUpClass()
    cases = {
        "linklayer-ver6.lnk": LinkLayerTests.fixture,
        "linklayer-ver6-reordered.lnk": _export(LinkLayerTests.gob, flag=1),
    }
    for filename, data in cases.items():
        assert decode(data) == LinkLayerTests.expected
        (directory / filename).write_bytes(data)
        (directory / filename.removesuffix(".lnk").__add__(".json")).write_text(
            json.dumps(decode(data), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    (directory / "linklayer-ver6-truncated.lnk").write_bytes(LinkLayerTests.fixture[:354])
    broken = bytearray(LinkLayerTests.fixture)
    broken[0:4] = b"VER7"
    (directory / "linklayer-ver6-unknown.lnk").write_bytes(broken)
    print("Generated 2 valid + 2 invalid synthetic LinkLayer VER6 fixtures (no real secrets)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    export(parser.parse_args().output_dir)

#!/usr/bin/env python3
"""Offline validation for SP-DECODE Android planning sources.

Checks that official docs, visual SVG references and the Android decoder matrix
remain in sync with the existing Telegram decoder registry.
This does not claim that decoders have been tested on Android.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "android"
REQUIRED = (
    "README.md",
    "PRODUCT_REQUIREMENTS.md",
    "DESIGN_SYSTEM.md",
    "LOCALIZATION.md",
    "ARCHITECTURE.md",
    "DECODER_MATRIX.md",
    "DECODER_AUDIT.md",
    "A2_FIXTURE_POLICY.md",
    "A23_GOLDEN_CORPUS.md",
    "audit_decoders.py",
    "SECURITY_AND_QA.md",
    "ROADMAP.md",
    "ADR.md",
    "HANDOFF.md",
    "status.json",
    "design/home-dark.svg",
    "design/result-dark.svg",
)


def main() -> int:
    errors: list[str] = []
    for name in REQUIRED:
        if not (DOCS / name).is_file():
            errors.append(f"Missing official Android document: {name}")

    if errors:
        return report(errors)

    registry = json.loads((ROOT / "decoders.json").read_text(encoding="utf-8"))["decoders"]
    status = json.loads((DOCS / "status.json").read_text(encoding="utf-8"))
    matrix = (DOCS / "DECODER_MATRIX.md").read_text(encoding="utf-8")
    suffixes = re.findall(r"^\| \.([^|\s]+)\s+\|", matrix, flags=re.MULTILINE)
    if len(suffixes) != len(registry):
        errors.append(f"Decoder matrix has {len(suffixes)} rows vs registry {len(registry)}")
    if set(suffixes) != set(registry):
        errors.append(f"Decoder matrix suffix drift: missing {set(registry) - set(suffixes)}, extra {set(suffixes) - set(registry)}")

    counters = {"python": 0, "node": 0, "php": 0}
    all_scripts: set[str] = set()
    for spec in registry.values():
        counters[spec["runtime"]] += 1
        all_scripts.add(spec["script"])
    expected = status["formats"]
    for key, actual in (
        ("registeredSuffixes", len(registry)),
        ("pythonSuffixes", counters["python"]),
        ("nodeSuffixes", counters["node"]),
        ("phpSuffixes", counters["php"]),
        ("distinctScripts", len(all_scripts)),
    ):
        if expected.get(key) != actual:
            errors.append(f"status.json {key}: {expected.get(key)} != {actual}")

    locale = status.get("localization", {})
    if (locale.get("scope") != "ui_only"
        or locale.get("languages") != ["es", "en", "pt-BR", "ar"]
        or locale.get("decoderOutputTranslated") is not False
        or locale.get("decoderOutputMutationAllowed") is not False
        or locale.get("arabicRtlRequired") is not True):
        errors.append("Localization contract mismatch: four UI locales, Arabic RTL, original results unchanged")

    if status["offlineRequired"] is not True or status["loginRequired"] is not False:
        errors.append("Product offline/no-login invariant changed")

    for path in sorted(DOCS.glob("*.md")):
        body = path.read_text(encoding="utf-8")
        for url in re.findall(r"\[[^\]]+\]\(([^)]+)\)", body):
            url = url.strip().split("#", 1)[0]
            if not url or "://" in url or url.startswith("#") or url.startswith("mailto:"):
                continue
            local = (path.parent / url).resolve()
            if not local.is_file() or not local.is_relative_to(ROOT):
                errors.append(f"Broken local link in {path.name}: {url}")

    for name in ("design/home-dark.svg", "design/result-dark.svg"):
        path = DOCS / name
        try:
            root = ET.parse(path).getroot()
            if not root.tag.endswith("svg"):
                errors.append(f"Not an SVG root: {name}")
        except ET.ParseError as exc:
            errors.append(f"Invalid SVG {name}: {exc}")

    return report(errors)


def report(errors: list[str]) -> int:
    if errors:
        for message in errors:
            print(f"[FAIL] {message}")
        print(f"Android documentation validation failed: {len(errors)} issue(s)")
        return 1
    print("[OK] Official docs and links exist")
    print("[OK] Matrix registry and status counts match")
    print("[OK] AMOLED SVG assets parse as XML")
    print("Note: no Android APK, decoder functionality or device behavior was tested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

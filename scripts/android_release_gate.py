#!/usr/bin/env python3
"""Fail-closed release gates: public signed preview does not imply stable GO."""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

REQUIRED = (
    "arm64Physical", "page16KiB", "realExporterFormats",
    "securityDependencies", "privacyAndPermissions",
    "accessibilityAndPerformance", "ciMainFullSuite", "signingInstallUpgrade",
)
SOURCE = Path("release/android-readiness.json")


def check(evidence: dict, mode: str, version: str) -> list[str]:
    problems = []
    if evidence.get("schemaVersion") != 1:
        problems.append("unsupported evidence schema")
    if mode == "candidate":
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta|rc)(?:\.[0-9]+)?", version):
            problems.append("candidate must use a prerelease version")
        if evidence.get("candidateVersion") != version:
            problems.append("candidateVersion does not match requested build")
        return problems
    if mode == "public-preview":
        # Owner-authorized public distribution of the production-signed APK.
        # The release MUST remain a GitHub prerelease and must never imply
        # complete vendor/device certification or change the stable NO-GO.
        if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version):
            problems.append("public preview requires stable APK versionName")
        if evidence.get("stableVersion") != version:
            problems.append("stableVersion does not match public preview APK")
        if evidence.get("decision") != "NO-GO":
            problems.append("preview channel only applies while stable release is NO-GO")
        if evidence.get("ownerApproval") is not True or evidence.get("publicPreviewApproval") is not True:
            problems.append("explicit owner public-preview approval required")
        return problems
    if mode != "stable":
        return ["unknown release mode"]
    if not re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", version):
        problems.append("stable version must be an ordinary semver tag")
    if evidence.get("stableVersion") != version:
        problems.append("stableVersion does not match")
    if evidence.get("decision") != "GO" or evidence.get("ownerApproval") is not True:
        problems.append("explicit verified GO and owner approval are required")
    reports = evidence.get("evidence", {})
    if not isinstance(reports, dict):
        return problems + ["evidence must be an object"]
    for key in REQUIRED:
        info = reports.get(key)
        if not isinstance(info, dict) or info.get("status") != "verified":
            problems.append(f"{key}: verification pending")
            continue
        ref = info.get("report", "")
        if not isinstance(ref, str) or not ref.strip() or ref.strip() in ("N/A", "pending"):
            problems.append(f"{key}: evidence link/path required")
        elif not (ref.startswith("https://") or
                  (ref.startswith("docs/android/") and Path(ref).is_file()) or
                  (ref.startswith("release/evidence/") and Path(ref).is_file())):
            problems.append(f"{key}: evidence must be an accessible URL or existing report")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("candidate", "public-preview", "stable"), required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--file", type=Path, default=SOURCE)
    opts = parser.parse_args()
    data = json.loads(opts.file.read_text(encoding="utf-8"))
    problems = check(data, opts.mode, opts.version)
    if problems:
        for line in problems:
            print("NO-GO: " + line)
        return 1
    print(f"Gate verified: {opts.mode} {opts.version}. Check signature and CI again before publishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

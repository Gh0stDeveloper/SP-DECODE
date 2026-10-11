#!/usr/bin/env python3
"""Phase S.3: tracked credential, Android diagnostic, CI and APK leakage audit.

Only reports rule IDs and paths, NEVER matched values, source excerpts,
exceptions or file contents. Original decoder reference constants are PUBLIC
protocol data; unlike production keystore/private tokens they are not secrets.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("android/app/src/main/AndroidManifest.xml")
ACTIVITY = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
DIAGNOSTICS = Path("android/app/src/main/java/com/ghostdeveloper/spdecode/SafeDecodeDiagnostics.kt")
SIGNED = Path(".github/workflows/android-signed-release.yml")
SOURCE_EXTENSIONS = {
    ".py", ".kt", ".kts", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".sh", ".bash", ".json", ".xml", ".yml", ".yaml", ".properties",
    ".toml", ".gradle", ".md", ".txt", ".html", ".php",
}
PRIVATE_MARKERS = {
    "private-key-pem": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "github-access-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{28,}\b"),
    "github-finegrained-token": re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{36,}\b"),
    "aws-access-id": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "slack-bot-or-user-token": re.compile(rb"\bxox[bapors]-[A-Za-z0-9-]{22,}\b"),
    "openai-service-token": re.compile(rb"\bsk-(?:proj-|svc-)[A-Za-z0-9_-]{28,}\b"),
    "telegram-bot-token": re.compile(rb"\b[0-9]{8,12}:[A-Za-z0-9_-]{35,}\b"),
}
PRIVATE_SUFFIXES = {".p12", ".pfx", ".jks", ".keystore"}
PRIVATE_FILE_NAMES = {
    "id_rsa", "id_ed25519", "secrets.json", "service-account.json",
    "service_account.json", "credentials-private.json",
}
ANDROID_BAD_LOGGING = {
    "android-logcat": re.compile(r"\b(?:android\.util\.)?Log\.(?:d|e|v|i|w|wtf|println)\s*\("),
    "stacktrace-export": re.compile(r"\b(?:printStackTrace|stackTraceToString)\s*\("),
    "stdout-logging": re.compile(r"\b(?:System\.out\.print(?:ln)?|System\.err\.print(?:ln)?|println)\s*\("),
    "raw-android-logger": re.compile(r"\bimport\s+android\.util\.Log\b"),
}
WORKFLOW_BAD_LOGGING = {
    "shell-command-tracing": re.compile(r"(?m)^\s*(?:set\s+(?:-[a-z]*x|-[^-]*x)|bash\s+-x)\b"),
    "print-env-dump": re.compile(r"(?m)^\s*(?:env|printenv)\s*(?:$|[|>])"),
    "dump-all-github-secrets": re.compile(r"\$\{\{\s*toJSON\(secrets\)\s*\}\}", re.I),
}


def tracked_paths(root: Path = ROOT) -> list[Path]:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached"],
        capture_output=True, check=True,
    )
    return sorted(
        Path(p.decode("utf-8", "surrogateescape"))
        for p in proc.stdout.split(b"\0") if p
    )


def private_filename(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in PRIVATE_FILE_NAMES
        or name in {".env", "config.json"} and len(path.parts) <= 2
        or name.startswith(".env.") and not name.endswith(".example")
        or path.suffix.lower() in PRIVATE_SUFFIXES
    )


def find_tokens(data: bytes) -> list[str]:
    return [rule for rule, pattern in PRIVATE_MARKERS.items() if pattern.search(data)]


def scan_tracked(root: Path = ROOT, files: list[Path] | None = None) -> list[dict]:
    findings: list[dict] = []
    for relative in files if files is not None else tracked_paths(root):
        path = root / relative
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            continue
        if private_filename(relative):
            findings.append({"rule": "tracked-private-file", "path": relative.as_posix()})
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        # Do not scan a source blob unboundedly. Raise an explicit policy
        # finding for oversized text rather than silently excluding it.
        if path.stat().st_size > 16 * 1024 * 1024:
            findings.append({"rule": "source-too-large-to-audit", "path": relative.as_posix()})
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        for rule in find_tokens(data):
            findings.append({"rule": rule, "path": relative.as_posix()})
    return findings


def android_guards(root: Path = ROOT) -> list[dict]:
    found: list[dict] = []
    manifest = (root / MANIFEST).read_text("utf-8")
    activity = (root / ACTIVITY).read_text("utf-8")
    diagnostic = (root / DIAGNOSTICS).read_text("utf-8")
    conditions = {
        "app-backup-disabled": 'android:allowBackup="false"' in manifest,
        "no-internet-permission": not re.search(r'<uses-permission[^>]+android:name="android.permission.(?:INTERNET|ACCESS_NETWORK_STATE)"', manifest),
        "no-application-debuggable": 'android:debuggable="true"' not in manifest,
        "clipboard-is-sensitive": 'android.content.extra.IS_SENSITIVE' in activity,
        "no-raw-throwable-api": not re.search(r"fun\s+record\s*\([^)]*(?:Throwable|Exception|String|ByteArray|DecodeView)", diagnostic),
        "no-background-telemetry": all(x not in diagnostic for x in (
            "android.util.Log", "HttpURLConnection", "Socket(", "SharedPreferences",
            "FileOutputStream(", "sendBroadcast(", "ContentResolver",
        )),
        "history-stored-in-keystore": "AndroidKeyStore" in (root/"android/app/src/main/java/com/ghostdeveloper/spdecode/SecureDecodeHistory.kt").read_text("utf-8"),
    }
    for name, ok in conditions.items():
        if not ok:
            found.append({"rule": name, "path": MANIFEST.as_posix() if "permission" in name or "backup" in name or "debuggable" in name else DIAGNOSTICS.as_posix()})
    kotlin_root = root / "android/app/src/main/java"
    for path in sorted(kotlin_root.rglob("*.kt")):
        body = path.read_text("utf-8")
        for name, pattern in ANDROID_BAD_LOGGING.items():
            if pattern.search(body):
                found.append({"rule": name, "path": path.relative_to(root).as_posix()})
    return found


def workflow_guards(root: Path = ROOT) -> list[dict]:
    found = []
    for path in sorted((root / ".github/workflows").glob("*.yml")):
        body = path.read_text("utf-8")
        for name, pattern in WORKFLOW_BAD_LOGGING.items():
            if pattern.search(body):
                found.append({"rule": name, "path": path.relative_to(root).as_posix()})
    production = (root / SIGNED).read_text("utf-8")
    for snippet, name in (
        ("SPDECODE_SIGNING_KEYSTORE_BASE64", "missing-production-keystore-secret"),
        ("SPDECODE_SIGNING_STORE_PASSWORD", "missing-production-store-password"),
        ("SPDECODE_SIGNING_KEY_PASSWORD", "missing-production-key-password"),
        ("apksigner", "missing-production-signature-check"),
    ):
        if snippet not in production:
            found.append({"rule": name, "path": SIGNED.as_posix()})
    return found


def scan_apk(apk: Path) -> list[dict]:
    problems = []
    with zipfile.ZipFile(apk) as zf:
        for name in zf.namelist():
            file = Path(name)
            if private_filename(file):
                problems.append({"rule": "packaged-private-file", "path": file.name})
                continue
            if file.suffix.lower() not in {".dex", ".json", ".txt", ".xml", ".pem", ".properties"}:
                continue
            info = zf.getinfo(name)
            if info.file_size > 64 * 1024 * 1024:
                problems.append({"rule": "oversized-apk-member", "path": file.name})
                continue
            contents = zf.read(name)
            for rule in find_tokens(contents):
                problems.append({"rule": "apk-" + rule, "path": file.name})
    return problems


def audit(root: Path = ROOT, apk: Path | None = None, files: list[Path] | None = None) -> dict:
    findings = scan_tracked(root, files=files)
    findings.extend(android_guards(root))
    findings.extend(workflow_guards(root))
    if apk is not None:
        findings.extend(scan_apk(apk))
    return {
        "phase": "S.3",
        "status": "FAIL" if findings else "PASS",
        "findings": sorted(findings, key=lambda f: (f["rule"], f["path"])),
        "sourceFilesConsidered": len(files) if files is not None else len(tracked_paths(root)),
        "scope": "tracked-source, android-log-sinks, workflow-signing, optional-apk",
        "secretValuesReported": False,
        "publicDecoderMaterialClassifiedAsProductionCredential": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = audit(apk=args.apk)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", "utf-8")
    print("Phase S.3 security audit:", result["status"],
          "tracked files:", result["sourceFilesConsidered"],
          "findings:", len(result["findings"]))
    for finding in result["findings"]:
        print("  ", finding["rule"], "in", finding["path"])
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

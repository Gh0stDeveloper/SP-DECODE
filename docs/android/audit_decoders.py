#!/usr/bin/env python3
"""Static, read-only audit of SP-DECODE's registered file decoders.

Purpose:
- Inventory every extension/script from decoders.json.
- Parse Python syntax without importing or executing decoder modules.
- Report direct imports, input/IO style, known required resources and
  potentially unsafe or non-portable implementation patterns.
- Export reports containing METADATA ONLY: never decoder source, fixed
  algorithm secrets, tokens, payloads, raw keys or file contents.

This cannot determine whether a decoder successfully decrypts any file.
Dynamic behavior, nested includes, transitive packages and ABI compatibility
require separate experiments and golden fixtures.

Run:
  python docs/android/audit_decoders.py
  python docs/android/audit_decoders.py --output-dir out/android-a2
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REGISTERED_RUNTIMES = {"python", "node", "php"}
SCRIPT_RUNTIME = {"python": ".py", "node": ".js", "php": ".php"}
KNOWN_RESOURCES = {
    "decoders/JavaScript/hat.js": ("nodehat.json",),
    "decoders/JavaScript/modulepro.js": (
        "cfg/config.inc.json",
        "cfg/lang/english.lang.json",
        "cfg/layout/default.layout.json",
        "lib/methods/eProDecryptor.lib.js",
    ),
    "decoders/JavaScript/chicosp.js": (
        "cfg/config.inc.json",
        "cfg/lang/english.lang.json",
        "cfg/layout/default.layout.json",
        "lib/methods/npv2Decryptor.lib.js",
    ),
    "decoders/Python/maya.py": ("decoders/Python/_noobcrypt.py",),
    "decoders/Python/xui.py": ("decoders/Python/_noobcrypt.py",),
}
THIRD_PARTY_ROOTS = {"Crypto", "cryptography", "argon2", "msgpack", "requests"}
NODE_BUILTINS = {"fs", "path", "crypto", "buffer", "zlib", "util", "os", "process"}
EXPLICIT_SECRET_WORDS = ("password", "secret", "key", "token")  # Never print matched values.


def _regex_flags(src: str, runtime: str) -> dict[str, bool]:
    return {
        "declares_run": bool(re.search(r"(?m)^\s*(?:async\s+)?def\s+run\s*\(", src))
        if runtime == "python" else False,
        "reads_files": bool(re.search(
            r"\bopen\s*\(|\bread_bytes\s*\(|\bread_text\s*\(|"
            r"\breadFileSync\s*\(|\bfile_get_contents\s*\(|\bfopen\s*\(", src
        )),
        "writes_files": bool(re.search(
            r"\bwriteFileSync\s*\(|\bfile_put_contents\s*\(|"
            r"\bwrite_bytes\s*\(|\bwrite_text\s*\(", src
        )),
        "has_cli_entry": bool(re.search(
            r"__main__|process\.argv|\$argv|sys\.argv|ArgumentParser", src
        )),
        "uses_subprocess": bool(re.search(
            r"\bsubprocess\b|\bchild_process\b|\bos\.system\s*\(|"
            r"\bshell_exec\s*\(|\bexecSync\s*\(", src
        )),
        "imports_network_facility": bool(re.search(
            r"\brequests\b|\bsocket\b|\burllib\.request\b|"
            r"\bhttp[s]?\b|\bcurl_init\b", src
        )),
        "invokes_network_api": bool(re.search(
            r"\brequests\.(?:get|post|put|delete|request|Session)\s*\(|"
            r"\burllib\.request\.urlopen\s*\(|"
            r"\bfetch\s*\(|\bcurl_exec\s*\(|"
            r"\bhttps?\.(?:get|request)\s*\(", src
        )),
        "uses_pickle": bool(re.search(r"\bpickle\.loads?\s*\(", src)),
        "uses_eval": bool(re.search(
            r"\beval\s*\(|\bexec\s*\(|\bnew\s+Function\s*\(", src
        )),
        "crypto_api_mentioned": bool(re.search(
            r"\bAES\b|\bChaCha20\b|\bDES3?\b|\bopenssl_decrypt\b|"
            r"\bcreateDecipheriv\b|\bCrypto\.Cipher\b", src, re.IGNORECASE
        )),
    }


def _python_imports(source: str, path: str) -> tuple[list[str], list[str]]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [], [f"python_syntax_error:{exc.lineno}:{exc.msg}"]
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                roots.add(name.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            # Relative modules are local even when module=None.
            roots.add(("." if node.level else "") + (node.module or "").split(".", 1)[0])
    return sorted(roots - {"__future__"}), []


def _script_inspection(script: str, runtime: str, suffixes: list[str]) -> dict[str, Any]:
    errors: list[str] = []
    relative = Path(script)
    actual = (ROOT / relative).resolve()
    if actual == ROOT or not actual.is_relative_to(ROOT):
        return {"script": script, "errors": ["script_escapes_repository"]}
    if relative.suffix.lower() != SCRIPT_RUNTIME[runtime]:
        errors.append("runtime_extension_mismatch")
    if not actual.is_file():
        return {"script": script, "errors": ["script_missing"]}

    raw = actual.read_bytes()
    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError:
        src = raw.decode("utf-8", errors="replace")
        errors.append("non_utf8_source")

    flags = _regex_flags(src, runtime)
    imports: list[str] = []
    if runtime == "python":
        imports, problems = _python_imports(src, script)
        errors.extend(problems)
    elif runtime == "node":
        imports = sorted(set(re.findall(
            r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", src
        ) | set())) if False else sorted(set(re.findall(
            r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", src
        )))
        # Include dynamic local dependencies in the written report only by name;
        # do not attempt to evaluate require expressions or load user content.
    else:
        imports = sorted(set(re.findall(
            r"\b(?:include|require)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]", src
        )))

    third_party = sorted(set(imports) & THIRD_PARTY_ROOTS)
    resources = [
        {"path": item, "present": (ROOT / item).is_file()}
        for item in KNOWN_RESOURCES.get(script, ())
    ]
    missing = [x["path"] for x in resources if not x["present"]]
    if missing:
        errors.append("missing_known_resource")
    port_tags = []
    if runtime != "python":
        port_tags.append(f"port_{runtime}_to_local_engine")
    if runtime == "python" and not flags["declares_run"]:
        port_tags.append("needs_embedded_run_adapter")
    if flags["has_cli_entry"] or flags["reads_files"]:
        port_tags.append("isolate_input_from_cli_and_filesystem")
    if flags["writes_files"]:
        port_tags.append("remove_shared_mutable_configuration")
    if flags["imports_network_facility"]:
        port_tags.append("review_network_usage_for_no_internet_build")
    if flags["invokes_network_api"]:
        port_tags.append("active_network_call_candidate")
    if flags["uses_pickle"]:
        port_tags.append("review_pickle_trust_boundary")
    if flags["uses_eval"]:
        port_tags.append("review_dynamic_execution")
    if third_party:
        port_tags.append("validate_android_wheels_or_port")
    if resources:
        port_tags.append("package_assets_and_validate_licensing")
    if not port_tags:
        port_tags.append("port_behavior_and_golden_test")

    return {
        "script": script,
        "runtime": runtime,
        "suffixes": sorted(suffixes),
        "bytes": len(raw),
        "lines": len(src.splitlines()),
        "imports": imports,
        "thirdPartyImports": third_party,
        "knownResources": resources,
        "flags": flags,
        "androidWork": sorted(set(port_tags)),
        "issues": errors,
        "androidStatus": "not_verified",
    }


def analyze(root: Path | None = None) -> dict[str, Any]:
    global ROOT
    if root is not None:
        ROOT = root.resolve()
    path = ROOT / "decoders.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    mapping = data.get("decoders")
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("decoders.json: missing nonempty 'decoders' mapping")

    scripts: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    suffixes_seen: set[str] = set()
    registered = Counter()
    for suffix, entry in mapping.items():
        if not isinstance(suffix, str) or not isinstance(entry, dict):
            errors.append("invalid_decoder_registry_record")
            continue
        if suffix.casefold() in suffixes_seen:
            errors.append(f"duplicate_casefold_suffix:{suffix}")
        suffixes_seen.add(suffix.casefold())
        runtime, script = entry.get("runtime"), entry.get("script")
        if runtime not in REGISTERED_RUNTIMES or not isinstance(script, str):
            errors.append(f"invalid_runtime_or_script:{suffix}")
            continue
        if Path(script).is_absolute() or ".." in Path(script).parts:
            errors.append(f"unsafe_script_path:{suffix}")
            continue
        registered[runtime] += 1
        script_record = scripts.setdefault(script, {"runtime": runtime, "suffixes": []})
        if script_record["runtime"] != runtime:
            errors.append(f"script_multiple_runtimes:{script}")
        script_record["suffixes"].append(suffix)

    examined = [
        _script_inspection(script, row["runtime"], row["suffixes"])
        for script, row in sorted(scripts.items())
    ]
    for row in examined:
        for issue in row.get("issues", row.get("errors", [])):
            errors.append(f"{row['script']}:{issue}")

    record = {
        "schemaVersion": 1,
        "method": "static_read_only",
        "scope": "registered_file_decoders_only",
        "resultVerification": "not_performed",
        "androidExecutionVerification": "not_performed",
        "sourceBaseline": "working_tree",
        "counts": {
            "registeredSuffixes": len(mapping),
            "distinctScripts": len(scripts),
            "pythonSuffixes": registered["python"],
            "nodeSuffixes": registered["node"],
            "phpSuffixes": registered["php"],
            "pythonWithRun": sum(x.get("flags", {}).get("declares_run", False) for x in examined),
            "scriptsWithExternalImports": sum(bool(x.get("thirdPartyImports")) for x in examined),
            "scriptsWithKnownAssets": sum(bool(x.get("knownResources")) for x in examined),
            "scriptsWithNetworkImportCandidate": sum(
                x.get("flags", {}).get("imports_network_facility", False) for x in examined
            ),
            "scriptsWithActiveNetworkCandidate": sum(
                x.get("flags", {}).get("invokes_network_api", False) for x in examined
            ),
            "scriptsWithPickleCandidate": sum(
                x.get("flags", {}).get("uses_pickle", False) for x in examined
            ),
        },
        "registeredExtensions": [
            {
                "suffix": suffix,
                "runtime": entry.get("runtime"),
                "script": entry.get("script"),
                "androidStatus": "not_verified",
            }
            for suffix, entry in sorted(mapping.items())
            if isinstance(entry, dict)
        ],
        "scripts": examined,
        "errors": sorted(errors),
        "caveats": [
            "No untrusted file, decoder code, or subprocess was executed.",
            "Regex flags are indicators, not proof of active behavior or exploitability.",
            "Some resources and dependencies are dynamic; knownResources is not exhaustive.",
            "CI static success is not Android decoder functional compatibility.",
            "Any embedded constants are never included in generated audit reports.",
        ],
    }
    return record


def format_md(report: dict[str, Any]) -> str:
    c = report["counts"]
    lines = [
        "# SP-DECODE Android: A.2 static source audit",
        "",
        "> **Static analysis only:** no input configs were decrypted,",
        "> no decoder code was executed and no Android binary was built.",
        "",
        f"- Registered suffixes: **{c['registeredSuffixes']}**",
        f"- Unique scripts: **{c['distinctScripts']}** "
        f"(Python {c['pythonSuffixes']} suffixes, Node.js {c['nodeSuffixes']}, "
        f"PHP {c['phpSuffixes']})",
        f"- Python scripts exposing run(...): **{c['pythonWithRun']}**",
        "- Android verified decoders: **0**",
        "",
        "## Per-script observations",
        "",
        "| Script | Suffixes | Runtime | run(bytes) | External imports | "
        "Known assets | Candidate actions | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in report["scripts"]:
        fl = row.get("flags", {})
        actions = ", ".join(row.get("androidWork", []))
        imports = ", ".join(row.get("thirdPartyImports", [])) or "—"
        assets = ", ".join(x["path"] for x in row.get("knownResources", [])) or "—"
        line = (
            f"| \`{row['script']}\` | "
            f"{', '.join('.' + x for x in row.get('suffixes', []))} | "
            f"{row.get('runtime', '?')} | "
            f"{'Yes' if fl.get('declares_run') else 'No'} | "
            f"{imports} | {assets} | {actions} | Not verified |"
        )
        lines.append(line)
    lines.extend([
        "",
        "## Integrity findings",
        "",
    ])
    if report["errors"]:
        lines.extend("- " + x for x in report["errors"])
    else:
        lines.append("- No registry paths/syntax/known-asset integrity errors detected.")
    lines.extend([
        "",
        "## Important limitations",
        "",
        *["- " + x for x in report["caveats"]],
        "",
        "See DECODER_AUDIT.md for reviewed risk prioritization and the fixture strategy.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        help="Write sanitized machine JSON and Markdown to this folder")
    args = parser.parse_args()
    try:
        report = analyze()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Cannot audit decoder registry: {exc}", file=sys.stderr)
        return 2
    c = report["counts"]
    print(f"[A.2] {c['registeredSuffixes']} suffixes / {c['distinctScripts']} scripts")
    print(f"[A.2] Python: {c['pythonSuffixes']}  Node.js: {c['nodeSuffixes']}  "
          f"PHP: {c['phpSuffixes']}")
    print(f"[A.2] Python run() declarations: {c['pythonWithRun']}")
    print(f"[A.2] Static network candidates: "
          f"{c['scriptsWithNetworkImportCandidate']} import-level, "
          f"{c['scriptsWithActiveNetworkCandidate']} call-level")
    print(f"[A.2] Known assets: {c['scriptsWithKnownAssets']} scripts; "
          f"pickle candidate: {c['scriptsWithPickleCandidate']}")
    print("[A.2] Android verified decoders: 0 (static-only audit)")
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "a2-static-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (args.output_dir / "a2-static-report.md").write_text(
            format_md(report), encoding="utf-8"
        )
        print(f"[A.2] Reports written to {args.output_dir}")
    for issue in report["errors"]:
        print(f"[FAIL] {issue}")
    if report["errors"]:
        print(f"[A.2] Integrity errors: {len(report['errors'])}")
        return 1
    print("[OK] Every registry script exists; static syntax/resources checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

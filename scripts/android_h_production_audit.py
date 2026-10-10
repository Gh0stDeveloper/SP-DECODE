#!/usr/bin/env python3
"""SP-DECODE Phase H: fail-closed independent pre-production source audit.

No file exports, ciphertext, decoded credentials, keystore or user data are
uploaded. The audit reports what is proven and what requires real-device QA.
A signed APK is NOT the same as full export-version compatibility.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.android_a24_catalog import generate
from scripts.android_release_gate import check, REQUIRED

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MANIFEST = ROOT / "android/app/src/main/AndroidManifest.xml"
BUILD = ROOT / "android/app/build.gradle.kts"
WORKFLOW = ROOT / ".github/workflows/android-signed-release.yml"
CI = ROOT / ".github/workflows/validate.yml"
READINESS = ROOT / "release/android-readiness.json"
RESTRICTED = frozenset((
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
))
PHASES = {"legacy": 61, "B": 81, "C": 41, "D": 16, "E": 27, "F": 13}
G_FILE = ROOT / "docs/android/PHASE_G_TEXT_PROTOCOLS.md"


def inspect(expected_version: str | None = None, expected_code: int | None = None) -> dict:
    checks: dict[str, dict] = {}
    def record(name: str, passed: bool, detail: str):
        checks[name] = {"pass": bool(passed), "detail": detail}
    catalog = generate()
    entries = catalog["entries"]
    counts = {phase: sum(row["migrationPhase"] == phase for row in entries)
              for phase in PHASES}
    record("catalog_239_unique_source_routes",
           len(entries) == 239 and len({r["suffix"] for r in entries}) == 239
           and all(r["script"] and r["originalRuntime"] for r in entries),
           "239 bot-registered suffixes, exactly one original source per suffix")
    record("native_239_but_not_real_vendor_certification",
           catalog["androidNativePortSuffixes"] == 239
           and catalog["androidPendingNativeSuffixes"] == 0
           and catalog["androidCertifiedSuffixes"] == 0,
           "239 source-matched native routes; zero independent current-exporter certifications")
    record("phase_distribution", counts == PHASES, repr(counts))
    root = ET.parse(MANIFEST).getroot()
    requested = {x.attrib.get(ANDROID_NS + "name", "")
                 for x in root
                 if x.tag in ("uses-permission", "uses-permission-sdk-23")}
    record("source_manifest_offline",
           not requested.intersection(RESTRICTED),
           "No prohibited network, legacy storage, overlay, or QUERY_ALL_PACKAGES permissions in source manifest")
    app = root.find("application")
    flags = app.attrib if app is not None else {}
    record("history_backup_disabled",
           flags.get(ANDROID_NS + "allowBackup") == "false"
           and flags.get(ANDROID_NS + "fullBackupContent") == "false"
           and flags.get(ANDROID_NS + "usesCleartextTraffic") == "false",
           "Backup disabled, full-backup disabled, cleartext disabled in source manifest")
    build = BUILD.read_text("utf-8")
    version = re.search(r'versionName\s*=\s*"([^"]+)"', build)
    code = re.search(r'versionCode\s*=\s*(\d+)', build)
    version = version.group(1) if version else ""
    version_code = int(code.group(1)) if code else -1
    record("version_monotonic",
           bool(re.fullmatch(r"[1-9]\d*\.\d+\.\d+", version))
           and version_code > 16
           and (expected_version is None or version == expected_version)
           and (expected_code is None or version_code == expected_code),
           "Source version=" + version + " code=" + str(version_code)
           + ", previous signed public v1.0.5 code 16")
    record("permanent_signing_only",
           all(token in build for token in (
               "SPDECODE_RELEASE_STORE_FILE", "SPDECODE_RELEASE_STORE_PASSWORD",
               "SPDECODE_RELEASE_KEY_ALIAS", "SPDECODE_RELEASE_KEY_PASSWORD",
               "signingConfigs.findByName(\"production\")"
           )), "Release Gradle config accepts only injected production keystore credentials")
    flow = WORKFLOW.read_text("utf-8")
    record("release_sha_and_main_only",
           all(token in flow for token in (
               "github.event.workflow_run.event == 'push'",
               "github.event.workflow_run.head_branch == 'main'",
               "github.event.workflow_run.conclusion == 'success'",
               'SOURCE_SHA" != "$MAIN_SHA"',
               "Exact main SHA has no successful full Validate SP-DECODE run",
           )), "Signing is bound to a successful main push and exact source SHA")
    record("v1v2v3_and_alignment",
           all(token in flow for token in (
               "--v1-signing-enabled true", "--v2-signing-enabled true",
               "--v3-signing-enabled true", "--min-sdk-version 23",
               "zipalign", "-P 16", "sha256sum --check SHA256SUMS.txt",
               "SIGNATURE_VERIFICATION.txt",
           )), "Production workflow explicitly verifies signatures, alignment and hashes")
    record("release_publication_gate",
           all(token in flow for token in (
               "--mode stable", "--mode public-preview",
               "needs['publication-gate'].outputs.approved == 'true'",
           )), "Stable and preview releases are gated independently")
    continuous = CI.read_text("utf-8")
    record("all_golden_generators_ci",
           all(token in continuous for token in (
               "android_a24_catalog.py", "android_b_generic_profiles.py",
               "android_c_ultra_profiles.py", "android_d_renz_profiles.py",
               "android_e_special_fixtures.py", "android_f_independent_fixtures.py",
               "android_g_text_fixtures.py",
               ":app:connectedDebugAndroidTest",
           )), "Synthetic parity generators A–G and connected Android API35 are configured")
    record("phase_g_documented", G_FILE.is_file(),
           "Python handlers and Android text protocols are documented separately")
    readiness = json.loads(READINESS.read_text("utf-8"))
    record("fail_closed_new_release",
           readiness.get("stableVersion") == version
           and readiness.get("decision") == "NO-GO"
           and readiness.get("ownerStableAcceptance", {}).get("approved") is False
           and readiness.get("publicPreviewApproval") is False
           and bool(check(readiness, "stable", version))
           and bool(check(readiness, "public-preview", version)),
           "No stable tag or public prerelease permitted without NEW version-scoped approval and evidence")
    outstanding = []
    for name in REQUIRED:
        evidence = readiness.get("evidence", {}).get(name, {})
        if evidence.get("status") != "verified":
            outstanding.append({"gate": name, "status": evidence.get("status", "missing"),
                                "report": evidence.get("report", "")})
    for requirement in (
        "real_exporter_version_matrix_for_new_file_formats",
        "real_text_protocol_version_matrix",
        "physical_arm64_new_version_install_and_upgrade",
        "physical_16KiB_new_version",
        "accessibility_and_performance_new_version",
        "production_signed_new_apk_cryptographic_verification",
    ):
        outstanding.append({"gate": requirement, "status": "pending", "report": ""})
    source_checks_passed = all(v["pass"] for v in checks.values())
    return {
        "schemaVersion": 1, "phase": "H", "targetVersion": version,
        "targetVersionCode": version_code,
        "catalog": {
            "suffixes": len(entries),
            "nativePortRoutes": catalog["androidNativePortSuffixes"],
            "certifiedCurrentExporterSuffixes": catalog["androidCertifiedSuffixes"],
            "syntheticCoveredSuffixes": catalog["syntheticLinuxCoveredSuffixes"],
            "byPhase": counts
        },
        "sourceChecks": checks,
        "sourceGate": "PASS" if source_checks_passed else "FAIL",
        "productionGate": "NO-GO",
        "signedCandidatePossibleAfterMainCI": source_checks_passed,
        "pendingEvidence": outstanding,
        "assertions": {
            "source_static_checks_only": True,
            "no_real_vendor_exporters_claimed": True,
            "android_emulator_coverage_is_not_physical_arm64_coverage": True,
            "source_manifest_does_not_prove_merged_manifest": True,
            "no_signing_secrets_or_real_configurations_processed": True
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version")
    parser.add_argument("--code", type=int)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--require-production", action="store_true")
    args = parser.parse_args()
    report = inspect(args.version, args.code)
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(f"[H] static gate: {report['sourceGate']} | production: "
          f"{report['productionGate']} | {report['catalog']['nativePortRoutes']} native"
          f" | {len(report['pendingEvidence'])} evidence items pending")
    for name, entry in report["sourceChecks"].items():
        print(("PASS" if entry["pass"] else "FAIL") + " " + name + ": " + entry["detail"])
    if report["sourceGate"] != "PASS":
        return 1
    if args.require_production and report["productionGate"] != "GO":
        print("NO-GO: real exporter, device, upgrade and QA reports are not yet verified.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

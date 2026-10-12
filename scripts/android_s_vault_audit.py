#!/usr/bin/env python3
"""Phase S: fail-closed offline asset packaging, provenance and parity audit.

Never prints source decoder passwords or table content. The .spv wrapper
removes plaintext assets from the APK but is NOT secret against an attacker
who extracts its compiled build-local unwrap key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "android/app/src/main/assets"
REQUIRED = (
    "embedded_kotlin_profiles.json",
    "flex_f_profiles.json",
    "generic_b_profiles.json",
    "hc_source_keys.json",
    "http_tweak_source_tables.json",
    "legacy_epro_npv2_keys.json",
    "npvs_v5_tables.b85",
    "nur_tunnel_server_endpoint.json",
    "renz_d_profiles.json",
    "ultra_c_profiles.json",
)
OPTIONAL = ("npv_whitebox.bin",)
ALL = REQUIRED + OPTIONAL
KOTLIN = ROOT / "android/app/src/main/java/com/ghostdeveloper/spdecode/parity"
LOADERS = {
    "EmbeddedDecoderMaterials.kt": "embedded_kotlin_profiles.json",
    "GenericProfileStore.kt": "generic_b_profiles.json",
    "UltraProfileStore.kt": "ultra_c_profiles.json",
    "RenzProfileStore.kt": "renz_d_profiles.json",
    "HcPort.kt": "hc_source_keys.json",
    "HttpTweakReferencePort.kt": "http_tweak_source_tables.json",
    "LegacyModuleText.kt": "legacy_epro_npv2_keys.json",
    "IndependentF1Port.kt": "flex_f_profiles.json",
    "NpvsWhitebox.kt": "npvs_v5_tables.b85",
    "NpvWhiteboxReferencePort.kt": "npv_whitebox.bin",
}
LOADERS_OUTSIDE_PARITY = {
    "NurTunnelServerCatalog.kt": "nur_tunnel_server_endpoint.json",
}
MAGIC = b"SPV1"


def manifest(source: Path = SOURCE) -> dict:
    missing = [name for name in REQUIRED if not (source / name).is_file()]
    if missing:
        raise ValueError("Required decoder sources missing: " + ", ".join(missing))
    result = {}
    for name in ALL:
        file = source / name
        if not file.is_file():
            continue
        raw = file.read_bytes()
        if not raw:
            raise ValueError("Empty protected source: " + name)
        if name.endswith(".json"):
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError("Invalid protected JSON: " + name)
        result[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


def check_source(root: Path = ROOT) -> None:
    gradle = (root / "android/app/build.gradle.kts").read_text("utf-8")
    reader = (root / "android/app/src/main/java/com/ghostdeveloper/spdecode/parity/SecureAssetVault.kt").read_text("utf-8")
    for name in ALL:
        if f'"{name}"' not in gradle or f'"{name}"' not in reader:
            raise ValueError("Vault allowlist mismatch: " + name)
    required_markers = (
        "sourceSets.getByName(\"main\").assets.setSrcDirs",
        "prepareSecureAssetVault",
        "AES/GCM/NoPadding",
        "VaultBuildKey.kt",
        "Plaintext protected asset was packaged",
    )
    if not all(marker in gradle for marker in required_markers):
        raise ValueError("Vault build transformation is incomplete")
    for file, name in LOADERS.items():
        text = (root / "android/app/src/main/java/com/ghostdeveloper/spdecode/parity" / file).read_text("utf-8")
        if f'SecureAssetVault.open(context,"{name}")' not in text and (
            f'SecureAssetVault.open(ctx,"{name}")' not in text and
            f'SecureAssetVault.open(context,ASSET)' not in text and
            f'SecureAssetVault.readText(ctx, ASSET)' not in text
        ):
            raise ValueError("Unprotected Android resource loader: " + file)
    for file, name in LOADERS_OUTSIDE_PARITY.items():
        text = (root / "android/app/src/main/java/com/ghostdeveloper/spdecode" / file).read_text("utf-8")
        if f'SecureAssetVault.readText(context, "{name}")' not in text:
            raise ValueError("Unprotected Android resource loader: " + file)
    # These are different security classes. Do not put signing secrets,
    # backend credentials or AndroidKeyStore-generated history keys in assets.
    signed = (root / ".github/workflows/android-signed-release.yml").read_text("utf-8")
    if not all(s in signed for s in (
        "secrets.SPDECODE_SIGNING_KEYSTORE_BASE64",
        "secrets.SPDECODE_SIGNING_KEY_PASSWORD",
        "SPDECODE_TRUSTED_SIGNER_SHA256",
    )):
        raise ValueError("Permanent signing-key separation broken")


def check_apk(apk: Path, expected: dict) -> dict:
    if not apk.is_file():
        raise ValueError("APK not found: " + str(apk))
    results = {}
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
        for name in ALL:
            raw_path = "assets/" + name
            encrypted = raw_path + ".spv"
            if raw_path in names:
                raise ValueError("PLAINTEXT decoder source present in APK: " + name)
            if name in expected:
                if encrypted not in names:
                    raise ValueError("Encrypted decoder resource missing in APK: " + name)
                data = zf.read(encrypted)
                if not data.startswith(MAGIC) or len(data) < 33 or len(data) > 8 * 1024 * 1024 + 32:
                    raise ValueError("Malformed encrypted vault asset: " + name)
                # No source-byte echoing; the original hash is known only
                # to the source manifest, not reproduced in APK metadata.
                results[name] = {"encrypted": True, "bytes": len(data)}
            elif encrypted in names:
                raise ValueError("Optional vault resource absent from source: " + name)
        if "assets/decoder_catalog.json" not in names:
            raise ValueError("Public decoder catalog must remain packaged")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, help="Write sha256 parity manifest for Android instrumented tests")
    parser.add_argument("--apk", type=Path, help="Verify APK contains encrypted resources but no plaintext profile assets")
    parser.add_argument("--report", type=Path, help="Write sanitized JSON report")
    args = parser.parse_args()
    check_source()
    expected = manifest()
    result = {
        "phase": "S.1",
        "assetCount": len(expected),
        "required": len(REQUIRED),
        "optional": [name for name in OPTIONAL if name in expected],
        "status": "PASS",
        "assetClassification": "historical_public_decoder_material_recoverable_after_reverse_engineering",
        "privateSigningKeysBundled": False,
        "runtimeKeyCanBeRecoveredFromApk": True,
        "privateHistoryKey": "android_keystore_generated_per_install",
        "coverage": "source_inventory_and_apk_container_not_independent_device_certification",
    }
    if args.fixtures:
        args.fixtures.parent.mkdir(parents=True, exist_ok=True)
        args.fixtures.write_text(json.dumps({"schemaVersion": 1, "files": expected}, sort_keys=True) + "\n", "utf-8")
    if args.apk:
        result["packaged"] = check_apk(args.apk, expected)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", "utf-8")
    print(f"Phase S vault: PASS; {len(expected)} protected resources; "
          f"APK checked: {'yes' if args.apk else 'no'}; no key material printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

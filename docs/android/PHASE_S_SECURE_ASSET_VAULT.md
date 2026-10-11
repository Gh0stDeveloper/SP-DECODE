# Phase S — Android asset hardening, key classification and decoder parity

**Status:** S.1 implementation on a feature branch. No stable release version bump.
**Threat model:** offline SP-DECODE Android, historical source-available decoder constants, no Internet permission, signed releases via GitHub Secrets.

## Findings and key classes

| Material | Location | Class | Confidentiality properties |
| --- | --- | --- | --- |
| Historical AES/DES/Argon profiles | generic_b, ultra_c, renz_d, flex_f profile sources | Public/historical decoder material | Already present in this repository and recoverable from a reverse-engineered APK |
| HTTP Custom, HTTP Tweak, ePro/NPV2 materials | hc_source_keys, http_tweak_source_tables, legacy_epro_npv2_keys | Public/historical embedded constants | Recoverable; never classify as backend/API credentials |
| NPVS v5 whitebox and reference NPV whitebox | npvs_v5_tables.b85, generated npv_whitebox.bin | Public or algorithm-derived cryptographic tables | Originally encoded, not secret; now authenticated in APK |
| Signed APK certificate SHA-256, application ID | Android package / BuildConfig | Public identity / trust anchor | Public by design; changing signing identity can break in-place updates |
| Android release signing private key | GitHub Secrets (PKCS12 only in CI temporary runner directory) | High-value private | **Must never enter the repository or APK** |
| Local history AES-GCM key | AndroidKeyStore on the device | Device private | Must not be exported or compiled into app resources |
| User-imported configuration credentials | User-provided files/results | Sensitive user data | Encrypted local history; never include in diagnostics, analytics or CI |

**Important:** A public GitHub repository containing original decoders and config constants cannot be made confidential by encrypting the APK. The encrypted resource wrapper stops casual plaintext ZIP inspection, not forensic key extraction. Build-generated wrapping material is inside the app DEX and can be reconstructed. AndroidKeyStore is appropriate for keys provisioned locally, not for an offline universal decoder key that all installations must share.

## S.1 Secure Asset Vault (initial migration)

1. **Originals remain canonical in source** under `android/app/src/main/assets`, so existing Python exporters, fixture generators and golden tests keep working. No new private secrets are committed.
2. Gradle `prepareSecureAssetVault` creates a clean generated assets tree and copies nonprotected resources unchanged. The Android `main` asset sourceSet is **only** this generated tree, not the original directory.
3. Nine protected resource names are encoded individually as `<name>.spv`: `SPV1` magic (4 bytes), 12-byte random nonce, AES-256-GCM ciphertext and 16-byte GCM tag. The authenticated associated data is `spdecode:s1:<name>`, binding the ciphertext to the intended filename.
4. A fresh wrapping key is generated with `SecureRandom` per build. The generated Kotlin key material is separated into two XOR integer arrays. This is only a reverse-engineering obstacle, **not a secrecy boundary**, since both arrays ship in the APK. R8 remains enabled for release.
5. The Kotlin `SecureAssetVault` reader enforces a strict resource-name allowlist, maximum byte length, exact magic, authenticated decryption and failure on corrupted/swapped resources. Old decoders receive exactly the same original bytes through a compatible `InputStream`.
6. Legacy Hc/Epro/NPV2, generic B, Ultra C, RENZ D, Flex F, HTTP Tweak and NPVS tables now use this reader. Decoder JSON schemas and algorithms were not altered.

**Note:** `npv_whitebox.bin` is generated before Gradle on CI runners. It is included in the vault when present; the other eight protected assets must always be present. Nonsecret UI labels/catalog resources remain normal assets.

## CI and parity gates

- `scripts/android_s_vault_audit.py` inventories **source metadata only** (SHA-256 hashes, sizes), verifies the loader allowlist, and produces `parity/s-vault-fixtures.json` for instrumentation.
- `SecureAssetVaultInstrumentedTest` decrypts every packaged protected resource on Android and checks its SHA-256/size against the original independently hashed Python source. It also tests GCM tampering, cross-resource substitution and invalid filenames.
- `tests/test_android_s_vault_audit.py` tests synthetic APKs that include raw, malformed or missing protected resource entries, without processing user credentials.
- The CI gate scans the actual **debug APK and unsigned R8 release APK** for missing `.spv` files and prohibited readable profile assets. The separately signed production pipeline also runs the APK audit before release verification.
- Any failed GCM tag, missing asset, plaintext asset regression, source mismatch or emulator regression is **NO-GO**. Do not silently fall back to the original plaintext resources.

## S.2–S.5 follow-up (not yet certified)

- **S.2**: inventory cryptographic constants embedded directly in Kotlin/Dex, classify per-format and migrate high-exposure constants in safe batches with synthetic/reference parity.
- **S.3**: enforce diagnostics redaction, certificate pinning invariants and secret scanning across code and generated APK, including standalone scripts and repository history.
- **S.4**: assess optional user-password-derived or remotely provisioned truly private profiles without breaking offline default mode; never label app-shipped keys irrecoverable.
- **S.5**: full signed physical-device upgrade, ARM64/16KiB, accessibility/performance and real-exporter regression before owner-approved production version bump.

## Signing clarification

The Android signing certificate **is public**. Its display name and SHA-256 identity are not private credentials. Renaming or regenerating the signing identity solely to hide the app name provides no secrecy and risks incompatible updates. Retain the production private key exclusively in GitHub Secrets.

## Local verification

```sh
python scripts/android_s_vault_audit.py
python -m unittest tests.test_android_s_vault_audit -v
# Generate source profiles and whitebox as in validate.yml, then:
python scripts/android_s_vault_audit.py --fixtures android/app/src/androidTest/assets/parity/s-vault-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
cd ..
python scripts/android_s_vault_audit.py --apk android/app/build/outputs/apk/debug/app-debug.apk
```

Do not publish a stable APK automatically from this feature branch. Merge only after CI passes and user decides the subsequent production version.

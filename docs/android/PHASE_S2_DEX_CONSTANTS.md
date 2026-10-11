# Phase S.2 — Kotlin / DEX decoder material hardening

**Scope:** Native SP-DECODE Android, no network, no signing changes, no version bump.

## Risk analysis

SP-DECODE historically contains per-format decoder constants directly in Kotlin
source. R8 may rename classes, but cannot keep string literals private. A user
can inspect `classes*.dex` or reverse-engineer the APK. S.1 moved eight source
assets plus optional generated NPV whitebox data behind authenticated AES-GCM,
but did **not** move literals within Kotlin source. S.2 migrates a controlled,
parity-testable batch and establishes an ongoing DEX-level regression gate.

The original decoder methods and matching Python/JavaScript references remain
published in this repository. All migrated values are **historical public
decoder material**, not production service credentials. The same reversible
AES-GCM wrapping key remains embedded in the APK. This increases resistance
to casual string extraction; **it does not provide confidentiality against
reverse engineering**, rooting, runtime instrumentation or source inspection.

## Implemented migration

| Port | Literal family migrated | Byte-exact handling |
| --- | --- | --- |
| HAT / HTTP Injector HAT (`HatPort.kt`) | AES-128 source key, profile-v5 XOR string | strict RFC4648 Base64 decode; unchanged character XOR ordering |
| HTTP Custom (`HcPort.kt`) | outer XOR key | original hexadecimal to bytes |
| LTM Tunnel (`IndependentF1Port.kt`) | source password encoded as hexadecimal | preserve old hex → UTF-8 decode (replacement semantics) → UTF-8 encode |
| VN7 (`IndependentF1Port.kt`) | two candidate passwords in original order | UTF-8 encoding; preserve candidate-loop/fallback behavior |

**Not migrated in S.2:** protocol identifiers, nonsecret fixed nonces, JSON
field labels, algorithm behavior, the remaining hardcoded Kotlin constants
from other formats, and runtime user credentials. Future formats need
separate fixtures and must never share unrelated decoder profiles.

The **canonical source** is
`android/app/src/main/assets/embedded_kotlin_profiles.json`; it is
source-available to preserve deterministic parity with the legacy engines.
The production APK contains only
`assets/embedded_kotlin_profiles.json.spv`. Gradle's `prepareSecureAssetVault`
authenticates the package using AES-256-GCM and per-file AAD, while
`EmbeddedDecoderMaterials.kt` exposes strictly validated typed adapters.
A missing/broken asset fails closed, without a plaintext fallback.

## CI, security checks and compatibility

- `scripts/android_s2_dex_audit.py` inventories potential byte-array,
  hexadecimal and Base64 material across **all** native decoder Kotlin
  sources without printing any candidate strings. Heuristic hits are
  **not** automatically secret findings; human assessment is needed.
- The same audit fails if migrated literals are reintroduced in the
  three source files or appear as readable byte sequences in any
  `classes*.dex` of the debug, R8 or signed release APK.
- Python tests exercise source-guard, deterministic SHA-256 material
  fixtures and synthetic APKs with leaking `classes2.dex`.
- `PhaseS2DexMaterialsInstrumentedTest` compares six recovered runtime
  byte arrays/string encodings with source-derived fixture SHA-256 digests
  on Android API 35.
- Previous Phase S.1 encrypted-asset checks still validate source bytes and
  tamper detection. Existing native decoder corpus tests remain enabled.
- The signed APK workflow independently rejects plaintext assets and
  migrated DEX constants before version/signature verification.

### Local checks

```sh
python scripts/android_s_vault_audit.py
python scripts/android_s2_dex_audit.py --report /tmp/spdecode-s2.json
python -m unittest tests.test_android_s2_dex_audit -v
python scripts/android_s2_dex_audit.py \
  --fixtures android/app/src/androidTest/assets/parity/s2-constants-fixtures.json
# After source fixture exporters have run:
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
cd ..
python scripts/android_s2_dex_audit.py \
  --apk android/app/build/outputs/apk/debug/app-debug.apk
```

## Remaining work / release boundary

- Continue incremental, separately validated batches for TLS/EHI/Dark
  Tunnel/NPVS and other embedded constants, prioritizing format coverage.
- S.3: repository/CI secret scanning, redacted logging and diagnostics;
  improve policy for new sensitive data.
- S.4: truly private passwords/keys must be user-entered or provisioned
  outside the APK; user-password-derived keys cannot be replaced by
  a universally embedded secret.
- S.5: ARM64 device installs and upgrades, 16 KiB device checks, vendor
  exporter parity and owner release decision.

**No release is authorized by these checks alone.** Keep permanent signing
secrets in GitHub Secrets and release `v1.1.1` intact unless a later version
passes the complete stable production gate.

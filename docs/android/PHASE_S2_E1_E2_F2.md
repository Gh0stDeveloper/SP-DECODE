# Phase S.2 — Native Phase E.1, E.2 and F.2 decoder material migration

**Repository:** `Gh0stDeveloper/SP-DECODE`  
**Branch:** `feat/android-phase-s2-e1-e2-f2`  
**Distribution:** no version bump; no stable APK published by this branch.

## Source classification and integrity

Three additional decoder families used source-visible constants within Android
Kotlin objects. These are **historical, public/reproducible decoder constants**,
not server API tokens, user-imported credentials, AndroidKeyStore keys or the
private APK-signing keystore.

All migrated canonical values are maintained in the source
`android/app/src/main/assets/embedded_kotlin_profiles.json`, nested under
`specialKeyFamilies`. Only the authenticated
`embedded_kotlin_profiles.json.spv` exists in the installed APK (Phase S.1
AES-256-GCM envelope with random nonce and per-filename AAD). The strictly
typed `PhaseS2FamilyMaterials` reader checks byte counts, character encodings
and candidate-array ordering, then supplies keys **per decode**. No global
mutable session context or fallback to plaintext assets is used.

### Engines covered

| Engine | Source key families | Critical parity semantics |
| --- | --- | --- |
| `SpecialE1Port.kt` | Sentinel, V2Box, SlipNet, EUT, Juan/Mobi | Sentinel's XOR and HMAC; V2Box secondary SHA candidate; EUT Latin-1 16-byte password; Juan PBKDF2 source password |
| `SpecialE2Port.kt` | WyrLite, WyrVPN, IntVPN, FTHP, AR/MSY, EC | WyrLite ChaCha/GCM method order; FTHP password order; AR nested key/IV; 15-byte EC key padded to 16 only at XXTEA use |
| `IndependentF2Port.kt` | CREV, KTR, Zoba, DEV, N4 | CREV source-key ordering, KTR CBC key/IV, exact DEV Unicode alphabet, N4 17/16/16-character Unicode conversion tables and source key derivations |

The `itv` format in Phase E.1 does **not** have a static universal key;
it obtains decryption input from its data. It remains unchanged. Existing
protocol nonsecrets and JSON field names remain as source literals, as intended.

## Regression gates

- `scripts/android_s2_family_audit.py`: inventory and SHA-256 hashes for
  **30 distinct source-material entries**; error if a migrated constant
  reappears directly in its Kotlin engine or if a route bypasses the vault.
- Python tests include a synthetic multidex APK with a prohibited original
  string; the scanner must reject it without logging the literal.
- Android `PhaseS2FamilyMaterialsInstrumentedTest` checks all 30 runtime byte
  sequences (including Unicode and Latin-1 exactness) against hashes computed
  from canonical source *outside Android*.
- Existing `PhaseESpecialInstrumentedTest` checks Python→Android parity of
  source-encrypted Phase E formats. `PhaseFIndependentInstrumentedTest`
  verifies Phase F source-encrypted formats and alternative key variants.
- GitHub Actions audits debug, minified R8 release and signed production APK
  `classes*.dex` for long original material strings, and fails if a raw
  `embedded_kotlin_profiles.json` is packaged. Short/nonunique literals
  are not treated as proven private secret leaks.
- No stable release is permitted based solely on these tests; device/owner
  verification of representative real configurations remains useful.

## Important security boundary

Static decoder constants packaged in an entirely offline APK cannot be
hidden from a determined reverse engineer. SPV1's unwrap key is itself
shipped in compiled Android code; source materials are also committed in
the public GitHub repository. This migration **reduces obvious plaintext
exposure and detects packaging regressions**. It does not introduce private
credentials or imply that public decoder keys become cryptographically secret.

## Local commands

```sh
python scripts/android_s2_family_audit.py --report /tmp/s2-family.json
python -m unittest tests.test_android_s2_family_audit -v
python scripts/android_s2_family_audit.py \
  --fixtures android/app/src/androidTest/assets/parity/s2-family-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
cd ..
python scripts/android_s2_family_audit.py \
  --apk android/app/build/outputs/apk/debug/app-debug.apk
```

## Remaining S.2 audit scope

A raw-string heuristic scan of all Kotlin engines can still find constants
outside E1/E2/F2; their presence must be classified with reference-port
provenance and tested by format-specific fixtures before migration.
Do not automatically treat generic key names, salts, IVs, labels, public
signing fingerprints or user-entered values as private hardcoded secrets.

# Phase S.2 continuation — TLS 8.5.0, EHI, EHIL, Dark Tunnel and six legacy engines

## Scope and status
This is the next high-exposure security batch after PR #72. The implementation
does not change file decoding algorithms, cryptographic modes, parser rules, JSON
result formats, supported inputs, key-candidate order, versionCode or the
permanent Android signing identity. It does not publish a new release.

### Migrated from hardcoded Kotlin DEX
- **TLS Tunnel:** all six profile keys, preserving ordered AES-GCM candidates,
  strict authentication and profile #6's historical result layout.
- **HTTP Injector .ehi:** the two outer-layer keys, the original XXTEA key,
  three bypass IVs and three standard IVs. Argon2id and XChaCha20-Poly1305
  processing and field-local recovery are unchanged.
- **HTTP Injector Lite .ehil:** three first-layer AES keys, two second-layer
  keys and seven IV candidates. Its shared first key is verified against EHI.
  The independent source candidate order and parser remain unchanged.
- **Dark Tunnel:** original AES-256 outer key, AES-192 nested key and CFB IV.
  All nested/recursive calls now receive per-decode material explicitly,
  avoiding global mutable context.
- **Routing:** `AndroidOfflineDecoderRouter` and the Android parity tests
  pass the same `Context` to the existing engines.
- **Source:** `embedded_kotlin_profiles.json` remains auditable source-controlled
  canonical historical material, while Gradle packages only its authenticated
  `SPV1` ciphertext in the Android APK.

## Second S.2 migration batch — additional legacy engines

The following six native decoder ports were added, with source-exact material
in the same authenticated `embedded_kotlin_profiles.json.spv` bundle:

| Port | Migrated material | Semantics preserved |
| --- | --- | --- |
| SocksIP (`SipPort.kt`) | AES-128 key and VER8 AES-256 key | Original ECB wrapper; VER8 GCM requires authentication |
| SSH (`SshPort.kt`) | Blowfish password | Existing fixed IV, XML filtering and output untouched |
| SKS (`SksPort.kt`) | Original 32-character MD5 input prefix | Preserves version-specific MD5-to-AES derivation |
| Cloudy (`CloudyPort.kt`) | Base64-derived AES-256 key and IV | Identical CBC operation and output labels |
| Gold Tunnel (`GoldPort.kt`) | Historical SHA-256 seed | Original nested field decryption and fixed nonsecret string mappings |
| TNL/OpenTunnel (`TnlPort.kt`) | Two original TNL passphrases, OPL2 secret and OpenTunnel key | Keeps original candidate order, checksums, password derivation and scramble |

`LegacyBatch2Materials.kt` provides typed byte-level adapters rather than
adding plaintext fallbacks. The Android router and existing synthetic golden
tests now pass the application context, without changing public filenames,
output schemas, encryption modes or key selection.

`scripts/android_s2_legacy_audit.py` independently inventories **11** source
materials and fails if the old literal strings are reintroduced into the six
source ports or any `classes*.dex` in an APK. Its sanitized SHA-256 parity
manifest is checked at runtime by
`PhaseS2LegacyMaterialsInstrumentedTest.kt`. Existing parity fixtures for
SocksIP, SSH, SKS, Cloudy, Gold and TNL remain mandatory.

Across S.2 so far: 5 ports in PR #72, 4 higher-risk ports in this PR and
6 additional legacy ports, for **15 migrated engine ports**. This is not a
claim that all 103 Kotlin parity/support files contain sensitive secrets or
that every format's constants are already migrated. The original public
source remains available for reproducible compatibility checks.

### Validation
- Python metadata checks in `scripts/android_s2_extra_audit.py` hash 30 source
  materials and compare expected counts/sizes, without logging secrets.
- Source audit rejects the original constants being reinstated as Kotlin literals.
- Debug, R8 and signed APK checks reject those exact literals from all
  `classes*.dex` or an unencrypted `embedded_kotlin_profiles.json` asset.
- Android instrumentation compares all 30 runtime materials with independent
  SHA-256 fixtures, then runs existing TLS, EHI, EHIL and Dark Python golden
  fixtures including failure and tampering paths.
- No fallback to plaintext assets if the authentication tag is invalid.

### Caveats and remaining work
This build-layer AES-GCM envelope uses a locally compiled unwrap key. It
prevents casual extraction of raw plaintext by unzipping the APK; it does **not**
make a universal offline decryption secret irrecoverable. All historical
material is also present in this open repository. A real private credential
must be external to the APK, e.g. user-supplied or independently provisioned.

The S.2 scanner intentionally continues to report potential inline constants
in other Android decoders. They require individual fixture-backed migration;
a heuristic inventory is not proof of a live secret leak or a guarantee of full
DEX secrecy.

## GitHub Actions storage quota handling
The earlier `main` workflow run after PR #72 reported GitHub's
`Artifact storage quota has been hit` on optional source-audit uploads.
This is not a decoder or compilation error. The optional **validation job**
uploads now use `continue-on-error: true`, while actual Python/Android tests,
debug/R8/Dex checks and signed-release evidence/identity gates stay fail-closed.
No production release is authorized by allowing optional diagnostic uploads
to fail.

## Check locally
```sh
python scripts/android_s2_extra_audit.py --report /tmp/spdecode-s2-extra.json
python -m unittest tests.test_android_s2_extra_audit -v
python scripts/android_s2_extra_audit.py --fixtures android/app/src/androidTest/assets/parity/s2-extra-fixtures.json
cd android
gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest
cd ..
python scripts/android_s2_extra_audit.py --apk android/app/build/outputs/apk/debug/app-debug.apk
```

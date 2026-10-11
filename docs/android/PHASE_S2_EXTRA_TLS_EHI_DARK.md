# Phase S.2 continuation — TLS 8.5.0, HTTP Injector and Dark Tunnel

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
- **Dark Tunnel:** original AES-256 outer key, AES-192 nested key and CFB IV.
  All nested/recursive calls now receive per-decode material explicitly,
  avoiding global mutable context.
- **Routing:** `AndroidOfflineDecoderRouter` and the Android parity tests
  pass the same `Context` to the existing engines.
- **Source:** `embedded_kotlin_profiles.json` remains auditable source-controlled
  canonical historical material, while Gradle packages only its authenticated
  `SPV1` ciphertext in the Android APK.

### Validation
- Python metadata checks in `scripts/android_s2_extra_audit.py` hash 18 source
  materials and compare expected counts/sizes, without logging secrets.
- Source audit rejects the original constants being reinstated as Kotlin literals.
- Debug, R8 and signed APK checks reject those exact literals from all
  `classes*.dex` or an unencrypted `embedded_kotlin_profiles.json` asset.
- Android instrumentation compares all 18 runtime materials with independent
  SHA-256 fixtures, then runs existing TLS, EHI and Dark Python golden
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

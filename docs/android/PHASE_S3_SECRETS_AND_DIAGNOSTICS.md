# Phase S.3 — Secret hygiene and privacy-safe diagnostics

**Project:** SP-DECODE Android, offline, 239 decoder formats  
**Scope:** Source tree, CI, signed APK, native Android error paths and diagnostic surfaces.

## Threat model and data classification

| Class | Examples | Handling and security boundary |
| --- | --- | --- |
| Private production material | Signing PKCS12/JKS, signing passwords, GitHub tokens, bot/service credentials | **Never** commit, package, upload to CI artifacts, print or inject as build constants |
| User-imported sensitive content | VPN username/password, SSH credentials, proxy host, complete decoded JSON, imported file name/path | Intentionally visible to the device owner. Never send through Logcat, unrequested telemetry, exception messages or diagnostics; encrypted no-backup history only |
| Public/reference material | Decoder compatibility constants in open-source engines, public APK signer SHA-256, app identifier and algorithms | Necessary for offline decoding; classify as historical public reference data, **not** private backend credentials |
| Protected local key | Per-install history AES key | AndroidKeyStore generates and retains it; never export via diagnostics or external storage |
| Build-time asset wrapping key | S.1/SPV1 build-produced AES unwrap bytes bundled in APK | Recoverable via reverse engineering; minimizes superficial plaintext inspection, **not** confidentiality against an offline analyst |

## Security controls implemented

1. `SafeDecodeDiagnostics.kt` exposes six fixed, content-free failure
   categories, with memory-only atomic counters capped at 9999. Its API
   deliberately cannot accept an exception, file name, URI, user text,
   decrypted JSON or password. No crash telemetry SDK, network calls,
   persistent diagnostic databases or Logcat side effects are introduced.
2. `MainActivity.kt` calls only the fixed event API from relevant
   file-import, text, history-write and file-export failures.
   User-visible errors remain translated static strings, **not**
   `Exception.message`, `toString()` or stack traces. Successful
   results remain full and exportable by explicit user action.
3. `scripts/android_s3_security_audit.py` rejects tracked private
   keystores, .env production files, known real credential token formats,
   private key PEM, raw Android `Log.*` / `printStackTrace` /
   `System.out.println`, shell `set -x` / bulk environment dumping and
   insecure Android backup/network policy. It checks that history uses
   AndroidKeyStore and that supported Android versions mark clipboard
   content as sensitive.
4. For debug, unsigned R8 and production-signed APKs, the same scanner
   inspects all `classes*.dex` plus text assets to reject recognizable
   private keys and service-access tokens or packaged private files.
   Existing S.1/S.2 checks continue to protect decoder source profiles.
5. The production signing workflow checks source before loading private
   signing material, verifies the final signed APK before upload, and
   calls `keytool -storepass:env STORE_PASSWORD` instead of passing the
   store password as a process command-line argument. `apksigner` already
   uses `--ks-pass env:` and `--key-pass env:`. The temporary
   PKCS12 is written with `umask 077` inside runner.temp and the
   existing `if: always()` cleanup is retained.
6. `.gitignore` rejects future accidental local commits of JKS/P12/PFX,
   keystores, machine identity and private service-account files.
   The **CI tracked-file scan** is still authoritative: `.gitignore`
   does not remove an already tracked secret.

## CI / release gates

Run from the repository root:

```sh
python scripts/android_s3_security_audit.py --report /tmp/s3-audit.json
python -m unittest tests.test_android_s3_security_audit -v
python scripts/android_s3_security_audit.py \
  --apk android/app/build/outputs/apk/debug/app-debug.apk
```

The generated report includes only rule identifiers, affected *repository
paths* and aggregate counts; it contains no matched secret or user
configuration. Never publish raw stack traces, complete decrypted payloads,
environment dumps, keystore data or debug APKs as a substitute for this
report. Full decoded data stays visible exclusively in the on-device UI,
encrypted history and owner-initiated copy/export.

## Important limitations

- Pattern-based scanning catches recognizable credentials, not every possible
  obfuscated or custom token. False positives require specific review, not
  blanket exclusions. Historical public decoder constants are handled by
  existing S.2 DEX controls, not mislabeled as private signing keys.
- An Android app cannot prevent the owner from intentionally copying or
  exporting its full decoded result. The existing clipboard sensitive flag
  applies on Android 13+; older system clipboard behavior is OS-controlled.
- Android unhandled-crash/system logging is outside application diagnostic
  API control; the app avoids explicit logging of sensitive fields. Do not
  copy a full crash dump without reviewing/redacting it first.
- The vault key can be extracted from the APK; S.3 makes no promise of
  secrecy for universal offline decoder constants.
- This phase does not authorize rebuilding or publishing a new stable APK,
  resetting the release keystore or deleting user history.

## Exit conditions

Require green Python source/tests, S.3 debug/R8 scans, existing S.1/S.2
audits, Android API 35 tests (including the no-payload diagnostics test), and
the later signed-release gate for any future production version. Document
remaining manually reviewable risks before moving to S.4.

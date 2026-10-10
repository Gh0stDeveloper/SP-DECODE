# SP-DECODE Android 1.0.7 — HTTP Injector (.ehi) full JSON repair and owner production acceptance

**Date:** 2026-10-10  
**Source reference:** `decoders/Python/HTTPINJECTOR.py`  
**Android implementation:** `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/EhiPort.kt`  
**Target:** `versionName = 1.0.7`, `versionCode = 18`, `com.ghostdeveloper.spdecode`.

## Report received from project owner

The project owner reported performing manual tests of the application's file decoders and confirmed correct behavior for the tested formats **except some HTTP Injector (.ehi) files whose displayed JSON contains only part of the decrypted fields**. The owner explicitly requested the missing-output bug be corrected and authorized a new public production APK **conditional on successful correction and validation**.

This record captures the owner's assessment. It is **not** independently measured device telemetry, a public real-exporter corpus, or independent certification of all 239 currently available external exporter versions. The specific intermittent failing real `.ehi` file was not provided and therefore cannot be claimed retested byte-for-byte.

## Cause and correction

Two concrete data-loss paths existed:

1. **Inner field decoding:** `EHIDecryptor._decode_inner_fields` and `EhiPort.decode` previously discarded nonblank string fields whenever the custom-alphabet Base64/XOR layer returned no output. HTTP Injector variants can include literal strings or values encoded in unknown representations. Both bot reference and native Kotlin decoder now retain the original field value **unchanged** if the supported field-specific decode fails. Successfully decrypted values still use the original algorithm. Every original top-level field is represented in the output.
2. **Multiline output conversion:** `ResultPresentation.parse` previously ignored physical continuation lines not prefixed with `│[۞]`. A multiline HTTP payload, proxy header, or pretty JSON in a scalar could be truncated in the app JSON view even though the native result included it. The parser now groups continuation lines with the originating field, including internal blank lines, until the next field or a decorative footer, and flattens only after the complete content is collected. JSON copy/export and the visible JSON represent all fields; the raw text remains unchanged.

The patch does not introduce unrelated cryptographic fallbacks, network permissions, external runtime requirements or replacements for successful decryption paths. It preserves already-supported standard-IV Argon2id/XChaCha20-Poly1305 profiles and bypass-IV AES/XXTEA profiles.

## Reproducible regression

`scripts/android_ehi_complete_fixture.py` produces a **synthetic** genuine-format bypass-IV `.ehi` profile and source-derived Python golden, with:

- Original custom encrypted `serverHost` and an unencrypted `plaintextHost`.
- Mixed known/unknown field representations that previously disappeared.
- HTTP payload containing CRLF, blank line and final payload body.
- Nested objects and arrays, type-preserved booleans, numbers and null.
- A last-key sentinel to detect lost tail content.

`tests/test_android_ehi_complete_result.py` verifies the Python regression and field order. `EhiCompleteResultInstrumentedTest.kt` verifies exact Python↔Kotlin decrypted output, complete typed JSON in `ResultPresentation` / `ResultJsonDisplay`, nested fields, multiline content and original-copy integrity on Android API35. Existing EHI standard-IV fixtures and 239 file-format / text-protocol tests must remain green.

The new synthetic regression is **representative, not a substitute for reproducing the owner's intermittent real .ehi file**. A different unexpected real-file representation should be reported with a private, redacted sample so the relevant parser or cipher can be corrected further.

## Production decision: OWNER-GO (version scoped)

The owner expressly authorized a production release **if this defect is corrected**. As in the established v1.0.4 owner-accepted release model, the owner may accept a bounded manual QA risk without asserting that missing independent audit evidence exists. For `v1.0.7`, permission is limited to the tested functionality and this regression fix; it does **not** carry over to future versions.

**Mandatory automated gates before publication:**

1. Python source regression, catalog, static audit and security tests all pass on **the exact `main` SHA**.
2. Android API35 instrumentation including standard and complete-profile `.ehi` tests passes; no old decoder regression.
3. `assembleRelease` is signed **only** by the permanent GitHub Secrets PKCS#12 certificate; V1/V2/V3 pass independent verification.
4. 16 KiB ZIP alignment, package/versionCode consistency, SHA256SUMS and signing report verified.
5. Production signer certificate SHA-256 matches the already published `v1.0.5-rc.1` certificate. If not, block release and investigate.
6. `scripts/android_release_gate.py --mode stable --version 1.0.7` verifies this document, exact version-scoped owner acceptance and gate decision; a successful previous-version gate is never reused.
7. GitHub Release tag `v1.0.7` must not exist already; never overwrite existing APKs/tags. Release notes must disclose owner QA vs independent unverified evidence.

**Pending non-blocking independent evidence (not marked verified):** the complete real-vendor exporter matrix (including this specific intermittently failing file), physical ARM64/16KiB multi-model validation, accessibility/performance metrics and signed in-place upgrade logs. The owner's conditional distribution instruction accepts those explicitly documented limitations, not an assertion they were tested.

The stable release must not be claimed published before the production workflow confirms a signed asset, matching SHA and public GitHub Release. If CI or signing fails, do not publish.

# SP-DECODE Android v1.0.9 — Ultra Tunnel nested AES-GCM, sole developer credit, signing integrity

**Target:** `versionName = 1.0.9`, `versionCode = 20`, `com.ghostdeveloper.spdecode`.  
**Owner approval:** 2026-10-10: owner explicitly requested public stable production after corrections, and specifically accepted this version rather than reusing v1.0.8. This is bounded, version-specific `OWNER-GO`, not a claim of independent audit.

## Root cause and verified behavior

The previous Ultra/Sandok Python and Android native decoders successfully authenticated the outer Argon2id/AES-256-GCM document, but attempted the secondary encrypted JSON fields **only without GCM AAD**. Newer Ultra Tunnel exports authenticate the same field envelope `salt[16] | nonce[12] | ciphertext | tag[16]` **with `AAD=salt`**. Because the implementation correctly rejected an invalid tag, these values were retained as Base64.

Using the owner's supplied **already-decrypted JSON example**, all eight encrypted nested fields (`BugDNS`, `CustomProxy`, `Payload`, `SNI`, `V2rayAddress`, `V2rayConfig`, `V2rayHost`, `V2raySNI`) authenticated under the existing Ultra secondary password, Argon2id memory 8192 KiB, and `AAD=salt`. Their plaintext was verified locally. The user's actual example and its plaintext are **not committed**.

Both `decoders/Python/ultra.py` and `UltraSandokPort.kt` now try authenticated `AAD=salt` first, then authenticated no-AAD as a backwards-compatible fallback. The GCM tag is **never ignored**. Unrecognized fields retain their original string. Python and Kotlin parity fixtures alternate AAD/no-AAD among the 11 known nested field names, including tamper rejection. Valid empty plaintext is preserved.

## Attribution

App clipboard JSON and original format use **Ghost Developer** as sole developer attribution. The structured app copy no longer includes third-party/group/channel footer promotions. No other personal developer is credited by the Android app.

## Resigned APK detection (defense in depth)

`ReleaseIntegrity.kt` compares the installed APK's signer SHA-256 certificate digest with the value computed from the **permanent** GitHub Secrets signing keystore at build time. Android API28+ uses `hasSigningCertificate`; API24-27 checks the installed signing certificate. On release builds, missing/incorrect signer causes immediate Activity exit. Debug instrumentation remains enabled. This detects ordinary APK re-signing but cannot provide absolute tamper resistance: an attacker can modify or remove client-side checks. Play App Signing requires an explicitly configured additional trusted certificate before using a different distribution channel.

Never hardcode the keystore/private keys in the APK or repository. Historical Ultra passwords and white-box decoding tables are bundled in the app and therefore remain at risk of reverse engineering; key management and additional R8/hardening remain a future, independently tested phase.

## Ads policy

The user requested **occasional dismissible full-screen interstitial ads** as potential revenue. **No ads are activated in v1.0.9** without the owner's own AdMob application ID and interstitial unit ID, required privacy disclosures/consent, and explicit approval for changing the app's existing **no-INTERNET** security contract. No test ad IDs are misrepresented as monetization. A separate opt-in ads integration can display provider-closeable ads at natural navigation breaks, never in the middle of a decode or the credential/results page, with rate caps and a no-ad fallback.

## Required publication checks

1. Exact-`main` full Python and Android API35 emulator validation `SUCCESS`.
2. Production `assembleRelease` uses the permanent GitHub Secrets keystore only.
3. Verify V1/V2/V3 signatures, Android package ID and version, 16 KiB ZIP alignment, matching previous public signer and checksums.
4. Publish new immutable `v1.0.9` GitHub Release, never overwrite v1.0.8.
5. Independent current-exporter version coverage, accessibility, physical 16 KiB/ARM64 device reruns, real installed APK upgrade logs and additional anti-tamper resilience remain pending, **not verified by assertion**.

Owner distribution decision does not transfer to 1.1.0 or later.

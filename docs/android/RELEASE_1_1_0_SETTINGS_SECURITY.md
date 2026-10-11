# SP-DECODE Android v1.1.0 — Stable production release decision

**Product-owner authorization:** 2026-10-10: the owner explicitly requested shipping the already-merged Settings, Telegram-only contacts, first-use interactive guide and R8 integrity hardening as the **public stable** Android release. Target versionName: `1.1.0`, versionCode: `21`. Preserve app ID `com.ghostdeveloper.spdecode`, historical decoding features, encrypted history and permanent GitHub Secrets keystore. No advertisements or Internet permission are introduced.

## Changes since the public v1.0.9 APK

- Settings link to **Ghost Developer only** as the app developer with Telegram developer, group and channel contacts, no repository or GitHub Issues links. Display actual versionName/versionCode from the installed app.
- Localized five-step interactive first-use tour (Spanish, English, Brazilian Portuguese, Arabic); highlight import/text and navigate Home/History/Formats/Settings. Skip/finish remembers progress and a Settings button can restart the tour.
- Release builds enable R8 code shrinking, optimization, obfuscation and resource shrinking. ProGuard rules narrowly preserve Room and Gson reflection requirements.
- Strengthen the existing signing-certificate SHA-256 fingerprint check with release debuggability/debugger checks at startup and on resume. Debug builds continue to work for Android instrumentation.
- No change to VPN decoder algorithms. Previous NPVS v5 full-JSON, Ultra nested AES-GCM salt AAD, HTTP Injector JSON, and Telegram copy formatting are retained.
- The app remains offline (no INTERNET permission), locally decodes and stores encrypted results. No AdMob SDK was added.

## Evidence and explicit limitations

- PR #67 tests validated original Python CI, Android API 35 emulator and **unsigned R8 release compile smoke** with SUCCESS before merging. This is meaningful regression coverage, but does **not** prove that the fully signed, R8-obfuscated release works on every physical ARM64 device.
- After merging the v1.1.0 bump, an **exact-main** full CI suite must pass again. The separate production signer workflow must build `assembleRelease` from that exact SHA, inject the original permanent signer fingerprint from GitHub Secrets, verify V1/V2/V3 and prior signing certificate, 16KiB alignment, version/manifest, SHA-256 and publish a **new** immutable tag `v1.1.0`.
- The project's pending external/current-exporter corpus, independent device metrics, accessibility/performance and installed signed-APK upgrade retests **remain pending**, not independently verified.
- R8 and local anti-repackaging are defense-in-depth; neither protects embedded/static keys against determined reverse engineering, and app UI link removal does not change the public GitHub repository's visibility or prior licenses.

**Owner-go is version-scoped:** explicitly approves publishing v1.1.0 as a stable APK with the above documented QA limits after mandatory gates, and must not be inherited by v1.1.1/1.2.0. Do not re-use or overwrite the v1.0.9 release.

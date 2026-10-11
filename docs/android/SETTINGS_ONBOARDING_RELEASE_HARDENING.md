# Android Settings, First-Use Guide and Offline Release Hardening

Scope: Android UI / local protections; no format decoder, private credentials, network permission, billing integration or backend contract is changed.

## Telegram-only support
The **Settings > Developer** section contains only Ghost Developer and three Telegram contacts:
- Developer: https://t.me/Gh0stDeveloper
- Group: https://t.me/CodeBreakersHub
- Channel: https://t.me/GhostDeve

The former GitHub repository, Issues and open-source solicitation are **removed from in-app Settings** and deleted from the Activity's external-link allowlist. The source repository, licenses and existing GitHub project/website remain unchanged; **hiding an app link does not make an already-public repository private**. To restrict future source access the repository owner must review GitHub visibility/licensing and previously cloned copies separately.

Settings now presents the installed `BuildConfig.VERSION_NAME` and `VERSION_CODE` rather than a stale hardcoded version, a private/local security summary, and a replay button for the tutorial.

## First-use interactive guide
A localized five-stage Compose guide is presented on the first launch after the branded splash and after dismissing a What's New modal. It has **Next / Finish / Skip** controls and highlights real Home import, Home text, History, Formats, and Settings navigation controls. Steps navigate between tabs automatically; guide progress remains in memory; completion is stored in app-private `first_run_guide_completed` preferences. Users may restart it at any time from Settings. It never sends configuration contents, asks for permissions, or touches encrypted history.

All guide and Settings strings are localized in English, Spanish, Brazilian Portuguese and Arabic; Arabic uses the app's locale-aware RTL configuration.

## Local release integrity
- An official release APK is signed from **GitHub Secrets**. Its allowed SHA-256 signing certificate is embedded as a **public digest**, and checked by `ReleaseIntegrity.isTrusted`.
- The check also rejects production processes unexpectedly built as debuggable or with a connected debugger. It is verified at startup and on Activity resume; debug builds remain testable.
- For GitHub releases we do **not** require Google Play installer/source recognition, because users download APKs from GitHub.
- No cleartext or Internet permission is added; the Android manifest retains `usesCleartextTraffic=false`.
- **R8** code shrinking, optimization, name obfuscation and resource shrinking are enabled for **release builds only** with narrow Room/Gson preservation rules. Debug APKs remain un-obfuscated for instrumentation.
- CI compiles an **unsigned R8 release smoke** before the emulator tests; this artifact must **never** be published. The separate release pipeline is still required to sign with the permanent key (V1/V2/V3) and verify certificate parity.

**Limits:** R8 is obfuscation, not encryption of embedded keys or mathematical proof of integrity. Repackagers can modify client checks, and source already publicly available may have been copied. Root/virtualized environments and hook frameworks can bypass purely local protections. The certificate check is compatible with the existing GitHub signing identity; publishing via Google Play App Signing requires reviewing the alternate certificate and independent validation before enforcing it.

## Verification / manual QA
- Fresh install: What's New then five guide steps; skip/finish hides the guide and persists completion.
- App restart: guide stays dismissed. Settings > Interactive guide restarts it.
- Switch locale to es/en/pt-BR/ar and repeat guide; verify correct translation and RTL.
- Settings: verify **no GitHub links** and only three distinct Telegram destinations, verify real version/build.
- Existing encrypted history, decoding and JSON copy/export remain unchanged.
- On an actual **permanently signed release APK**, verify normal startup and import results; alter/re-sign a copy with a *different* test certificate and confirm it exits. Never publish the test-signed variant.
- Inspect R8 mapping only in trusted CI build artifacts. Avoid committing mappings or APK signing private material.

# SP-DECODE Android — baseline histórico y migración de 239 formatos

> **Phase B update (migration branch):** the app recognizes 239 formats; **142** have native Android routes (61 historical + 81 generic AES/DES), **97** remain disabled. See [Phase B validation](../docs/android/PHASE_B_GENERIC_81.md).

> Actualización de Fase A: el proyecto cuenta con aplicación Compose funcional y
> un catálogo v3 de **239 formatos registrados**, de los cuales **61** tienen
> rutas Android anteriores y **178** permanecen **sin implementar**. Esta
> migración no habilita los 178 motores ni constituye certificación total.
> Ver [Fase A y criterios de CI](../docs/android/PHASE_A_239_REGISTRY.md).

# A.2.4 — Android instrumented parity baseline

This directory is an **experimental Android test host**, not SP-DECODE's
finished application. It deliberately has no network or storage permission,
user import interface, support catalog, history, or exposed profile decoding
UI. Phase B's full app and phases C–E remain future work.

The native `V2RayReferencePort` supports **only two synthetic .v2 reference
vectors** (`ev2ray-plain`, `ev2ray-aes128`). It uses platform JCA (AES-ECB)
and compares raw UTF-8 output byte-for-byte with the original Python golden
in an Android instrumented test on an emulator. Unknown versions fail closed.
Keys are existing historical **public-to-this-repository constants**, never
production service credentials. Embedded constants are recoverable from APKs.

### Evidence gates

1. Run `PYTHONPATH=. python scripts/android_a24_prepare.py --output-dir android/app/src/androidTest/assets/parity` from repo root to create deterministic test assets from the manifest, verifying SHA-256.
2. From `android/`, run `gradle --no-daemon :app:assembleDebug :app:assembleAndroidTest` with JDK 17, Android SDK 35, AGP 8.9.2, Gradle 8.11.1.
3. With an Android emulator connected, run `gradle --no-daemon :app:connectedDebugAndroidTest`.
4. Only a successful connected Android test job qualifies the **specific synthetic vectors** for native runtime parity. A Linux-only golden/compile is not proof of Android execution.

**Not verified:** other 58 suffixes, other .v2 export variants, actual exporter
app versions, arm64 device ABI, 16-KiB page size, 4-language UI, Chaquopy
wheels or any release APK. These limitations are intentional, not hidden.

# SP-DECODE Android — official guide

> **Current as of 2026-10-09:** the native Android APK **has been implemented and published**. Stable **v1.0.4** is publicly released. **v1.0.5-rc.1** is a public APK signed with the permanent production keystore but **v1.0.5 stable remains NO-GO** pending validation of additional real exporter samples. Earlier A-series phase specifications document historical development, not the current app availability.

[Repository overview](../../README.md) · [Guía en español](../../README.es.md) · [All releases](https://github.com/Gh0stDeveloper/SP-DECODE/releases)

## Get the APK

| Channel | Version | Download | Notes |
|---|---|---|---|
| Stable (owner-accepted) | v1.0.4 | [Official stable release](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4) | Does not imply all exporters are independently certified |
| Preview (production-signed) | v1.0.5-rc.1 | [Official prerelease](https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1) | Compatibility updates; stable gate still NO-GO |

Releases contain the APK, `SHA256SUMS.txt` and `SIGNATURE_VERIFICATION.txt`. Never substitute debug-signed builds for the production APK. A certificate mismatch typically prevents in-place updating.

## Implemented application

SP-DECODE Android uses **Kotlin and Jetpack Compose**, targets **Android API 35**, and supports **Android 7.0+** (minSdk 24). It is local-only and requires no bot, server, Telegram account, Internet or Node/Python/PHP interpreters on the device.

- Local file import and batch processing; **60 registered file suffixes with native Android routing**.
- Dedicated text/link decoders; `nm-ssh://` uses a text-specific key and must not be routed through the `.nm` file decoder.
- Nested decoded fields, ordered result display, copying, exporting and local history.
- Language support: es/en/pt-BR/ar with Arabic RTL, without translating decoded content.
- Signed APK release workflow with permanent keystore and verification of V1/V2/V3 signatures.

## Compatibility and evidence

**A registered extension is not proof of compatibility with every exporter build.** The 60-route checks and synthetic fixtures audit routing and selected cryptographic paths; true parity requires identical input bytes and matching output from the reference Python, Node.js, PHP or dedicated Telegram-text engine.

The v1.0.5 PR reported **130 Android API 35 instrumented tests passed**. Recent improvements cover Dark Tunnel `.dark` / text, `nm-ssh://` and `ar-ssh://` and repeated imports. Some real-world failures still lack a reproducing sample; the **NO-GO stable gate** for v1.0.5 is retained in [release readiness](../../release/android-readiness.json). Details: [real-sample triage](REAL_DECODER_PARITY_TRIAGE.md), [release runbook](RELEASE_RUNBOOK.md).

## Documentation index

| Area | Reference |
|---|---|
| Native architecture and offline boundaries | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Product requirements and historical scope | [PRODUCT_REQUIREMENTS.md](PRODUCT_REQUIREMENTS.md) |
| UI design and editable SVG mockups (not live screenshots) | [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md) |
| Localization and output fidelity | [LOCALIZATION.md](LOCALIZATION.md) |
| Format registry and compatibility matrix | [DECODER_MATRIX.md](DECODER_MATRIX.md) |
| Original decoder source audit | [DECODER_AUDIT.md](DECODER_AUDIT.md) |
| Synthetic fixture policy and reports | [A2_FIXTURE_POLICY.md](A2_FIXTURE_POLICY.md), [A23_GOLDEN_CORPUS.md](A23_GOLDEN_CORPUS.md), [A24_PARITY_SECURITY.md](A24_PARITY_SECURITY.md) |
| Real file triage | [REAL_DECODER_PARITY_TRIAGE.md](REAL_DECODER_PARITY_TRIAGE.md) |
| Security, QA and release approvals | [SECURITY_AND_QA.md](SECURITY_AND_QA.md), [RELEASE_RUNBOOK.md](RELEASE_RUNBOOK.md) |
| Project history | [ROADMAP.md](ROADMAP.md), [ADR.md](ADR.md), [HANDOFF.md](HANDOFF.md) |
| Developer reports | [USER_MANUAL_VALIDATION_2026-10-09.md](USER_MANUAL_VALIDATION_2026-10-09.md) |

![UI design reference for Android home (not an app screenshot)](design/home-dark.svg)
![UI design reference for Android results (not an app screenshot)](design/result-dark.svg)

## Verification

Run project-level validation from the root:

~~~bash
python validate_project.py
python docs/android/validate_docs.py
python -m unittest discover -s tests -v
~~~

GitHub's [Validate SP-DECODE workflow](https://github.com/Gh0stDeveloper/SP-DECODE/actions/workflows/validate.yml) includes Android API 35 instrumented tests. These are useful engineering signals, **not** automatic approval of unknown exporter variants. Report sanitized issues via [CONTRIBUTING.md](../../CONTRIBUTING.md) or security vulnerabilities via [SECURITY.md](../../SECURITY.md).

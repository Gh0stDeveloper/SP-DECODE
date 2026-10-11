# SP-DECODE Android v1.1.1 — Production release decision

**Release target:** `versionName 1.1.1`, `versionCode 22`, application ID `com.ghostdeveloper.spdecode`. The owner explicitly requests public stable distribution of this specific version on 2026-10-10, conditional on GitHub CI and permanent production-key signing checks.

## Changes since public v1.1.0

- Preserve merged PR #69: TLS Tunnel 8.5.0 with six AES-GCM key profiles in Python and Android; keep legacy TLS decoding compatible.
- Preserve HTTP Injector `.ehi` recursive processing for nested/encoded fields without discarding undecodable values. Synthetic regressions do **not** prove full recovery of every rare `.ehi` exporter variant with concatenated names.
- Preserve validated Dark Tunnel Base64-only text detection; ordinary Base64 must not be misidentified as Dark Tunnel.
- Center the five-step multilingual first-run guide inside the available content viewport instead of positioning it below content above the navigation bar. Allow scrolling within the guide on compact devices. Keep Next, Skip, automatic tab navigation and restart from Settings.
- Update localized What's New information in English, Spanish, Brazilian Portuguese and Arabic to v1.1.1.
- Keep encrypted offline history, 239 source-mapped routes, no INTERNET permission, R8 production optimization and existing integrity checks.

## Production conditions

1. The exact `main` SHA must pass `Validate SP-DECODE`: Python tests, Phase H release audit and Android API 35 instrumentation, including version-22 and centered-guide checks.
2. Build `assembleRelease` from that SHA with the permanent production keystore stored in GitHub Secrets. Never substitute a debug, unsigned or temporary-key APK.
3. Verify V1/V2/V3 APK signing, prior release certificate parity, manifest application ID/versionName/**versionCode**, 16 KiB zip alignment, and SHA-256 artifacts. Public stable Release creation is permitted only if `android_release_gate.py` approves `1.1.1` under the owner's specific acceptance.
4. Keep earlier release tags intact; never replace the v1.1.0 APK with a different binary.

## Evidence and limitations

- The previous PR #69 validations and subsequent signed candidate covered the original engine changes, but the new v1.1.1 **must pass fresh validation and signing on its own exact commit**. This document does not pre-certify the final binary.
- A genuine problematic `.ehi` configuration with concatenated/encoded names is still necessary to verify full decoding in that edge case. Current-exporter vendor corpus, physical ARM64 and 16 KiB device installations/upgrades, accessibility/performance and signed-install evidence remain pending and must not be relabeled verified.
- **OWNER-GO** means version-scoped authorization to distribute a stable APK despite the documented QA gaps; it does not mean independent format/device/security certification. No approval is inherited by later versions.

# Server VPN / NUR TUNNEL VPN (.solid)

Scope: PR #84, branch `fix/nur-url-private-hc-text-v1.1.4`, planned app version 1.1.4 (versionCode 25).

## Distinct integrations

| Function | Android | Telegram bot |
|---|---|---|
| NUR TUNNEL VPN 1.0.8.8 exported profile (`.solid`) | Offline file-import decoder | `decoders/Python/nur_tunnel_solid.py` registered as `.solid` |
| NUR TUNNEL VPN encrypted server catalog | New **Server VPN** tab, **NUR TUNNEL VPN** entry, explicit HTTPS download and authenticated decode | **Not registered**; no URL fetching in the bot |

Both formats use the same native KDF/envelope, **not the same document schema**. A profile must contain string `Name` and `TunnelType`; a catalog must contain string `Version` and arrays of objects `Servers` and `Networks`. The other document type is rejected, and authentication failure yields **no partial output**.

## Cryptographic parity

Based on the user-provided and already real-file-tested `NUR_TUNNEL_SOLID.py` and `NUR_TUNNEL_SERVERS.py`:

- Legacy export carrier: total length congruent to 1 mod 4; remove inserted byte at zero-based index 3, then Base64 decode. Secret selection is **not** brute force.
- Internal carrier: total length congruent to 0 mod 4, direct Base64 decode.
- `salt = raw[:16]`, `nonce = raw[16:28]`, remaining ciphertext and 16-byte GCM tag.
- Argon2id version 19: iterations=3, memory=8192 KiB, parallelism=1, key length=32.
- AES-256-GCM 12-byte nonce, with the exact 16-byte salt as AAD.
- Known nested encrypted fields are recursively authenticated, preserving nested JSON strings as strings; otherwise plain fields are not modified.
- Boundaries: 16 MiB encrypted input, at most 100,000 visited JSON values, at most 64 levels.

The already-public, legacy app-wide cipher material is obtained from the existing encrypted build asset vault, not stored as literal NUR secrets in Kotlin classes. This does **not** guarantee irrecoverability from an offline APK.

## Android UX and privacy

- The fifth bottom tab is **Server VPN**, alongside Home, History, Formats and Settings, using the app's existing black/charcoal visual system.
- Initial supported catalog application: **NUR TUNNEL VPN**. Its logo surface currently has a generic placeholder icon until the user provides the actual artwork.
- The catalog URL is not displayed in the Android interface. The endpoint is a source asset registered in the existing AES-GCM vault and is packaged as authenticated ciphertext; the app validates it and resolves it only after the user taps **Decode servers**.
- Network access occurs **only on tapping Decode servers**. The downloader requires HTTPS, disallows redirects, sets connect/read timeouts, and limits the response to 16 MiB. No automatic polling or silent fetching is added.
- This protects the packaged asset against casual plaintext extraction, not a determined APK reverse engineer: the runtime unwrap key is recoverable from app code. It should not be described as absolute URL secrecy.
- Authenticated decoded catalog is displayed using the existing **Home** JSON/result viewer and saved in encrypted local history. Download/authentication failures do not create records.
- `.solid` is visible in Formats and routed through the normal offline import flow (including batch imports).
- The original frozen 239-format Android catalog remains unchanged. The additive `.solid` route is counted and tested separately to preserve its golden audit contract.
- The HTTP Custom password/HWID secure dialog keeps the existing authentication/KDF flow and forces entered password/HWID text to white for contrast.

## Validation

- `tests/test_nur_tunnel_solid.py`: fixed independent valid export profile, nested value, corrupted tag and wrong document rejection.
- `NurTunnelInstrumentedTest`: independent Python-produced AES-GCM/Argon2id vectors for both envelopes, schema separation and inner authenticated field.
- Existing 239-format catalog invariants and unit tests remain asserted.
- Must pass `Validate SP-DECODE`, Android API 35 instrumentation, debug APK, R8 release smoke and security audit on **the final head commit** before any merge or production release.
- Real Android device and server endpoint availability tests remain pending. No private sample or real credential was committed.

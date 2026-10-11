# Android parity: TLS Tunnel 8.5.0, nested HTTP Injector and bare Base64 Dark Tunnel

## TLS Tunnel 8.5.0

The separate research branch analysis/tls-tunnel-850 identified six AES-256-GCM configuration-key profiles for TLS Tunnel 8.5.0. It authenticated one private real TLS export with profile 1; the old key is profile 6. The private sample is not in the repository.

Python decoders/Python/TLS.py and Android TlsReferencePort.kt now share the verified six-profile container algorithm. A failed GCM authentication tag never yields plaintext. Five modern profiles keep all previously unknown fields in the structured _tls.fields array as index, raw and decoded value; they do not mislabel modern booleans as old DNS settings. The historic key retains the older field names. Unknown or invalid inner Base64 remains untouched.

The Android parity corpus contains six independently generated authenticated TLS synthetic profiles and compares byte-for-byte with the original Python outputs. The private real export has not been loaded on the Android device.

## HTTP Injector EHI

The known custom Base64/hex/XOR field decoding in Python and Android previously covered only root JSON string values. It is now applied recursively to nested dictionaries and arrays, with 32-level bounds, while retaining unknown text and all typed data. No unrelated key guessing, loss of failed strings or fake plaintext is accepted.

The user's pasted example shows concatenated keys and apparently corrupted field text. The original failing EHI binary was not supplied, so it is not possible to prove whether those particular fields are encrypted or exporter-created junk. Those exact values are not certified repaired. Real-file diagnosis requires the source .ehi.

## Base64 Dark Tunnel text

DarkPort already decoded raw Base64 JSON envelopes when given a .dark file. The text detector now recognizes an unprefixed or whitespace-wrapped Base64 token as Dark Tunnel only if strict UTF-8 JSON contains an encryptedLockedConfig field. It reuses exactly the same file decoder. The optional prefixes darkb64:// and darkbase64:// also work, alongside dtunnel://, dt:// and dark://. Unrelated Base64 JSON is not guessed as Dark Tunnel; NetMod keeps its own independent route.

## QA and release

The CI validates Python TLS fixtures and EHI nested regression, Android API35 six TLS profiles, tampering, file and text routes, raw Base64 Dark input and negative cases. Existing EHI golden fixtures now contain nested custom-XOR scalar values with exact Python Android parity.

No Internet permission, advertising SDK, device secret, signing key or VPN protocol network request is added. Existing release v1.1.0 is immutable: this branch is source work until an independently versioned release is explicitly approved and signed with the permanent keystore. R8/debug release checks remain unchanged.

# SP-DECODE bot — Ultra / Sandok (42 extension aliases)

This is the **Telegram bot's Python-only** implementation. Android is deliberately
unchanged; do not advertise Android support from this document.

## Source and provenance

- Source: user-authorized standalone `66.py`, original `ULTRA_EXTS`,
  `ULTRA_CONFIGS`, `EXT_TO_KEY`, `VPNS_SD`,
  `ultra_derive_key`, `decrypt_ultra_field`, and `decrypt_ultra_file`.
- Engine: `decoders/Python/ultra.py`, independent from bot administration and
  text protocol handlers.
- All 42 original suffixes, all 42 descriptions/key mappings, and all 19
  original key/memory profiles are retained in this single Python file.
- Source-specific URLs/user agents are metadata only. **Never contact a vendor
  endpoint to decrypt**; local input and local keys suffice.

## Exact 42 file extensions

```text
.aura .bcl .bee .btv .deep .ena .eta .fix .flynet .flynetvpn
.glory .great .lucky .marvs .md .mdp .mdproxy .mdvpn .mehaf
.mm .mmt .mtv2ray .mtv2raypro .nur .nurtunnel .ost .osv .ry
.t10 .t20 .tik .tiktunnel .tsm .tx .ulti .ultra .ultratunnel
.ut .vel .vlx .wolf .wolftunnel
```

41 suffixes are new to the Telegram bot. `.ost` already existed for
**OUSS Tunnel (legacy DES)**. `decoders/Python/ost.py` first tries that
original decoder, then the Ultra/Sandok engine only when the legacy XML
envelope was not recognized. Both variants keep the same `.ost` file name.

The 61 existing Android suffixes are recorded in `decoders.json`.
Only the Telegram bot's `spdecode.registry` overlays the 41 new suffixes
by reading the constants exported from `ultra.py`, resulting in **102
bot-recognized suffixes**. No Android catalog, app source or Android release
workflow needs changes for this phase.

## Decoding pipeline

1. Read the file as UTF-8 text, optionally remove an importer `://` scheme,
   strip whitespace, and enumerate the same finite Base64 correction candidates
   as the authorized source (including one-character repair).
2. Choose the extension's corresponding profile first, then the source's
   alternative profile order. Profiles retain the original first password,
   second-stage password and Argon2 memory value.
3. Decode the envelope as `salt[16] | nonce[12] | ciphertext | tag[16]`.
4. Derive the 32-byte AES key using **Argon2id**:
   `time_cost=3`, `parallelism=1`, `memory_cost=profile.mem`.
5. Authenticate/decrypt AES-256-GCM with `AAD=salt`; if unsuccessful,
   retry without AAD, as the source does.
6. Parse the resulting JSON object and optionally decrypt its known string
   fields (`BugDNS`, `CustomProxy`, `Payload`, `SNI`,
   `V2rayAddress`, `V2rayConfig`, `V2rayHost`, `V2raySNI`,
   `Info`, `Host`, `Server`).
7. The source omitted GCM tag verification on those inner fields; the port
   **checks the tag** and preserves an unverified inner field verbatim
   instead of presenting modified plaintext.
8. Emit complete UTF-8 JSON without truncating fields. A bad input yields
   a nonzero CLI exit code, and no fake successful configuration.

## Usage

Requirements are already present in root `requirements.txt`:
`pycryptodome==3.23.0`, `argon2-cffi==25.1.0`.

```sh
python decoders/Python/ultra.py ./example.ultra
python decoders/Python/ultra.py ./example.flynet
python decoders/Python/ost.py ./example.ost
python -m unittest tests.test_ultra_sandok -v
```

Telegram file documents are automatically dispatched through
`spdecode.handlers.documents` and `spdecode.registry`, with no new commands.

## Testing and limitations

Synthetic tests cover the 42 registrations, representative first/second
password combinations, multiple Argon2 memory settings, both outer AAD
variants, inner field tag authentication, and both `.ost` decoders.

**No authenticated test export from every actual third-party application is
included in this commit.** A registered alias does not certify that newer
vendor application releases still use this historical key format. Real export
comparisons are separate from the bot-only source integration.

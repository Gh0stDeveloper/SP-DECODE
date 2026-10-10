# RENZ / 7NET — bot Python handoff (sin Android)

## Provenance and scope

- Source: user-provided authorized `66.py` (RENZ constants, profile dictionary,
  custom XXTEA/AES paths, Threefish-256, nested fields, and generic type 0–3).
- Implementation: `decoders/Python/renz.py`, a **single Python script** for all
  supported file variants and shareable text schemes.
- Integration: `spdecode.registry` registers file suffixes; the existing
  `spdecode.handlers.text_protocols` routes schemes to `decode_text`.
- No extra bot commands, HTTP requests or JavaScript/PHP code. Original
  `RENZ_KEYS` URL entries are reference metadata and are **not requested**.
- No files in `android/` or `decoders.json` changed. The Android catalog stays
  at 61 suffixes; the bot registry grows from 102 to 118.

## 16 RENZ file extensions

```text
.7net .actunnelvpn .actun .xhypher .tcx .bshield .osp
.safetunnel .mhrtunnel .letsvpngo .aloplusvpn .cranetunnel
.vipsnipherpro .deshtunnelvpn .hamotunnelplus .gcpvpn
```

`.osp` maps to the source's `7net` key material; `.actun` is
mapped to `actunnelvpn`, because the source's `RENZ_KEYS` has no
`actun` entry. The source's standalone extension mapping mentions
`.vlx` but provides no `RENZ_KEYS["vlx"]` key material; moreover,
`.vlx` already belongs to Ultra/Sandok. Therefore **do not register
`.vlx` in RENZ and do not claim it decodes using RENZ**.

`.izph` and its `izph://` protocols have a distinct dedicated engine
in the original source and belong to the next independent phase.

## 23 text protocols

```text
7net:// 7netvpn://  tcx://  tcxtunnelplus://
ihome://  ihomevpn://  xhypher://  xhyphertunnelpro://
osp://  osptunnel://  actunnelvpn://  actunnel://
bshieldnet://  bshield://  safetunnel://  mhrtunnel://
letsvpngo://  aloplusvpn://  cranetunnel://
vipsnipherpro://  deshtunnelvpn://  hamotunnelplus://
gcpvpn://
```

The text handler accepts case-insensitive prefixes at the start of a
message, uses the same authenticated chat authorization as the existing
text handlers, and prints full JSON in split Telegram messages.
File input runs through `spdecode.handlers.documents`, with no
special Telegram command.

## Source-derived decode algorithm

**Standalone per-app route** (`RENZ_KEYS`):

1. Strip the recognized scheme (if any), Base64-decode the input.
2. For the normal RENZ profiles: `AES-128-CBC` with
   `SHA256(KEY_SEED)[:16]` and app-specific fixed `IV`, then custom
   XXTEA and optionally subtract 2 per byte (depending on profile).
3. `tcxtunnel` and `trptunnel` use their own XXTEA constants, keys and
   ordering of XXTEA followed by AES-CBC.
4. Parse the outer JSON and visit nested objects/lists. For hostname/path
   fields, try `HKDF-SHA256 → Threefish-256 → AES-CBC` with the
   profile-specific tweak schedule. For username/password fields, use
   `PBKDF2-HMAC-SHA256 → XXTEA → AES-CBC`. Other encrypted strings
   try the source's main and special routes.
5. Keep the **complete decrypted fields**, including original IP addresses:
   the original `66.py` replaced one particular address with unrelated
   text when formatting fields; that presentation rewrite is removed to
   avoid altering actual configuration values.
6. The legacy generic 7NET type 0/1/2/3 route remains as a fallback
   when the profile-specific outer route fails. The source's optional
   PySkein requirement for Type 1 is replaced by its already-bundled
   pure-Python Threefish-256 implementation.

**Important:** AES-CBC / XXTEA / Threefish formats are not authenticated
ciphertexts. JSON structure plus valid padding provides only a practical
format check, **not a cryptographic integrity guarantee**. Do not label
these files as authenticated or tamper-proof.

## Running and tests

The project already requires `pycryptodome`. Additional dependencies
are not needed for the pure-Python Threefish variant.

```sh
python decoders/Python/renz.py /path/to/example.7net
python decoders/Python/renz.py /path/to/example.tcx
python decoders/Python/renz.py /path/to/example.bshield
python -m unittest tests.test_renz_family -v
```

The test suite synthesizes independent positive encrypt→decrypt vectors
for all 16 extension aliases and all 23 text schemes, checks the
legacy CBC/XXTEA paths, the standalone Threefish inner decryptor, the
legacy typed AES fallback, the CLI, malformed inputs and Ultra .vlx
collision avoidance.

No real third-party exported profile is included yet. Passing
synthetic test vectors proves the source-compatible implementation
paths under test, **not compatibility with every new vendor version**.

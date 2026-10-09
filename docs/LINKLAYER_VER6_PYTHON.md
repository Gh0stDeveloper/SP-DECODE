# LinkLayer VPN VER6 — Python decoder

Verified on 2026-10-09 against the supplied real `.lnk` export and LinkLayer
VPN **3.11.2**, build **93**, package `com.newtoolsworks.linklayer`.

## Run

```sh
python -m pip install pycryptodome==3.23.0
python decoders/Python/linklayer.py "configuration.lnk"
```

Python 3.9+; the repository already declares this dependency. No Android runtime,
APK, emulator, network access, external key or password is needed for the supplied
export. `decode(bytes)` returns a dictionary. The CLI emits complete, indented
UTF-8 JSON to stdout; failures use stderr and exit code 2. Omitted Go fields are
restored to their original zero values: false, 0 and empty strings.

## Evidence from the supplied application

`Models.ConfigManager.ImportConfig(content)` calls
`androidclient.Androidclient.importConfigContent(filesDir, content)`, then
`ForceReloadLinkLayerConfig()` calls `Androidclient.loadConfig(filesDir)`.
Native `ImportConfigContent` writes the bytes; the cryptographic processing occurs
when the configuration is reloaded.

Relevant ARM64 virtual addresses in `libgojni.so`:

| Function | Address | Observed responsibility |
| --- | --- | --- |
| `androidclient.ImportConfigContent` | `0x149cba0` | Write imported bytes |
| `configuration.LoadNativeConfig` | `0x11e93b0` | Read file, call `d`, decode Go gob |
| `configuration.d` | `0x11e9dd0` | Decrypt container layers |
| `configuration.e` | `0x11eb000` | Reverse flow used by exports |
| `kcp-go.decrypt` | `0xa4fc40` | Full-block CFB, including partial final blocks |

The file's `VER6` branch is confirmed by the four string constants used by
`configuration.d`, not inferred from another application.

Verified processing order:

1. Remove `VER6`; take the final 8 bytes as the Blowfish key; Blowfish-CFB64.
2. Remove 72 bytes of key material; form a 32-byte AES key from its first
   16 bytes and reversed final 16 bytes; AES-CFB128.
3. Use the first 32 bytes as a Salsa20 key, discard the final 32 bytes, reverse
   the middle packet, preserve its 8-byte nonce and decrypt the remainder.
4. Read the big-endian segment length after the nonce. Three equal segments
   follow; decrypt the middle segment with CAST5-CFB64 using its final 16-byte key.
5. Remove the ordering flag; apply the half/reversal operation when it is 1.
6. Use the next 16 bytes as the PBKDF2 password, with SHA-1, the application salt,
   **32 iterations and a 1500-byte result**. XOR only the first 1500 available
   bytes; the application does not repeat this mask over the entire buffer.
7. Take the final 32-byte AES key and swap its first and last bytes. Restore
   the encrypted payload from the preceding 10 bytes plus the reversed remainder;
   AES-CFB128 yields Go gob `NativeConfig`.
8. Parse the bounded NativeConfig struct schema, including every zero value.

All CFB stages use the fixed KCP IV found in the supplied library; Salsa20 uses
the packet nonce. Constants are in the standalone script. No credentials from
the real configuration are embedded in the source or tests.

## Validation

- Real encrypted input: **7270 bytes**, SHA-256
  `adf51e275152998b0743c8114a31794077b0cbf34a2bbe1389998b87c1a0799f`.
- Decrypted Go gob: **2305 bytes**, SHA-256
  `1951c999d66b23abbdd082110be1832b3a593ffd5f2fd85a42a9c971b89a74b5`.
- All Go gob messages consumed exactly: **25 root fields / 60 leaf fields**.
- **10 unittest tests passed**, including the real export, both ordering flags,
  partial cipher blocks, Unicode, strings exceeding the XOR mask, invalid headers,
  corruption, truncation, unknown schema, missing dependency and CLI behavior.
- Separately tested **every one of the 7270 truncated prefixes**: none accepted.
- Executed the real file through the unchanged repository `spdecode.executor`:
  exit 0, empty stderr, JSON identical to direct decoding.

```sh
python -m unittest discover -s tests -p test_linklayer_ver6.py -v
# Optional private real input; never commit this configuration:
SPDECODE_LINKLAYER_REAL_FILE=/absolute/path/sample.lnk \
  python -m unittest discover -s tests -p test_linklayer_ver6.py -v
```

The public suite skips the private real-input test when its environment variable
is absent. Public test exports contain synthetic data only.

## Scope and limits

This delivers the standalone Python method for the supplied VER6 format and
NativeConfig schema. No legacy decoders, registry entries, Android source,
versions, signing or workflow files are changed. Registering `.lnk` and Android
integration are deferred. The branch can be reviewed without opening a PR that
would trigger the repository's Android validation job.

No live emulator import was performed; validation uses the extracted native
import/reload path, exact Go gob decoding, the real file and the bot subprocess.
Other versions, schemas and password-wrapped outer exports are not verified and
are rejected rather than guessed.

The original format has **no MAC or authentication tag**. Structural validation
rejects malformed data but cannot establish authenticity or detect every change
to ignored padding or valid field values. The suite explicitly checks this limit.
Input is limited to 8 MiB, individual strings to 1 MiB, and type definitions to
16 bounded structs; no executable deserialization is used.

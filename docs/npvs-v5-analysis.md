# NPV Tunnel `.npvs` v5 import path

Analysis target: NPV Tunnel 124.0.37 (`arm64-v8a`) and one local export.
No APK, native library, key material, or configuration is stored in this repo.
Offsets below are relative to the extracted shared libraries of this version.

## Compact envelope

The outer frame is `NPVS`, version `5`, a big-endian 32-bit header length,
the raw header, a 12-byte nonce, a big-endian 32-bit body length, the body,
and a 64-byte signature. The sample has a 345-byte header and 5009-byte
body beginning with `NPF\x01`. These lengths are only framing; they do not
authenticate or reveal the document.

The compact header parser in `libgojni.so` (`parseCompactHeader`, around
`0x1f1f090`) consumes the following fields in this appKey export:

| Header offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 1 | compact codec `1` |
| 1 | 16 | configuration identifier |
| 17 | 33 | creator public key |
| 50 | 1 | recipient selector `2` (appKey) |
| 51 | 2 | optional recipient data length, big endian; `0` here |
| 53 | 2 | appKey generation, big endian; `2` here |
| 55 | 16 | appKey salt |
| 71 | 60 | wrapped 32-byte document key: nonce, ciphertext and tag |
| 131 | 4 | encrypted metadata length, big endian; `210` here |
| 135 | 210 | encrypted metadata |

The parser must account for optional recipient data before the appKey
record; the offsets shown are for the provided export. Other recipient
selectors use other layouts and require separate analysis.

## Import call chain

`OpenCompactEnvelopeForImport` calls `OpenCompactEnvelope`. For an appKey
record the route reaches `openSourceAppKey` (`libgojni.so` near `0x1f4bc90`),
which decodes the salt, wrapped key and configuration identifier. It calls
`appKeyGen2Kdk` (near `0x1f1e270`) with **two 16-byte inputs**. That delegates
to `gen2KdkViaLib`, dynamically resolves `libnpvtunnel.so`, and calls its
`npvtunnel_rt_load` export (`0x2f8c`). The native code reads the APK asset
`assets/rt.dat`; the wrapped key is opened with ChaCha20-Poly1305 using the
salt as associated data (`openSourceWrappedKey`, near `0x1f4c040`).
The document key then reaches `openCompactMetadata` and
`core/fieldconfig.OpenDocument` to open the `NPF1` body. Metadata requires
the document key as well. `InspectCompactEnvelope` only exposes header
information and does not open either encrypted section.

The previous Python script's white-box tables and generation-1 derivation
were tested against this export's salt and wrapped key. Both table variants
fail ChaCha20-Poly1305 authentication. The generation-2 native routine uses
a different table set: its loader reads `rt.dat` and selects 14 rounds.
There is no evidence that the exporter's optional usage password is an
input to `appKeyGen2Kdk` or the import call chain.

## Remaining work

Port or instrument `npvtunnel_rt_load` plus its `rt.dat` table loading to
derive the generation-2 app key from the two header inputs. Verify the
60-byte key wrap with ChaCha20-Poly1305. Then implement the compact
metadata and `NPF1` document opening path, and compare the result with a
controlled import in NPV Tunnel. Finally verify the envelope signature.
The current `NPVS.py` is a bounded parser; it does **not** decrypt the
provided file or verify its signature.

#!/usr/bin/env python3
"""Recover inspection DEX from the exact TLS Tunnel 8.5.0 APK.

Research only; the standalone TLS.py decoder does not depend on these tools.
Run with --work-dir pointing to an empty analysis directory. No Android/emulator
installation, APK rebuild, or execution of recovered application code is used.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
import os
from pathlib import Path
import runpy
import shutil
import struct
import sys
import zipfile
import zlib

APK_SHA256 = '939586121d0fc2fe11e0e3d5b255ca41583537dcd57f21ca8a34f6298d7854c7'

def expand(prk, info, size):
    out = b''
    previous = b''
    for counter in range(1, (size + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), 'sha256')
        out += previous
    return out[:size]

def decompress(data):
    size = struct.unpack_from('<I', data)[0]
    name = ctypes.util.find_library('zstd')
    if not name:
        import zstandard
        output = zstandard.ZstdDecompressor().decompress(data[4:], max_output_size=size)
    else:
        library = ctypes.CDLL(name)
        function = library.ZSTD_decompress
        function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_size_t
        buf = ctypes.create_string_buffer(size)
        result = function(buf, size, data[4:], len(data) - 4)
        if result != size:
            raise ValueError('Zstandard length verification failed')
        output = buf.raw
    if len(output) != size:
        raise ValueError('Unexpected uncompressed length')
    return output

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', help='APK or ZIP containing exactly one APK')
    parser.add_argument('--work-dir', required=True)
    args = parser.parse_args()
    source = Path(args.apk).resolve()
    payload = source.read_bytes()
    if source.suffix.lower() == '.zip':
        with zipfile.ZipFile(source) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith('.apk')]
            if len(names) != 1:
                raise ValueError('ZIP must contain exactly one APK')
            payload = archive.read(names[0])
    if hashlib.sha256(payload).hexdigest() != APK_SHA256:
        raise ValueError('This recovery harness is specific to the documented 8.5.0 APK; review offsets for other builds')
    work = Path(args.work_dir).resolve()
    analysis = work / 'analysis_tls'
    analysis.mkdir(parents=True, exist_ok=True)
    support = Path(__file__).resolve().parent
    for name in ('unpack_native.py', 'open_assets_metadata.py', 'open_java_mix.py', 'open_segments.py', 'chacha8.py'):
        shutil.copyfile(support / name, analysis / name)
    (analysis / 'base.apk').write_bytes(payload)
    with zipfile.ZipFile(analysis / 'base.apk') as archive:
        (analysis / 'libdexprotector.so').write_bytes(archive.read('lib/arm64-v8a/libdexprotector.so'))
        (analysis / 'classes.dex').write_bytes(archive.read('classes.dex'))
        (analysis / 'assets.dat').write_bytes(archive.read('assets/assets.dat'))
    os.chdir(work)
    sys.path.insert(0, str(analysis))
    runpy.run_path(str(analysis / 'open_assets_metadata.py'))
    metadata = (analysis / 'assets_metadata.bin').read_bytes()
    assets = (analysis / 'assets.dat').read_bytes()
    pointer, offset = 1, 0
    for unused in range(metadata[0]):
        kind = metadata[pointer]
        pointer += 1
        size, shift = 0, 0
        while True:
            byte = metadata[pointer]
            pointer += 1
            size |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                break
        (analysis / f'segment_{kind}.bin').write_bytes(assets[offset:offset + size])
        offset += size
    from Crypto.Cipher import ChaCha20_Poly1305
    root = (analysis / 'assets_matching_prk.bin').read_bytes()
    key = expand(root, struct.pack('<Q', 0x3045c9c1c2460b68), 44)
    data = (analysis / 'segment_9.bin').read_bytes()
    dex = ChaCha20_Poly1305.new(key=key[:32], nonce=key[32:]).decrypt_and_verify(data[:-16], data[-16:])
    (analysis / 'segment_9.dex').write_bytes(dex)
    runpy.run_path(str(analysis / 'open_java_mix.py'))
    runpy.run_path(str(analysis / 'open_segments.py'))
    data = decompress((analysis / 'segment_5_plain.bin').read_bytes())
    size = struct.unpack_from('<I', data, 32)[0]
    dex = bytearray(data[:size])
    if not dex.startswith(b'dex\n037\0'):
        raise ValueError('Recovered data is not the expected DEX')
    # Protector appends extra tables. Repair header checksum in an inspection
    # copy only so androguard/jadx can parse it; do not build/install this DEX.
    struct.pack_into('<I', dex, 8, zlib.adler32(dex[12:]) & 0xffffffff)
    target = analysis / 'real_classes_parse.dex'
    target.write_bytes(dex)
    print('Recovered inspection DEX:', target)

if __name__ == '__main__':
    main()

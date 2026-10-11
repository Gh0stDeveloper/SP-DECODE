"""Independent cipher fixtures and optional private real-file regression.

Run: python -m unittest discover -s tests -p test_httpinjector_diagnostics.py
EHI_REAL_FILE enables the user sample without committing its bytes or secrets.
"""
import base64
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad
from argon2.low_level import hash_secret_raw, Type
from decoders.Python import HTTPINJECTOR as engine

C = engine.EHIConstants


def field(value, salt='EVZJNI'):
    encoded = bytes(b ^ ord(salt[i % len(salt)]) for i, b in enumerate(value.encode())).hex()
    translate = str.maketrans(C.STD_ALPHABET, C.CUSTOM_ALPHABET)
    return base64.b64encode(encoded.encode()).decode().translate(translate)[::-1]


def xxtea_encrypt(data):
    data += bytes((-len(data)) % 4)
    v = list(struct.unpack('<%dI' % (len(data) // 4), data))
    v.append(len(data.rstrip(b'\0')))
    k = struct.unpack('<4I', C.EOO_MASTER_KEY.ljust(16, b'\0')[:16])
    total = 0
    z = v[-1]
    for _ in range(6 + 52 // len(v)):
        total = (total + 0x9e3779b9) & 0xffffffff
        e = (total >> 2) & 3
        for p in range(len(v)):
            y = v[(p + 1) % len(v)]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
            v[p] = (v[p] + mx) & 0xffffffff
            z = v[p]
    return struct.pack('<%dI' % len(v), *v)


def wrap(obj, iv):
    raw = xxtea_encrypt(json.dumps(obj, separators=(',', ':')).encode())
    inner_iv = bytes(range(16))
    raw = AES.new(C.L2_KEY_STATIC, AES.MODE_CBC, inner_iv).encrypt(pad(raw, 16))
    text = base64.b64encode(inner_iv) + b':fixture:' + base64.b64encode(raw)
    payload = AES.new(C.L1_KEY, AES.MODE_CBC, iv).encrypt(pad(text, 16))
    def utf(v): return struct.pack('>H', len(v)) + v
    return utf(b'ehi') + bytes(8) + utf(b'6.5.0') + bytes(8) + struct.pack('>I', len(payload)) + bytes(8) + payload


def fixture(iv, standard=False, tamper=False, cost=1):
    plain = {
        'configSalt': 'EVZJNI', 'host': field('example.invalid'),
        'literal': 'plain:unchanged', 'opaque': '0123456789abcdef',
        'nested': {'entries': [field('nested.invalid'), False, 443, None]},
        'rawJson': '{"literal":"preserve exact string"}',
        'payload': field('GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\nbody'),
        'empty': '', 'final': 'LAST_FIELD',
    }
    expected = {**plain, 'host': 'example.invalid',
                'nested': {'entries': ['nested.invalid', False, 443, None]},
                'payload': 'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\nbody'}
    if not standard:
        return wrap(plain, iv), expected
    envelope = {'configSalt': 'EVZJNI', 'configIdentifier': 'synthetic',
                'configTimestamp': 1, 'configExpiryTimestamp': 0}
    header = b'\x01' + struct.pack('<II', cost, 32) + b'\x01' + bytes(range(16))
    nonce = bytes(range(24))
    if cost > 16:
        envelope['configData'] = field(base64.b64encode(header + nonce + bytes(16)).decode())
    else:
        key = hash_secret_raw(engine.EHIDecryptor._generate_master_key(envelope),
                              header[10:], cost, 32, 1, 32, Type.ID)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(plain).encode())
        if tamper: tag = bytes([tag[0] ^ 1]) + tag[1:]
        envelope['configData'] = field(base64.b64encode(header + nonce + ciphertext + tag).decode())
    return wrap(envelope, iv), expected


class EhiDiagnosticsTest(unittest.TestCase):
    def test_six_existing_iv_profiles(self):
        for standard, ivs in [(False, C.BYPASS_IVS), (True, C.STANDARD_IVS)]:
            for i, iv in enumerate(ivs):
                with self.subTest(standard=standard, profile=i + 1):
                    data, expected = fixture(iv, standard)
                    audit = {}
                    self.assertEqual(engine.decode_ehi(data, audit), expected)
                    self.assertEqual(audit['authenticated'], standard)
                    self.assertIn('/host', audit['transformed_fields'])
                    self.assertIn('/opaque', audit['untransformed_strings'])
                    self.assertEqual(audit['top_level_fields'], len(expected))

    def test_fallback_xchacha_authenticates(self):
        data, expected = fixture(C.STANDARD_IVS[1], True)
        with patch.object(engine, 'PYCRYPTODOME_AVAILABLE', False):
            self.assertEqual(engine.decode_ehi(data), expected)

    def test_tampered_tag_rejected_with_both_backends(self):
        data, _ = fixture(C.STANDARD_IVS[1], True, tamper=True)
        for backend in (True, False):
            with patch.object(engine, 'PYCRYPTODOME_AVAILABLE', backend):
                self.assertIsNone(engine.decode_ehi(data))

    def test_bypass_does_not_require_argon2(self):
        data, expected = fixture(C.BYPASS_IVS[0])
        with patch.object(engine, 'ARGON2_AVAILABLE', False):
            self.assertEqual(engine.decode_ehi(data), expected)
            data, _ = fixture(C.STANDARD_IVS[0], True)
            self.assertIsNone(engine.decode_ehi(data))

    def test_resource_cost_rejected_before_derivation(self):
        data, _ = fixture(C.STANDARD_IVS[0], True, cost=0xffffffff)
        with patch.object(engine, 'hash_secret_raw') as kdf:
            self.assertIsNone(engine.decode_ehi(data))
            kdf.assert_not_called()

    def test_invalid_headers_and_truncation(self):
        data, _ = fixture(C.BYPASS_IVS[0])
        for cut in (0, 2, 5, 21, len(data)-1):
            self.assertIsNone(engine.decode_ehi(data[:cut]))
        self.assertIsNone(engine.decode_ehi(data[:2] + b'bad' + data[5:]))

    def test_preservation_is_not_claimed_as_decryption(self):
        data, expected = fixture(C.BYPASS_IVS[0])
        audit = {}
        got = engine.decode_ehi(data, audit)
        self.assertEqual(got['opaque'], expected['opaque'])
        self.assertEqual(got['rawJson'], expected['rawJson'])
        self.assertIn('/nested/entries/0', audit['transformed_fields'])
        self.assertNotIn('example.invalid', json.dumps(audit))

    def test_json_cli_and_overwrite_guard(self):
        data, expected = fixture(C.BYPASS_IVS[0])
        with tempfile.TemporaryDirectory() as td:
            source, result, report = [Path(td)/p for p in ('test.ehi', 'result.json', 'audit.json')]
            source.write_bytes(data)
            cmd = [sys.executable, engine.__file__, str(source), '--json', '-o', str(result), '--audit', str(report)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, '')
            self.assertEqual(json.loads(result.read_text()), expected)
            self.assertIn('profile', json.loads(report.read_text()))
            proc = subprocess.run([sys.executable, engine.__file__, str(source), '-o', str(source)], capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(source.read_bytes(), data)

    @unittest.skipUnless(os.environ.get('EHI_REAL_FILE'), 'private real sample is intentionally excluded from Git')
    def test_private_650_sample(self):
        data = Path(os.environ['EHI_REAL_FILE']).read_bytes()
        audit = {}
        expected = engine.decode_ehi(data, audit)
        self.assertEqual(audit['input_sha256'], '54889797633ac07f192061659d821f8f7a456dd9f5101fdc7966fc66c1501444')
        self.assertEqual(audit['profile'], 'standard-2')
        self.assertTrue(audit['authenticated'])
        self.assertEqual(len(expected), 43)
        self.assertEqual(len(audit['transformed_fields']), 11)
        for key in ('host', 'dnsttNameserver', 'sniHostname', 'user', 'password', 'dnsttPublicKey', 'dnsttDnsResolverAddr'):
            self.assertIn('/' + key, audit['transformed_fields'])
        with patch.object(engine, 'PYCRYPTODOME_AVAILABLE', False):
            self.assertEqual(engine.decode_ehi(data), expected)


if __name__ == '__main__':
    unittest.main()

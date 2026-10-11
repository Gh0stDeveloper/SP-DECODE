import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from Crypto.Cipher import AES

ROOT = Path(__file__).parents[1]
DEFAULT_SOURCE = ROOT / 'TLS.py'
if not DEFAULT_SOURCE.exists():
    DEFAULT_SOURCE = ROOT / 'decoders' / 'Python' / 'TLS.py'
SOURCE = Path(os.environ.get('TLS_DECODER', DEFAULT_SOURCE))
spec = importlib.util.spec_from_file_location('tls_decoder', SOURCE)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)

def export_fixture(key, plaintext):
    # The layout in Ldd.t([B)[B, including the odd-sized ciphertext case.
    nonce = bytes(range(36))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    ct += tag
    half = len(ct) // 2
    raw = bytes(12) + ct[:half][::-1] + nonce[:18][::-1]
    raw += ct[half:][::-1] + nonce[18:][::-1] + bytes(84)
    return base64.b64encode(raw).decode().rstrip('=')[::-1] + ':::::'

class DecoderTests(unittest.TestCase):
    def test_all_six_apk_keys_and_original_constant(self):
        self.assertEqual(tls.CONFIG_KEYS[-1], tls.AES_KEY)
        for index, key in enumerate(tls.CONFIG_KEYS):
            with self.subTest(profile=index + 1):
                source = b'516:4:1:false:' + b':'.join([b''] * 8) + b'abc'
                text = export_fixture(key, source)
                result = tls.decrypt_tls_payload(text)
                self.assertEqual(result['_tls']['key_profile'], index + 1)
                self.assertEqual([x['raw'] for x in result['_tls']['fields']], source.decode().split(':'))

    def test_legacy_named_fields(self):
        parts = [''] * 28
        parts[0:4] = ['300', '1', '443', 'true']
        parts[4] = base64.b64encode('usuario-ñ'.encode()).decode()
        parts[20] = '2'
        result = tls.decrypt_tls_payload(export_fixture(tls.AES_KEY, ':'.join(parts).encode()))
        self.assertEqual(result['sshuser'], 'usuario-ñ')
        self.assertEqual(result['legacy_dns_mode'], 2)
        self.assertTrue(result['pserver'])

    def test_real_file_and_both_backends(self):
        path = os.environ.get('TLS_REAL_SAMPLE')
        if not path:
            self.skipTest('Set TLS_REAL_SAMPLE to the private attachment; it is not committed')
        data = Path(path).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), 'cc0b05dedbe3000f980b3ba25f3f5c171a0771e27786dddfb14302d87c6ccbd2')
        fast = tls.decrypt_tls_payload(data.decode())
        self.assertEqual(fast['_tls']['key_profile'], 1)
        self.assertEqual(fast['_tls']['field_count'], 58)
        self.assertEqual(fast['tlsvpnVersion'], 516)
        original = ':'.join(x['raw'] for x in fast['_tls']['fields']).encode()
        self.assertEqual(len(original), 16470)
        self.assertEqual(hashlib.sha256(original).hexdigest(), '880214f467d4252781636c0ec6ca8d6c15e44dd58d57a492880d287cc2d3a425')
        self.assertNotIn('nameserver', fast)  # field 23 is a boolean in this sample
        backend = tls._CryptoAES
        try:
            tls._CryptoAES = None
            self.assertEqual(tls.decrypt_tls_payload(data.decode()), fast)
        finally:
            tls._CryptoAES = backend

    def test_ciphertext_tampering_is_rejected(self):
        text = export_fixture(tls.CONFIG_KEYS[0], b'516:4:1:false')
        raw = bytearray(base64.b64decode(tls.fix_b64_padding(text.split(':')[0][::-1])))
        raw[12] ^= 1
        damaged = base64.b64encode(raw).decode()[::-1]
        with self.assertRaisesRegex(ValueError, 'autentica'):
            tls.decrypt_tls_payload(damaged)
        self.assertIsNone(tls.run(damaged.encode()))

    def test_malformed_input(self):
        for data in ('', '$invalid$', 'AAAA'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                tls.decrypt_tls_payload(data)
        self.assertIsNone(tls.run(b'\xff'))

    def test_unknown_values_are_preserved(self):
        self.assertEqual(tls.decode_internal_b64('@@unknown@@'), '@@unknown@@')
        parts = ['516'] + [''] * 57 + ['future-value']
        result = tls.decrypt_tls_payload(export_fixture(tls.CONFIG_KEYS[0], ':'.join(parts).encode()))
        self.assertEqual(result['_tls']['fields'][58]['raw'], 'future-value')

    def test_uri_and_cli_output(self):
        text = export_fixture(tls.CONFIG_KEYS[0], b'516:4:1:false')
        self.assertIsNotNone(tls.run(('tls://' + text).encode()))
        with tempfile.TemporaryDirectory() as directory:
            inp = Path(directory) / 'in.tls'
            output = Path(directory) / 'out.json'
            inp.write_text(text)
            process = subprocess.run([sys.executable, str(SOURCE), str(inp), '-o', str(output)], capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr.decode())
            self.assertTrue(json.loads(output.read_text())['_tls']['authenticated'])
            inp.write_text('bad')
            process = subprocess.run([sys.executable, str(SOURCE), str(inp)], capture_output=True)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(process.stdout, b'')

if __name__ == '__main__':
    unittest.main()

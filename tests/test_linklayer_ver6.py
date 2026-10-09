"""Public tests contain synthetic data only; a private real fixture is optional."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES, Blowfish, CAST, Salsa20

SCRIPT = Path(__file__).resolve().parents[1] / "decoders/Python/linklayer.py"
spec = importlib.util.spec_from_file_location("linklayer_decoder", SCRIPT)
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)


def _uint(number):
    if number < 128:
        return bytes([number])
    data = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return bytes([256 - len(data)]) + data


def _int(number):
    return _uint((~number << 1) | 1 if number < 0 else number << 1)


def _string(text):
    data = text.encode("utf-8")
    return _uint(len(data)) + data


def _zero(schema):
    return {name: _zero(kind) if isinstance(kind, dict)
            else False if kind == 1 else 0 if kind == 2 else ""
            for name, kind in schema.items()}


def _gob(value):
    # Encoding/gob wire records, with deliberately different ids from the real export.
    types = []

    def register(name, schema):
        type_id = 65 + len(types)
        record = [type_id, name, []]
        types.append(record)
        for field, kind in schema.items():
            record[2].append((field, register(field, kind) if isinstance(kind, dict) else kind))
        return type_id

    root_id = register("NativeConfig", decoder.SCHEMA)
    messages = []
    for type_id, name, fields in types:
        common = b"\x01" + _string(name) + b"\x01" + _int(type_id) + b"\x00"
        field_data = b"".join(b"\x01" + _string(n) + b"\x01" + _int(t) + b"\x00"
                              for n, t in fields)
        message = (_int(-type_id) + b"\x03\x01" + common + b"\x01"
                   + _uint(len(fields)) + field_data + b"\x00\x00")
        messages.append(_uint(len(message)) + message)

    def encode(type_id, item):
        if type_id == 1:
            return _uint(int(item))
        if type_id == 2:
            return _int(item)
        if type_id == 6:
            return _string(item)
        fields = types[type_id - 65][2]
        output = b""
        previous = -1
        for index, (name, kind) in enumerate(fields):
            field = item[name]
            if field == "" or field is False or field == 0:
                continue
            output += _uint(index - previous) + encode(kind, field)
            previous = index
        return output + b"\x00"

    message = _int(root_id) + encode(root_id, value)
    return b"".join(messages) + _uint(len(message)) + message


def _noise(label, length):
    return hashlib.shake_256(label.encode()).digest(length)


def _export(gob, flag=0):
    # Inverse of the layers observed in configuration.e, not a production exporter.
    def encrypt(cipher, key, data):
        size = cipher.block_size
        return cipher.new(key, cipher.MODE_CFB, iv=decoder.IV[:size],
                          segment_size=size * 8).encrypt(data)

    key = _noise("inner aes", 32)
    encrypted = encrypt(AES, key, gob)
    swapped = key[-1:] + key[1:-1] + key[:1]
    wrapped = bytearray(encrypted[10:][::-1] + encrypted[:10] + swapped)
    password = _noise("xor password", 16)
    mask = hashlib.pbkdf2_hmac("sha1", password, decoder.XOR_SALT, 32, 1500)
    for i in range(min(len(wrapped), len(mask))):
        wrapped[i] ^= mask[i]
    inner = password + wrapped
    if flag == 1:
        upper = len(inner) - len(inner) // 2
        inner = inner[upper:] + inner[:upper][::-1]
    cast_key = _noise("cast", 16)
    cast_block = encrypt(CAST, cast_key, bytes([flag]) + inner) + cast_key
    length = len(cast_block)
    nonce = _noise("nonce", 8)
    packet = (nonce + length.to_bytes(4, "big") + _noise("first padding", length)
              + cast_block + _noise("last padding", length))
    salsa_key = _noise("salsa", 32)
    packet = nonce + Salsa20.new(key=salsa_key, nonce=nonce).encrypt(packet[8:])
    salsa = salsa_key + packet[::-1] + _noise("salsa trailer", 32)
    outer_key = _noise("outer aes", 32)
    outer = (encrypt(AES, outer_key, salsa) + outer_key[:16]
             + _noise("outer padding", 40) + outer_key[16:][::-1])
    blowfish_key = _noise("blowfish", 8)
    return b"VER6" + encrypt(Blowfish, blowfish_key, outer) + blowfish_key


class LinkLayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = _zero(decoder.SCHEMA)
        cls.expected.update(Username="synthetic-user", Password="synthetic-password",
                            MessageConfig="Prueba 日本語 🇲🇽\nSecond line",
                            BlockAll=True, ExpireTimeConfig=-1, TypeAccount=1)
        cls.expected["SSH"].update(SSHServer="example.invalid:22",
                                   SSHPayload="GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        cls.gob = _gob(cls.expected)
        cls.fixture = _export(cls.gob)

    def test_synthetic_complete_fields_and_zero_values(self):
        self.assertEqual(decoder.decode(self.fixture), self.expected)
        self.assertEqual(decoder.decrypt_gob(self.fixture), self.gob)

    def test_both_cast_ordering_flags_and_partial_cipher_blocks(self):
        for flag in (0, 1):
            for length in (0, 1, 7, 8, 15, 16, 31, 32, 1500, 4096):
                with self.subTest(flag=flag, length=length):
                    expected = _zero(decoder.SCHEMA)
                    expected["MessageConfig"] = "x" * length
                    self.assertEqual(decoder.decode(_export(_gob(expected), flag)), expected)

    def test_unknown_header_and_version(self):
        for prefix in (b"VER5", b"VER7", b"VER8", b"OTHER"):
            with self.assertRaises(decoder.DecodeError):
                decoder.decode(prefix + self.fixture[4:])

    def test_truncation_at_container_boundaries(self):
        for size in (0, 1, 3, 4, 12, 75, 84, 128, 354, 355,
                     len(self.fixture) // 2, len(self.fixture) - 84,
                     len(self.fixture) - 1):
            with self.subTest(size=size), self.assertRaises(decoder.DecodeError):
                decoder.decode(self.fixture[:size])

    def test_random_ciphertext_and_damaged_ciphertext(self):
        for size in (355, 1024, 8192):
            with self.assertRaises(decoder.DecodeError):
                decoder.decode(b"VER6" + _noise("invalid", size))
        damaged = bytearray(self.fixture)
        damaged[4:68] = b"\x00" * 64
        with self.assertRaises(decoder.DecodeError):
            decoder.decode(bytes(damaged))

    def test_format_has_no_authentication_for_ignored_trailer(self):
        # Changing ignored random bytes can still decode; do not claim a MAC.
        changed = bytearray(self.fixture)
        changed[-56] ^= 1
        self.assertEqual(decoder.decode(bytes(changed)), self.expected)

    def test_gob_rejects_trailing_truncated_and_wrong_schema_data(self):
        for data in (b"", self.gob[:-1], self.gob + b"\x00",
                     self.gob.replace(b"NativeConfig", b"WrongXConfig", 1),
                     self.gob.replace(b"Username", b"UserXXXX", 1), b"\x80"):
            with self.subTest(size=len(data)), self.assertRaises(decoder.DecodeError):
                decoder.decode_gob(data)

    def test_input_size_and_missing_dependency(self):
        with patch.object(decoder, "MAX_INPUT_SIZE", 10):
            with self.assertRaises(decoder.DecodeError):
                decoder.decode(self.fixture)
        with patch.dict(sys.modules, {"Crypto.Cipher": None}):
            with self.assertRaises(decoder.DependencyError):
                decoder.decode(self.fixture)

    def test_cli_stdout_and_stderr_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.lnk"
            source.write_bytes(self.fixture)
            good = subprocess.run([sys.executable, str(SCRIPT), str(source)],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0)
            self.assertEqual(good.stderr, "")
            self.assertEqual(json.loads(good.stdout), self.expected)
            source.write_bytes(b"VER6")
            bad = subprocess.run([sys.executable, str(SCRIPT), str(source)],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, "")
            self.assertIn("truncated", bad.stderr)
            absent = subprocess.run([sys.executable, str(SCRIPT), str(source)+".missing"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(absent.returncode, 2)
            self.assertEqual(absent.stdout, "")

    @unittest.skipUnless(os.environ.get("SPDECODE_LINKLAYER_REAL_FILE"),
                         "private real fixture not supplied")
    def test_authorized_real_export(self):
        data = Path(os.environ["SPDECODE_LINKLAYER_REAL_FILE"]).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "adf51e275152998b0743c8114a31794077b0cbf34a2bbe1389998b87c1a0799f")
        gob = decoder.decrypt_gob(data)
        self.assertEqual(hashlib.sha256(gob).hexdigest(), REAL_GOB_SHA256)
        result = decoder.decode(data)
        self.assertEqual(len(result), 25)
        self.assertEqual(sum(len(v) if isinstance(v, dict) else 1 for v in result.values()), 60)
        self.assertTrue(result["Username"] and result["Password"] and result["SSH"]["SSHServer"])


# Frozen after decoding the authorized real export; no configuration content is included.
REAL_GOB_SHA256 = "1951c999d66b23abbdd082110be1832b3a593ffd5f2fd85a42a9c971b89a74b5"

if __name__ == "__main__":
    unittest.main()

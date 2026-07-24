from __future__ import annotations

import base64
import gzip
import json
import unittest
import zlib

from decoders.Python.sockip import (
    UnsupportedSocksIPVersion,
    _decode_ver7_container,
)


class SocksIPVer7ProbeTests(unittest.TestCase):
    def test_plain_json_wrapper(self) -> None:
        parsed, route = _decode_ver7_container(b'VER7{"host":"example.com","port":443}')
        self.assertEqual(parsed, {"host": "example.com", "port": 443})
        self.assertEqual(route, "VER7:payload")

    def test_base64_json_wrapper(self) -> None:
        inner = json.dumps({"mode": "ssh", "enabled": True}, separators=(",", ":")).encode()
        parsed, route = _decode_ver7_container(b"VER7" + base64.b64encode(inner))
        self.assertEqual(parsed, {"mode": "ssh", "enabled": True})
        self.assertIn("base64", route)

    def test_zlib_json_wrapper(self) -> None:
        inner = b'{"server":"127.0.0.1","port":22}'
        parsed, route = _decode_ver7_container(b"VER7" + zlib.compress(inner))
        self.assertEqual(parsed, {"server": "127.0.0.1", "port": 22})
        self.assertIn("zlib", route)

    def test_gzip_json_wrapper(self) -> None:
        inner = b'{"payload":"CONNECT [host_port] HTTP/1.1"}'
        parsed, route = _decode_ver7_container(b"VER7" + gzip.compress(inner))
        self.assertEqual(parsed["payload"], "CONNECT [host_port] HTTP/1.1")
        self.assertIn("gzip", route)

    def test_unknown_ver7_is_not_falsely_decoded(self) -> None:
        with self.assertRaises(UnsupportedSocksIPVersion):
            _decode_ver7_container(b"VER7\x01\x02\x03\x04\x05\x06\x07")


if __name__ == "__main__":
    unittest.main()

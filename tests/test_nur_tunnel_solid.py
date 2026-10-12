"""Independent authenticated vectors for the bot-only NUR .solid route.

Constructed with Argon2id 1.3 and AES-GCM in a separate implementation;
test vectors contain no user credentials or private files.
"""
import unittest

from decoders.Python.nur_tunnel_solid import DecodeError, decode, run
from spdecode.registry import get_decoder, get_supported_extension

SOLID = (
    "AQIXDBAUGBwgJCgsMDQ4PEBQVFhcYGRobHB0eHw0rJtdBkpqoFQE9yPRDPvTKmNTRlF/do0jnqAnOTcpFAjj6Zz8NYeLkiB4bcno+ukg3Nhv54C2ztmdh0t56esvE1g4tyRC9cq5EYk0pJovcs+lywyK+nzJMYTXCylrpN2jzhYg0jiITY5TVXmjkBFlCSXDdErlbYpdYUsoLiGdmfj0ZMA811nMlk2WcogaKjU3IgbqzJpBhe4RauZ/o+yjwo57MDK+PQx2TjmuJKgMYWPcCoadTtFNzzOM+eEN0elU2wCl7S47rjQ=="
)
CATALOG = (
    "PD0+P0BBQkNERUZHSElKS1pbXF1eX2BhYmNkZbX6IiFFwyTKt3JkL1Yy+sIySAM7keBNoQUiSMYl3/nb3SSHsSvZIM3PH+3UoXmKmQiINr5BWPDVBpjaotnMCoE8DVkNRta0wPNwROwzaRUC4DLEu+EMAXDptd/ERkf0r328JWpQIKI6A8j5uGyhchYlJPXPAdHb9z36ZeqY7VYiX3GQQ90J8+hYFTKRf6sSHZGKIHyzqCrrpro0U+cOI+lcqnnLqWwRQQoHzu/nHhYHbDZy+q6Zi6Iz6+U5swNEA/DHGiv6se2KKkmQGT/B/IRUgGGTi7cY8TkMhB8zfPJi8WxqRLVz1IA="
)


class NurTunnelSolidTests(unittest.TestCase):
    def test_profile_outer_and_authenticated_inner(self):
        audit = {}
        result = decode(SOLID, audit=audit)
        self.assertEqual(result["Name"], "Synthetic NUR Test")
        self.assertEqual(result["TunnelType"], "SSH")
        self.assertEqual(result["SNI"], "example.org")
        self.assertEqual(result["Payload"], "GET / HTTP/1.1\r\nHost: example.org")
        self.assertTrue(audit["outer_authenticated"])
        self.assertEqual(audit["outer_mode"], "export-legacy")
        self.assertEqual(audit["decrypted_fields"], 1)
        self.assertIn('"Name": "Synthetic NUR Test"', run(SOLID))

    def test_catalog_cannot_masquerade_as_profile(self):
        with self.assertRaises(DecodeError) as ctx:
            decode(CATALOG)
        self.assertEqual(ctx.exception.code, "WRONG_DOCUMENT")

    def test_mac_failure_fails_closed(self):
        tampered = list(SOLID)
        tampered[10] = "A" if tampered[10] != "A" else "B"
        with self.assertRaises(DecodeError) as ctx:
            decode("".join(tampered))
        self.assertEqual(ctx.exception.code, "AUTH_FAILED")

    def test_dispatch_only_solid_not_servers(self):
        self.assertEqual(get_supported_extension("config.SoLiD"), "solid")
        self.assertEqual(get_decoder("solid").script, "decoders/Python/nur_tunnel_solid.py")
        self.assertIsNone(get_supported_extension("catalog.nurservers"))


if __name__ == "__main__":
    unittest.main()

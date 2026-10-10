"""HTTP Injector complete-field parity regression (synthetic, no user data)."""
import unittest
from decoders.Python.HTTPINJECTOR import EHIDecryptor,run
from scripts.android_ehi_complete_fixture import make

class EhiCompleteResultTest(unittest.TestCase):
    def test_plain_undecodable_string_kept_instead_of_silently_dropped(self):
        config={
            "overwriteServerData":"plain host",
            "unknownFormat":"plain:synthetic-not-encoded",
            "httpPayload":"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\nBODY",
            "serverPort":443,
            "flag":False,
            "nothing":None
        }
        result=EHIDecryptor._decode_inner_fields(config,"EVZJNI")
        self.assertEqual(config,result)
        self.assertEqual(list(config),list(result))
    def test_encodable_xor_string_still_decrypts(self):
        from scripts.android_ehi_standard_fixture import encode_field
        secret=encode_field("primary.example.invalid","EVZJNI")
        parsed=EHIDecryptor._decode_inner_fields({"serverHost":secret},"EVZJNI")
        self.assertEqual({"serverHost":"primary.example.invalid"},parsed)
    def test_full_bypass_iv_golden_retains_all_fields_and_types(self):
        encrypted,source,expected=make()
        self.assertEqual(source,run(encrypted)+"\n")
        for key,value in expected.items():
            with self.subTest(key=key):
                self.assertIn(f"│[۞] {key}:",source)
                if isinstance(value,str):
                    self.assertIn(value,source)
        self.assertIn("│[۞] finalField: LAST_FIELD_MUST_SURVIVE",source)
        self.assertIn('"servers":[',source)
        self.assertIn("serverPort: 443",source)
        self.assertIn("enabled: false",source)

if __name__=="__main__":unittest.main()

"""Security regressions for the source-controlled NPV whitebox table.

No untrusted pickle is accepted. Normal source-reference decryption must
continue producing the exact historical Linux golden output.
"""
from __future__ import annotations
import pickle
import unittest
from decoders.Python.NPVTUNNEL import (
    _load_whitebox_pickle, load_whitebox_state, _MAX_WHITEBOX_BYTES,
    whitebox_encrypt_block,
)


class NPVWhiteboxSecurityTests(unittest.TestCase):
    def test_safe_source_artifact_loads_and_whitebox_encrypts(self):
        state = load_whitebox_state()
        self.assertEqual(len(state), 4)
        block = whitebox_encrypt_block(bytes(range(16)), *state)
        self.assertEqual(len(block), 16)

    def test_globals_and_callable_reduce_are_rejected_without_execution(self):
        for evil in (b"cos\\nsystem\\n(S'echo dangerous'\\ntR.",
                     b"cbuiltins\\nlist\\n(tR.",
                     b"\\x80\\x04\\x8c\\x08builtins\\x94\\x8c\\x04eval\\x94\\x93."):
            with self.subTest(code=evil[:16]):
                with self.assertRaises((ValueError, pickle.UnpicklingError)):
                    _load_whitebox_pickle(evil)

    def test_reject_extra_data_and_wrong_types(self):
        for body in (pickle.dumps([]), pickle.dumps((1, 2, 3, 4)) + b"x"):
            with self.assertRaises(ValueError):
                _load_whitebox_pickle(body)

    def test_reject_decompression_budget_overrun(self):
        with self.assertRaises(ValueError):
            _load_whitebox_pickle(b"x" * (_MAX_WHITEBOX_BYTES + 1))


if __name__ == "__main__":
    unittest.main()

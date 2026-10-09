"""Regression gates for NPV source-derived, non-executable white-box bytes."""
from __future__ import annotations

import unittest

from scripts.android_a24_whitebox_export import compile_asset

class NpvWhiteboxAssetTests(unittest.TestCase):
    def test_audited_source_tables_are_fixed_size_and_reproducible(self):
        first = compile_asset()
        self.assertEqual(first[:8], b"NPWA0001")
        self.assertEqual(len(first), 8 + 96*16*16 + 2*16*256*4 + 16*256)
        self.assertEqual(first, compile_asset())

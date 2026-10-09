"""Ensure Android frozen HT/HAT source assets do not drift from originals.

No profile plaintext or secret material is included in assertion messages.
"""
import ast
import json
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

class FinalSourceIntegrityTests(unittest.TestCase):
    def test_http_tweak_original_variant_tables_pinned(self):
        src=ast.parse((ROOT/"decoders/Python/HTTPTWEAK.py").read_text("utf-8"))
        target=next(
            node for node in src.body if isinstance(node,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=="_TABLES_B64"
                    for t in node.targets)
        )
        original=ast.literal_eval(target.value)
        actual=json.loads((ROOT/"android/app/src/main/assets/http_tweak_source_tables.json").read_text("utf-8"))
        self.assertEqual({str(k):v for k,v in original.items()},actual,
                         "Android HTTP Tweak table snapshot differs from source")

    def test_hat_labels_snapshot_is_original(self):
        original=json.loads((ROOT/"nodehat.json").read_text("utf-8"))
        actual=json.loads((ROOT/"android/app/src/main/assets/nodehat_original_layout.json").read_text("utf-8"))
        self.assertEqual(original,actual,
                         "Android HAT layout snapshot differs from source")

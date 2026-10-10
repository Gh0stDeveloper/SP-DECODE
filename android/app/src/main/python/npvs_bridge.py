"""Android-only adapter. The original npvs.py decoder remains byte-for-byte unchanged."""
import base64
from npvs import run


def decode_b64(payload: str) -> str:
    return run(base64.b64decode(payload, validate=True))

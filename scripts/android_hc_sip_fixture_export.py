#!/usr/bin/env python3
"""Build deterministic, synthetic HC and SIP parity samples for Android CI."""
import argparse
import base64
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from decoders.Python.sockip import SIP_AES_KEY
from tests.golden.hc_sip_new_variants import export_android, sip_ver8_file, hccfg_file


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",type=Path,required=True)
    args=parser.parse_args()
    export_android(args.output_dir)
    raw=base64.b64decode(sip_ver8_file())
    outer=bytearray(unpad(AES.new(SIP_AES_KEY,AES.MODE_ECB).decrypt(raw),16))
    outer[-1]^=0x01
    broken=base64.b64encode(AES.new(SIP_AES_KEY,AES.MODE_ECB)
        .encrypt(pad(bytes(outer),16)))
    (args.output_dir/"variant-sip-ver8-bad-tag.sip").write_bytes(broken)
    bad=bytearray(hccfg_file())
    bad[-1]^=0x40
    (args.output_dir/"variant-hc-hccfg-bad-tag.hc").write_bytes(bad)
    print("HC/SIP multi-version synthetic Android fixtures prepared")


if __name__=="__main__":
    main()

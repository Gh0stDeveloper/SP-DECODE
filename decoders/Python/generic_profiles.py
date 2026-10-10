"""Key profiles preserved from the owner's authorized historical 66.py.

The source tables contain legacy application-specific decryption material.
Keep profile resolution deterministic and do not replace existing file decoders.
Original duplicate keys retain Python's last-definition-wins semantics.
Do not log or print profile passwords.
"""
from __future__ import annotations

import base64
from typing import Mapping

VPN_PASSWORDS = {
    '.tut': b'fubvx788b46v',
    '.uwu': b'Ed\x01',
    '.pb': b'fubvx788b46v',
    '.ziv': b'fubvx788b46v',
    '.v2i': b'Ed\x01',
    '.hdb': b'Ed\x01',
    '.hbd': b'Ed\x01',
    '.mtl': b'Ed\x01',
    '.purple': b'Ed\x01',
    '.tmt': b'$$$@mfube11!!_$$))012b4u',
    '.sks': b'662ede816988e58fb6d057d9d85605e0',
    #'.dark': b'W0RFRkFVTFRd',
    '.temt': b'fubvx788B4mev',
    '.stk': b'Bgw34Nmk',
    '.wcm': b'Ed\x01',
    '.utn': b'Ed\x01',
    '.tito': b'Ed\x01',
    '.1300': b'Ed\x01',
    '.acm': b'cinbdf66',
    '.etun': b'dyv35224nossas!!',
    '.pxp': b'bKps&92&',
    '.aipr': b'Ed\x01',
    '.ace': b'Ed\x01',
    '.mrc': b'Ed\x01',
    '.sshbrasil': b'sbr',
    '.net': b'Ed\x01',
    '.tsd': b'waiting',
    '.ssh': b'@263386285977449155626236830061505221752',
    '.ost': b'4pyF2Y5PU1Q=',
    '.aip': b'Ed\x01',
    '.cbp': b'Ed\x01',
    '.cyber': b'Ed\x01',
    '.wt': b'fuMnrztkzbQ',
    '.mij': b'Ed\x01',
    '.nac': b'Ed\x01',
    '.nhi': b'Ed\x01',
    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',
    '.nm': b'X25ldHN5bmFfbmV0bW9kXw==',
    '.fks': b'fubvx788b46v',
    '.gv': b'Ed\x01',
    '.sksx': b'Ed\x01',
    '.fnnetwork': b'Ed\x01',
    '.dkarl': b'Ed\x01',
    '.edan': b'Ed\x01',
    '.pkm': b'Ed\x01',
    '.spd': b'Ed\x01',
    '.ntr': b'Ed\x01',
    '.pir': b'Ed\x01',
    '.nx': b'Ed\x01',
    '.act': b'fubvx788b46v',
    '.cnet': b'cnt',
    '.gibs': b'Ed\x01',
    '.nd4': b'Ed\x01',
    '.dvd': b'dyv35224nossas!!',
    '.ezi': b'dyv35224nossas!!',
    '.ftp': b'Version6',
    '.fthp': b'furious0982',
    '.jph': b'fubvx788b46v',
    '.xsks': b'c7-YOcjyk1k',
    '.ht': b'error',
    '.ssi': b'Jicv',
    '.kt': b'kt',
    '.vmx': b'cdfdfdfd',
    '.fnet': b'62756C6F6B',
    '.mc': b'fubvx788b46v',
    '.hub': b'trfre699g79r',
    '.grd': b'fubvx788b46v',
    '.hta': b'Ed\x01',
    '.eug': b'fubvx788b46v',
    '.sds': b'rdovx202b46v',
    '.htp': b'chanika acid, gimsara htpcag!!',
    '.bbb': b'xcode788b46z',
    '.ccc': b'fubgf777gf6',
    '.ddd': b'fubvx788b46vcatsn',
    '.eee': b'dyv35182!',
    '.cln': b'fubvx788b46v',
    '.cyh': b'dyv35182!',
  #  '.agn': b'cigfhfghdf665557',
    '.Tcv2': b'fubvx788b46v',
    '.NT': b'0x0',
    '.ai': b'Ed\x01',
    '.cks': b'2$dOxdIb6hUpzb*Y@B0Nj!T!E2A6DOLlwQQhs4RO6QpuZVfjGx',
    '.sksrv': b'6pq8YieK$8D2kT4a6Pizv3i56nWi',
    '.skvoid': b'6pq8YieK$8D2kT4a6Pizv3i56nWi',
    '.garuda': b'fubvx788b46v',
    '.tpp': b'Ed\x01',
    '.sky': b'fubux788b46v',
    '.cks': b'2$dOxdIb6hUpzb*Y@B0Nj!T!E2A6DOLlwQQhs4RO6QpuZVfjGx',
    '.max': b'Ed\x01',
    '.pcx': b'cinbdf665$4',
   # '.crev': b'cinbdf665$4',
    '.hqp': b'Ed\x01',
    '.hq': b'Ed\x01',
    '.tsd': b'Ed\x01',
    '.pausa': b'Ed\x01',
    '.bdi': b'@technore 2022',
    '.ignix_vpn': b'DevProminex2026',
    '.ignix_vpn': b'3k8DiZh55Iss',
    '.dzd': b'A^ST^f6ASG6AS5asd',
    '.pin': b'agstgfohvs0hst',
    '.vpnlite': b'',
}

DES_PASSWORDS = {
    '.ost': base64.b64decode(b'4pyF2Y5PU1Q='),
   # '.agn': b'letsmake',
    '.vpc': b'cinbdf66',
    '.Fɴ': b'cinbdf66',
    '.clay': b'cinbdf66',
    '.cly': b'cinbdf66',
    '.jvi': b'cinbdf66',
    '.jvc': b'agstgfoh',
    '.v2i': b'cinbdf66',
    '.sbr': b'cinbdf66',
    '.acm': b'cinbdf66',
    '.dak': b'CREEBINJ',
    '.nxp': b'agstgfoh',
    '.wrld': b'cinbdf66',
    '.xsks': b'cinbdf66',
    '.ftr': b'cinbdf66',
    '.tut': b'fubvx788b46v',
    '.vmx': b'cdfdfdfd',
    '.it': b'cinbdf66',
    '.itv': b'cdfdfdfd',
    '.pin': b'agstgfohvs0hst',
    '.htp': b'chanika acid, gimsara htpcag!!',
    #'.apnalite': b'4be0c-69c3d9fe-19e2699',
    
}

MULTI_PASSWORDS = {
    '.ziv': [b'fubvx788b46v', b'SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5'],
    '.tnl': [b'A^ST^f6ASG6AS5asd', b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg'],
    '.pb': [b'fubvx788b46v', b'Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e'],
    '.cks': [b'2$dOxdIb6hUpzb*Y@B0Nj!T!E2A6DOLlwQQhs4RO6QpuZVfjGx'],
}

# All lookups are case-insensitive, because 66.py had mixed-case suffixes.
AES_PROFILES: dict[str, tuple[bytes, ...]] = {
    ext.lower(): tuple(
        MULTI_PASSWORDS.get(ext, [password])
    ) for ext, password in VPN_PASSWORDS.items() if password
}
DES_PROFILES: dict[str, bytes] = {
    ext.lower(): password for ext, password in DES_PASSWORDS.items() if password
}

# Disabled in the original generic router and must never be selected here.
GENERIC_EXCLUSIONS = frozenset({".vpnlite", ".hat"})


def generic_specs(
    already_registered: Mapping[str, object] | set[str] | frozenset[str],
) -> dict[str, tuple[str, str]]:
    """Only unclaimed suffixes; DES takes precedence if both have the key."""
    existing = {
        ("." + str(extension).lower().lstrip(".")) for extension in already_registered
    }
    available = (set(AES_PROFILES) | set(DES_PROFILES)) - GENERIC_EXCLUSIONS
    specs: dict[str, tuple[str, str]] = {}
    for extension in sorted(available - existing):
        if extension in DES_PROFILES:
            specs[extension] = ("Generic DES-ECB (AES-GCM fallback)", "decoders/Python/generic_des.py")
        else:
            specs[extension] = ("Generic AES-GCM / PBKDF2", "decoders/Python/generic_aes.py")
    return specs

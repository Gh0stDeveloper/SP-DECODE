#!/usr/bin/env python3
"""HTTP Custom HCCFG: script independiente con contraseña/HWID explícitos.

Probado con HTTP Custom 7.11.19 (885). No sustituye HTTPCUSTOM.py.
API: inspect_requirements(data), decode(data, password=None, hwid=None, audit=None).
CLI no interactiva: --password, --hwid, --inspect. JSON completo por defecto.
"""
import argparse
import hashlib, hmac, json, struct, sys, re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

PKG = b"xyz.easypro.httpcustom"
OUTER_AAD = b"HCX1|xyz.easypro.httpcustom|1"
OUTER_SEED = b"hc-envelope-seal-v1 xyz.easypro.httpcustom"
OUTER_SALT = b"hc-envelope-seal-salt-v1"
OUTER_INFO = b"hc-envelope-seal-info-v1"
OUTER_KEY_V3 = bytes.fromhex("88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f")
N7_HMAC_KEY = bytes.fromhex("9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3")
C0_PREFIX = bytes.fromhex(
    "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
    "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
)

class HCError(ValueError):
    """Error de importación con código y requisitos aptos para un formulario."""
    def __init__(self, message, *, code="INVALID_FILE", required=None):
        super().__init__(message)
        self.code = code
        self.required = list(required or [])

    def to_dict(self):
        result = {"error": {"code": self.code, "message": str(self)}}
        if self.required:
            result["error"]["required"] = self.required
        return result


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_SECTIONS = 256
MAX_ARGON_OPS = 16
MAX_ARGON_MEMORY = 256 * 1024 * 1024
    
def _c0(data: bytes) -> bytes:
    return hashlib.sha256(C0_PREFIX + data).digest()

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, ctr = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([ctr]), hashlib.sha256).digest()
        out += prev; ctr += 1
    return out[:length]

def _rol(v: int, b: int) -> int:
    return ((v << b) & 0xFFFFFFFF) | (v >> (32 - b))

def _qr(s: List[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rol(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rol(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rol(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rol(s[b] ^ s[c], 7)

def _rounds(s: List[int]) -> None:
    for _ in range(10):
        _qr(s,0,4,8,12); _qr(s,1,5,9,13); _qr(s,2,6,10,14); _qr(s,3,7,11,15)
        _qr(s,0,5,10,15); _qr(s,1,6,11,12); _qr(s,2,7,8,13); _qr(s,3,4,9,14)

def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + struct.unpack("<4I", nonce16))
    _rounds(s)
    return struct.pack("<8I", s[0],s[1],s[2],s[3],s[12],s[13],s[14],s[15])

def _chacha_block(key: bytes, nonce12: bytes, ctr: int) -> bytes:
    init = list(struct.unpack("<4I", b"expand 32-byte k") + struct.unpack("<8I", key) + (ctr & 0xFFFFFFFF,) + struct.unpack("<3I", nonce12))
    s = init.copy(); _rounds(s)
    return struct.pack("<16I", *((s[i] + init[i]) & 0xFFFFFFFF for i in range(16)))

def _stream_xor(data: bytes, key: bytes, nonce12: bytes, ctr: int = 1) -> bytes:
    out = bytearray(len(data))
    for bn, off in enumerate(range(0, len(data), 64)):
        st = _chacha_block(key, nonce12, ctr + bn)
        for i, v in enumerate(data[off:off+64]): out[off+i] = v ^ st[i]
    return bytes(out)

def _poly1305(msg: bytes, otk: bytes) -> bytes:
    r = int.from_bytes(otk[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    pad = int.from_bytes(otk[16:], "little"); acc = 0; mod = (1 << 130) - 5
    for off in range(0, len(msg), 16):
        acc = ((acc + int.from_bytes(msg[off:off+16] + b"\x01", "little")) * r) % mod
    return ((acc + pad) & ((1 << 128) - 1)).to_bytes(16, "little")

def _pad16(d: bytes) -> bytes:
    return b"" if len(d) % 16 == 0 else b"\x00" * (16 - len(d) % 16)

def _xdec_pure(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    sub = _hchacha20(key, nonce[:16]); n12 = b"\x00\x00\x00\x00" + nonce[16:]
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    otk = _chacha_block(sub, n12, 0)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    if not hmac.compare_digest(_poly1305(mac, otk), tag):
        raise HCError("XChaCha20-Poly1305 auth failed")
    return _stream_xor(ct, sub, n12, 1)

def _xdec(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 24 or len(ct_tag) < 16:
        raise HCError("bad XChaCha20 input")
    if CRYPTO_OK:
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce); c.update(aad)
        try: return c.decrypt_and_verify(ct_tag[:-16], ct_tag[-16:])
        except ValueError: raise HCError("XChaCha20-Poly1305 auth failed")
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        from nacl.exceptions import CryptoError
        try: return crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag, aad, nonce, key)
        except CryptoError: raise HCError("XChaCha20-Poly1305 auth failed")
    except ImportError:
        return _xdec_pure(key, nonce, aad, ct_tag)

def _argon2id(pw: bytes, salt: bytes, ops: int, mem: int, length: int = 32) -> bytes:
    if len(salt) != 16: raise HCError("Argon2 salt must be 16 bytes")
    try:
        from argon2.low_level import Type, hash_secret_raw
        from argon2.exceptions import HashingError
    except ImportError as exc:
        raise HCError("Instala argon2-cffi para archivos con contraseña.", code="DEPENDENCY_MISSING") from exc
    try:
        return hash_secret_raw(pw, salt, time_cost=ops, memory_cost=mem // 1024,
                               parallelism=1, hash_len=length, type=Type.ID, version=19)
    except (ValueError, RuntimeError, HashingError) as exc:
        raise HCError("No se pudo ejecutar Argon2id con los parámetros del archivo.",
                      code="KDF_FAILED") from exc

def _outer_key() -> bytes:
    return _hkdf(_c0(OUTER_SEED), OUTER_SALT, OUTER_INFO)

def _carriers(data: bytes):
    seen, cur = set(), data
    for _ in range(6):
        if cur in seen: break
        seen.add(cur)
        if len(cur) >= 40: yield cur
        try: text = cur.decode("utf-8")
        except UnicodeDecodeError: break
        if not all(ord(c) <= 0xFF for c in text): break
        nxt = bytes(ord(c) for c in text)
        if nxt == cur: break
        cur = nxt

def _open_outer(data: bytes, audit=None) -> Dict[str, Any]:
    if not isinstance(data, bytes) or not data:
        raise HCError("El archivo está vacío o no contiene bytes.")
    if len(data) > MAX_FILE_BYTES:
        raise HCError("El archivo supera el límite de 16 MiB.", code="RESOURCE_LIMIT")
    key = _outer_key(); last_err = None
    for carrier_depth, logical in enumerate(_carriers(data)):
        if len(logical) < 40: continue
        # Standard outer
        try:
            pt = _xdec(key, logical[:24], OUTER_AAD, logical[24:])
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict) and v.get("a") == "HCCFG":
                if audit is not None:
                    audit.update(outer="authenticated-v1", outer_authenticated=True,
                                 carrier_depth=carrier_depth, logical_bytes=len(logical))
                return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as e: last_err = e
        # V3 outer
        try:
            nonce, ct = logical[:24], logical[24:-16]
            sub = _hchacha20(OUTER_KEY_V3, nonce[:16]); n12 = b"\x00\x00\x00\x00" + nonce[16:]
            pt = _stream_xor(ct, sub, n12, 1)
            v = json.loads(pt.decode("utf-8"))
            if isinstance(v, dict) and v.get("a") == "HCCFG":
                if audit is not None:
                    audit.update(outer="stream-v3", outer_authenticated=False,
                                 carrier_depth=carrier_depth, logical_bytes=len(logical))
                return v
        except (HCError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as e: last_err = e
    raise HCError("No es un sobre HCCFG reconocido.", code="UNRECOGNIZED_FORMAT") from last_err

def _validate(env: Dict[str, Any]) -> int:
    if env.get("a") != "HCCFG": raise HCError(f"Bad magic: {env.get('a')!r}")
    schema = int(env.get("b", 0))
    if schema == 1: exp_c, exp_k = "XCHACHA20P1305", "NATIVE-HKDF-SHA256"
    elif schema in (2, 5, 7): exp_c, exp_k = "s1", "h1"
    else: raise HCError(f"Esquema HCCFG no compatible: {schema}.", code="UNSUPPORTED_VERSION")
    if env.get("c") != exp_c: raise HCError("Cifrado HCCFG no compatible.", code="UNSUPPORTED_VERSION")
    if env.get("d") != exp_k: raise HCError("KDF HCCFG no compatible.", code="UNSUPPORTED_VERSION")
    if env.get("e") not in ("n1", "n2", "n7", "n8"):
        raise HCError("Calendario HCCFG no compatible.", code="UNSUPPORTED_VERSION")
    return schema

def _features(env: Dict[str, Any]) -> bytes:
    f = env.get("f")
    if not isinstance(f, list) or not all(isinstance(x, str) for x in f): raise HCError("Bad features")
    return ",".join(f).encode()

def _n_bytes(env: Dict[str, Any]) -> Optional[bytes]:
    n = env.get("n")
    if n is None or isinstance(n, bool): return None
    ni = int(n)
    if str(ni) != str(n) or ni < 0: raise HCError("Bad n value")
    return str(ni).encode()

def _norm_hwid(hwid: str) -> bytes:
    if not isinstance(hwid, str):
        raise HCError("El HWID debe ser texto.", code="INVALID_HWID")
    v = hwid.strip()
    if len(v) != 32 or any(c not in "0123456789abcdefABCDEFhH" for c in v):
        raise HCError("El HWID debe tener 32 caracteres del formato de HTTP Custom.", code="INVALID_HWID")
    return v.upper().encode()

def _env_key(env: Dict[str, Any]) -> bytes:
    try: k = bytes.fromhex(env["g"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad inner key")
    if len(k) != 32: raise HCError("Inner key must be 32 bytes")
    return k

def _pw_kdf(env: Dict[str, Any], password: str, ekey: bytes) -> Tuple[bytes, bytes]:
    kdf = env.get("k")
    if kdf not in ("ARGON2ID13", "a1"): raise HCError("KDF de contraseña no compatible.", code="UNSUPPORTED_VERSION")
    try: ops, mem = int(env["l"]), int(env["m"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad Argon2 params")
    if (isinstance(env["l"], bool) or isinstance(env["m"], bool)
            or str(ops) != str(env["l"]) or str(mem) != str(env["m"])
            or not 1 <= ops <= MAX_ARGON_OPS or not 8192 <= mem <= MAX_ARGON_MEMORY
            or mem % 1024):
        raise HCError("Parámetros Argon2id inválidos o fuera de los límites.", code="RESOURCE_LIMIT")
    pk = _argon2id(password.encode(), ekey[:16], ops, mem)
    return pk, b"|1|ARGON2ID13|" + str(ops).encode() + b"|" + str(mem).encode()

def _h_flag(env: Dict[str, Any]) -> bool:
    h = env.get("h", 0)
    if not isinstance(h, (bool, int)) or h not in (0, 1): raise HCError("Indicador de contraseña inválido.")
    return bool(h)

def _transcript(env: Dict[str, Any], ekey: bytes, hwid_b: Optional[bytes] = None, n7_mode: bool = False) -> bytes:
    feats = _features(env); nb = _n_bytes(env); vb = b"1"
    t = b"HCCFG\x00" + PKG + b"\x00" + vb + b"\x00" + feats + b"\x00"
    if nb: t += nb + b"\x00"
    if hwid_b is not None: t += b"hwid\x00" + hwid_b + b"\x00"
    t += ekey
    if n7_mode:
        return hmac.new(N7_HMAC_KEY, b"\xd3" + C0_PREFIX[:32] + t, hashlib.sha256).digest()
    return _c0(t)

def _derive(env: Dict[str, Any], password: Optional[str], hwid: Optional[str]) -> Tuple[bytes, bytes]:
    sched = env.get("e"); schema = _validate(env); ekey = _env_key(env)
    feats = _features(env); nb = _n_bytes(env); vb = b"1"
    is_hwid = sched in ("n2", "n8")
    is_n7 = sched in ("n7", "n8")

    missing = []
    if _h_flag(env) and password is None: missing.append("password")
    if is_hwid and hwid is None: missing.append("hwid")
    if missing:
        code = ("CREDENTIALS_REQUIRED" if len(missing) == 2 else
                "PASSWORD_REQUIRED" if missing[0] == "password" else "HWID_REQUIRED")
        raise HCError("Debes proporcionar " + " y ".join(missing) + ".", code=code, required=missing)
    if password is not None and not isinstance(password, str):
        raise HCError("La contraseña debe ser texto.", code="INVALID_PASSWORD")

    hwid_b = _norm_hwid(hwid) if is_hwid else None
    ikm = _transcript(env, ekey, hwid_b, n7_mode=is_n7)
    protected = _h_flag(env)
    aad_prot = b"|0"

    if protected:
        pk, aad_prot = _pw_kdf(env, password, ekey)
        ikm = ikm + pk

    sched_b = sched.encode()
    info = b"app-config|" + sched_b + b"|" + PKG + b"|" + vb + b"|" + feats
    if nb: info += b"|" + nb
    if hwid_b: info += b"|hwid|" + hwid_b
    skey = _hkdf(ikm, ekey, info)

    aad = (b"HCCFG|" + str(schema).encode() + b"|XCHACHA20P1305|NATIVE-HKDF-SHA256|"
           + sched_b + b"|" + PKG + b"|" + vb + b"|" + feats + aad_prot)
    if nb: aad += b"|" + nb

    # For HWID schedules, try key slots
    if is_hwid:
        slots = env.get("o", [])
        if not isinstance(slots, list) or not slots: raise HCError("No HWID key slots")
        if len(slots) > MAX_SECTIONS:
            raise HCError("Demasiados slots HWID.", code="RESOURCE_LIMIT")
        for slot in slots:
            if not isinstance(slot, dict): continue
            try:
                nonce = bytes.fromhex(slot["a"]); ct = bytes.fromhex(slot["b"])
                sk = _xdec(skey, nonce, aad + b"\x00w", ct)
                if len(sk) == 32: return sk, aad
            except (HCError, TypeError, ValueError, KeyError): continue
        raise HCError("No se pudo autenticar el slot HWID: credenciales incorrectas o archivo alterado.",
                      code="AUTH_FAILED")

    return skey, aad
    
class _R:
    def __init__(self, d: bytes): self.d, self.o = d, 0
    def take(self, n: int) -> bytes:
        if self.o + n > len(self.d): raise HCError("Truncated HPC1")
        v = self.d[self.o:self.o+n]; self.o += n; return v
    def u32(self) -> int: return struct.unpack(">I", self.take(4))[0]
    def u64(self) -> int: return struct.unpack(">Q", self.take(8))[0]
    def txt(self) -> str:
        s = self.u32()
        if s > 16*1024*1024: raise HCError("HPC1 string too long")
        return self.take(s).decode("utf-8")

def _parse_hpc1(data: bytes, label: Optional[str]) -> Dict[str, Any]:
    r = _R(data)
    if r.take(4) != b"HPC1": raise HCError("Not HPC1")
    if r.u32() != 11: raise HCError("Bad HPC1 field count")
    name, proto, host = r.txt(), r.txt(), r.txt()
    port = r.u32(); user, pw, payload = r.txt(), r.txt(), r.txt()
    opts_txt = r.txt(); flags = r.u32(); updated = r.u64(); mode = r.txt()
    if r.o != len(data): raise HCError("HPC1 trailing bytes")
    try: opts = json.loads(opts_txt) if opts_txt else {}
    except json.JSONDecodeError: opts = opts_txt
    res: Dict[str, Any] = {"name": name, "protocol": proto, "host": host, "port": port,
                           "username": user, "password": pw, "payload": payload,
                           "options": opts, "flags": flags, "updated_at_ms": updated, "mode": mode}
    if label: res["label"] = label
    return res

def _dec_section(sec: Dict[str, Any], key: bytes, aad_base: bytes) -> bytes:
    try:
        label = sec["a"]; nonce = bytes.fromhex(sec["b"]); ct = bytes.fromhex(sec["c"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad section")
    if not isinstance(label, str) or not label: raise HCError("Bad section label")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode(), ct)

def _dec_sidecar(sec: Dict[str, Any], key: bytes, aad_base: bytes) -> Optional[bytes]:
    nested = sec.get("d")
    if nested is None: return None
    if not isinstance(nested, dict): raise HCError("Bad sidecar")
    label = sec.get("a", "")
    try: nonce = bytes.fromhex(nested["a"]); ct = bytes.fromhex(nested["b"])
    except (KeyError, TypeError, ValueError): raise HCError("Bad sidecar data")
    return _xdec(key, nonce, aad_base + b"\x00" + label.encode() + b":x", ct)

def _dec_hpr1(data: bytes, key: bytes, aad_base: bytes, label: Optional[str]) -> bytes:
    if not data.startswith(b"HPR1"): return data
    if len(data) < 44: raise HCError("HPR1 truncado.")
    nonce, ct_tag = data[4:28], data[28:]
    tag = (label or "s0").encode()
    # Las seis envolturas HPR1 reales autenticaron. Este script no convierte
    # un tag fallido en un resultado de flujo no autenticado.
    return _xdec(key, nonce, aad_base + b"\x00" + tag + b":r", ct_tag)

def _sec_list(v: Any) -> List[Dict[str, Any]]:
    if not isinstance(v, (list, dict)) or len(v) > MAX_SECTIONS:
        raise HCError("Colección de secciones inválida o demasiado grande.", code="RESOURCE_LIMIT")
    if isinstance(v, list) and all(isinstance(x, dict) for x in v): return v
    if isinstance(v, dict) and all(isinstance(x, dict) for x in v.values()): return list(v.values())
    raise HCError("Bad section collection")

PKM = {"a":"accessMode","c":"expiryEnabled","d":"expiryTime","e":"noteEnabled",
       "f":"hwidLockEnabled","g":"hwids","h":"loginHwidEnabled",
       "j":"loginHwidAuthorizationRequired","l":"mobileDataOnly","m":"blockRoot",
       "o":"providerLockEnabled","p":"providerCodes","v":"note"}

HC_VERSIONS = {756:"7.9.21", 759:"7.9.24", 766:"7.9.28", 789:"7.10.7", 810:"7.10.12",
               831:"7.10.19", 848:"7.10.25", 859:"7.11.1", 864:"7.11.8", 885:"7.11.19"}

def _ver(n):
    try: return f"{HC_VERSIONS[int(n)]} ({int(n)})"
    except (KeyError, TypeError, ValueError): return f"build-{n}"

def _norm_prot(p: Any) -> Any:
    if not isinstance(p, dict): return p
    return {PKM.get(k, k): v for k, v in p.items()}

def _requirements(env):
    _validate(env)
    return {"password_required": _h_flag(env), "hwid_required": env["e"] in ("n2", "n8"),
            "hwid_slots": len(env.get("o", [])) if isinstance(env.get("o", []), list) else 0}


def inspect_requirements(data: bytes) -> Dict[str, Any]:
    """Lee sólo los requisitos. En stream-v3 la cabecera no está autenticada."""
    try:
        audit = {}
        env = _open_outer(data, audit)
        _n_bytes(env)
        return {"format": "HCCFG", "schema": _validate(env), "schedule": env["e"],
                "app_version": _ver(env.get("n")), **_requirements(env),
                "header_authenticated": audit["outer_authenticated"]}
    except HCError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise HCError("Metadatos HCCFG inválidos.") from exc


def _decode(data, password, hwid, audit):
    envelope_audit = {}
    env = _open_outer(data, envelope_audit)
    requirements = _requirements(env)
    skey, aad_base = _derive(env, password, hwid)

    main_sec = env.get("i")
    if not isinstance(main_sec, dict): raise HCError("Missing main section")
    main_pt = _dec_section(main_sec, skey, aad_base)
    try: main_cfg = json.loads(main_pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError): raise HCError("Main section not JSON")
    if not isinstance(main_cfg, dict): raise HCError("La sección principal debe ser un objeto JSON.")

    profiles, others, hpr1_count = [], [], 0
    for sec in _sec_list(env.get("j", [])):
        pt = _dec_section(sec, skey, aad_base)
        label = sec.get("a")
        if pt.startswith(b"HPR1"):
            pt = _dec_hpr1(pt, skey, aad_base, label)
            hpr1_count += 1
        sidecar = _dec_sidecar(sec, skey, aad_base)
        if pt.startswith(b"HPC1"):
            prof = _parse_hpc1(pt, label)
            if sidecar is not None:
                try: prof["custom_payload_sidecar"] = sidecar.decode("utf-8")
                except UnicodeDecodeError: prof["custom_payload_sidecar_hex"] = sidecar.hex()
            profiles.append(prof)
        else:
            try:
                dec = pt.decode("utf-8")
                if dec.startswith(("{", "[")): dec = json.loads(dec)
            except (UnicodeDecodeError, json.JSONDecodeError): dec = {"hex": pt.hex()}
            others.append({"label": label, "content": dec})

    result: Dict[str, Any] = {"app_version": _ver(env.get("n")),
                              "requirements": requirements,
                              "config": profiles, "protections": _norm_prot(main_cfg.get("g", {})),
                              "main_config": main_cfg}
    if others: result["other_sections"] = others
    if audit is not None:
        audit.update(envelope_audit)
        audit.update(input_sha256=hashlib.sha256(data).hexdigest(), schema=env["b"],
                     schedule=env["e"], password_used=requirements["password_required"],
                     hwid_used=requirements["hwid_required"],
                     sections_authenticated=1 + len(_sec_list(env.get("j", []))),
                     hpr1_authenticated=hpr1_count,
                     profiles=len(profiles), all_sections_authenticated=True)
    return result


def decode(data: bytes, password: Optional[str] = None, hwid: Optional[str] = None,
           audit: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if audit is not None: audit.clear()
    try:
        return _decode(data, password, hwid, audit)
    except HCError as exc:
        if "auth failed" in str(exc):
            raise HCError("No se pudo autenticar el contenido: credenciales incorrectas o archivo alterado.",
                          code="AUTH_FAILED") from exc
        raise
    except (ImportError, ModuleNotFoundError) as exc:
        raise HCError("Instala pycryptodome y argon2-cffi.", code="DEPENDENCY_MISSING") from exc
    except (ValueError, TypeError, KeyError, UnicodeError, struct.error, RecursionError) as exc:
        raise HCError("Estructura HCCFG inválida.") from exc


decrypt = decode


def run(data: bytes, password: Optional[str] = None, hwid: Optional[str] = None) -> str:
    return json.dumps(decode(data, password, hwid), ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--password", help="contraseña exacta; se conserva espacios y mayúsculas")
    parser.add_argument("--hwid", help="HWID HTTP Custom, 32 caracteres")
    parser.add_argument("--inspect", action="store_true", help="sólo requisitos; no descifra perfiles")
    parser.add_argument("--json", action="store_true", help="JSON completo (predeterminado)")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args()
    try:
        paths = [p.resolve() for p in (args.file, args.output, args.audit) if p is not None]
        if len(set(paths)) != len(paths):
            raise HCError("Entrada, salida y auditoría deben usar rutas distintas.", code="INVALID_OUTPUT")
        with args.file.open("rb") as source:
            data = source.read(MAX_FILE_BYTES + 1)
        audit = {}
        if args.inspect:
            result = inspect_requirements(data)
            audit = {"mode": "inspect", "sections_authenticated": 0}
        else:
            result = decode(data, password=args.password, hwid=args.hwid, audit=audit)
        out = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output: args.output.write_text(out, encoding="utf-8")
        else: print(out, end="")
        if args.audit:
            args.audit.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0
    except HCError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError:
        print(json.dumps({"error": {"code": "IO_ERROR", "message": "No se pudo leer o guardar el archivo."}},
                         ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


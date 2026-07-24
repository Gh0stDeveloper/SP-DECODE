import base64
import binascii
import json
import struct
from typing import Any, Optional
from dataclasses import dataclass

# =========================================================================
# ثوابت SIP المتقدمة
# =========================================================================
SIP_AES_KEY = bytes.fromhex("192e04080804040905592959385f5417")
SIP_STREAM_MAGIC = b"\xac\xed\x00\x05"


class UnsupportedSocksIPVersion(Exception):
    """Raised when a recognized profile uses an unavailable inner container."""
    pass


@dataclass
class _SIPClassDesc:
    name: str
    flags: int
    fields: list[tuple[str, str]]
    superclass: Optional["_SIPClassDesc"] = None


class _SIPJavaObjectReader:
    """Bounded Java Object Serialization reader for SocksIP exports."""

    BASE_HANDLE = 0x7E0000

    def __init__(self, data: bytes):
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("serialización demasiado grande")
        self.data = data
        self.pos = 0
        self.handles: dict[int, Any] = {}
        self.next_handle = self.BASE_HANDLE

    def _read(self, size: int) -> bytes:
        end = self.pos + size
        if size < 0 or end > len(self.data):
            raise ValueError("serialización Java truncada")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def _u1(self) -> int:
        return self._read(1)[0]

    def _u2(self) -> int:
        return struct.unpack(">H", self._read(2))[0]

    def _u4(self) -> int:
        return struct.unpack(">I", self._read(4))[0]

    def _utf(self, long: bool = False) -> str:
        length = struct.unpack(">Q", self._read(8))[0] if long else self._u2()
        if length > 1024 * 1024:
            raise ValueError("cadena Java demasiado grande")
        return self._read(length).decode("utf-8", errors="replace")

    def _new_handle(self, value: Any) -> Any:
        self.handles[self.next_handle] = value
        self.next_handle += 1
        return value

    def read(self) -> Any:
        if self._read(4) != SIP_STREAM_MAGIC:
            raise ValueError("cabecera de serialización Java inválida")
        value = self._content()
        if self.pos != len(self.data):
            raise ValueError("datos adicionales en la serialización Java")
        return value

    def _content(self, token: Optional[int] = None) -> Any:
        token = self._u1() if token is None else token
        if token == 0x70:  # TC_NULL
            return None
        if token == 0x71:  # TC_REFERENCE
            handle = self._u4()
            if handle not in self.handles:
                raise ValueError("referencia Java desconocida")
            return self.handles[handle]
        if token == 0x74:  # TC_STRING
            return self._new_handle(self._utf())
        if token == 0x7C:  # TC_LONGSTRING
            return self._new_handle(self._utf(long=True))
        if token == 0x72:  # TC_CLASSDESC
            return self._classdesc()
        if token == 0x73:  # TC_OBJECT
            return self._object()
        raise ValueError(f"token de serialización Java no soportado: 0x{token:02x}")

    def _classdesc(self) -> _SIPClassDesc:
        name = self._utf()
        self._read(8)  # serialVersionUID
        desc = self._new_handle(_SIPClassDesc(name=name, flags=0, fields=[]))
        desc.flags = self._u1()
        count = self._u2()
        if count > 512:
            raise ValueError("demasiados campos en la clase Java")
        for _ in range(count):
            typecode = chr(self._u1())
            field_name = self._utf()
            type_name = typecode
            if typecode in {"L", "["}:
                descriptor = self._content()
                if not isinstance(descriptor, str):
                    raise ValueError("descriptor de campo Java inválido")
                type_name = descriptor
            desc.fields.append((field_name, type_name))

        while True:
            annotation = self._u1()
            if annotation == 0x78:  # TC_ENDBLOCKDATA
                break
            self._content(annotation)
        superclass = self._content()
        if superclass is not None and not isinstance(superclass, _SIPClassDesc):
            raise ValueError("superclase Java inválida")
        desc.superclass = superclass
        return desc

    def _object(self) -> dict[str, Any]:
        desc = self._content()
        if not isinstance(desc, _SIPClassDesc):
            raise ValueError("objeto Java sin descriptor de clase")
        result: dict[str, Any] = {"__class__": desc.name}
        self._new_handle(result)
        lineage: list[_SIPClassDesc] = []
        current: Optional[_SIPClassDesc] = desc
        while current is not None:
            lineage.append(current)
            current = current.superclass
        for current in reversed(lineage):
            for field_name, type_name in current.fields:
                result[field_name] = self._field(type_name)
            if current.flags & 0x01:  # SC_WRITE_METHOD
                while True:
                    token = self._u1()
                    if token == 0x78:
                        break
                    if token == 0x77:
                        self._read(self._u1())
                    elif token == 0x7A:
                        self._read(self._u4())
                    else:
                        self._content(token)
        return result

    def _field(self, type_name: str) -> Any:
        typecode = type_name[0]
        if typecode == "B":
            return struct.unpack(">b", self._read(1))[0]
        if typecode == "C":
            return chr(self._u2())
        if typecode == "D":
            return struct.unpack(">d", self._read(8))[0]
        if typecode == "F":
            return struct.unpack(">f", self._read(4))[0]
        if typecode == "I":
            return struct.unpack(">i", self._read(4))[0]
        if typecode == "J":
            return struct.unpack(">q", self._read(8))[0]
        if typecode == "S":
            return struct.unpack(">h", self._read(2))[0]
        if typecode == "Z":
            return bool(self._u1())
        if typecode in {"L", "["}:
            return self._content()
        raise ValueError(f"tipo de campo Java no soportado: {type_name}")


def _sip_unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise ValueError("plaintext vacío")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("padding PKCS#7 inválido")
    return data[:-padding]


def _sip_decrypt_aes_ecb(ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("ciphertext AES-ECB inválido")
    try:
        from Crypto.Cipher import AES
        plaintext = AES.new(SIP_AES_KEY, AES.MODE_ECB).decrypt(ciphertext)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        decryptor = Cipher(algorithms.AES(SIP_AES_KEY), modes.ECB()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return _sip_unpad_pkcs7(plaintext)


def decrypt_sip_advanced(file_data: bytes) -> Optional[dict]:
    """
    فك تشفير ملفات .sip باستخدام Java Serialization + AES-ECB
    """
    try:
        # تنظيف البيانات
        if isinstance(file_data, bytes):
            content = file_data.decode('utf-8', errors='ignore').strip()
        else:
            content = str(file_data)
        
        # إزالة البروتوكول إن وجد
        if content.startswith("sip://"):
            content = content[6:]
        
        # إزالة المسافات والأسطر الجديدة
        content = "".join(content.split())
        
        # إصلاح Base64 padding
        missing = len(content) % 4
        if missing:
            content += "=" * (4 - missing)
        
        # فك Base64
        encrypted = base64.b64decode(content)
        
        # فك AES-ECB
        plaintext = _sip_decrypt_aes_ecb(encrypted)
        
        # التحقق من VER7 (إصدار غير مدعوم)
        if plaintext.startswith(b"VER7"):
            raise UnsupportedSocksIPVersion(
                "الملف يستخدم إصدار VER7 غير مدعوم حالياً"
            )
        
        # قراءة Java Serialization
        parsed = _SIPJavaObjectReader(plaintext).read()
        
        if not isinstance(parsed, dict):
            raise ValueError("البيانات المفككة ليست كائن Java")
        
        # إزالة معلومات الفئة
        parsed.pop("__class__", None)
        
        return parsed
        
    except UnsupportedSocksIPVersion as e:
        logger.warning(f"SIP advanced: {e}")
        return None
    except Exception as e:
        logger.debug(f"SIP advanced error: {e}")
        return None


def format_sip_advanced_output(data: dict, extension: str = "sip") -> str:
    """
    تنسيق مخرجات SIP المتقدمة بنفس شكل البوت
    """
    from datetime import datetime
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    result = f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.sip)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"

    # عرض البيانات بشكل منظم
    if isinstance(data, dict):
        for key, value in data.items():
            if value is not None and str(value).strip():
                icon = get_premium_icon(str(key))
                if isinstance(value, dict):
                    result += f"│[۞] {icon} {sc(str(key))}:\n"
                    for sub_key, sub_value in value.items():
                        if sub_value and str(sub_value).strip():
                            result += f"│[۞] {sc(str(sub_key))}: {str(sub_value)[:200]}\n"
                elif isinstance(value, list):
                    result += f"│[۞] {icon} {sc(str(key))}: [{len(value)} items]\n"
                    for item in value[:3]:
                        if isinstance(item, dict):
                            for s_k, s_v in item.items():
                                if s_v:
                                    result += f"│[۞] {sc(str(s_k))}: {str(s_v)[:100]}\n"
                        else:
                            result += f"│[۞] {str(item)[:100]}\n"
                    if len(value) > 3:
                        result += f"│[۞]  ... and {len(value)-3} more\n"
                else:
                    val_str = str(value)
                    if len(val_str) > 300:
                        val_str = val_str[:300] + "..."
                    result += f"│[۞] {icon} {sc(str(key))}: {val_str}\n"
    elif isinstance(data, str):
        for line in data.split('\n')[:40]:
            if line.strip():
                result += f"│[۞] {line.strip()[:300]}\n"
    else:
        result += f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"


# ==================== SIP ADVANCED DECRYPTOR (XOR Layer) ====================

def decrypt_sip_xor(hex_input: str) -> Optional[str]:
    """
    فك تشفير النص السداسي عشري باستخدام مفتاح XOR ثابت (الطبقة الثانية لـ SIP)
    """
    try:
        hex_input = hex_input.strip().replace(" ", "").replace("\n", "")
        
        # التحقق من صحة النص السداسي
        try:
            input_bytes = binascii.unhexlify(hex_input)
        except (binascii.Error, ValueError):
            return None
        
        # مفتاح XOR المستخدم في SocksIP
        XOR_KEY = bytes.fromhex("192e04080804040905592959385f5417")
        
        # تطبيق XOR
        result = bytearray()
        for i, b in enumerate(input_bytes):
            result.append(b ^ XOR_KEY[i % len(XOR_KEY)])
        
        # محاولة فك تشفير النص
        try:
            return result.decode('utf-8', errors='ignore')
        except:
            return None
            
    except Exception:
        return None


def decrypt_sip_with_xor(file_data: bytes) -> Optional[dict]:
    """
    فك تشفير ملف .sip باستخدام XOR (الطبقة الثانية) ثم محاولة تحويل الناتج إلى JSON
    """
    try:
        if isinstance(file_data, bytes):
            content = file_data.decode('utf-8', errors='ignore').strip()
        else:
            content = str(file_data)
        
        # إزالة البروتوكول
        if content.startswith("sip://"):
            content = content[6:]
        
        # فك XOR
        decrypted = decrypt_sip_xor(content)
        if not decrypted:
            return None
        
        # محاولة تحليل JSON
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            # إذا لم يكن JSON، نعيد النص كقاموس raw
            return {"raw_decrypted": decrypted}
            
    except Exception as e:
        logger.debug(f"SIP XOR decrypt error: {e}")
        return None


# ==================== دمج SIP DECRYPTORS في البوت ====================

def decrypt_sip_file_combined(file_data: bytes) -> Optional[str]:
    """
    دالة متكاملة لفك تشفير ملفات .sip:
    1. محاولة فك XOR أولاً
    2. إذا فشل، محاولة الفك المتقدم (Java Serialization)
    3. إذا فشل، محاولة الفك البسيط (AES-ECB مع المفاتيح)
    """
    # 1. محاولة فك XOR
    try:
        xor_result = decrypt_sip_with_xor(file_data)
        if xor_result:
            # إذا كان JSON، نعرضه منسقاً
            if isinstance(xor_result, dict) and "raw_decrypted" not in xor_result:
                return format_sip_advanced_output(xor_result, "sip_xor")
            elif isinstance(xor_result, dict) and xor_result.get("raw_decrypted"):
                return f"```\n{xor_result['raw_decrypted'][:500]}\n```"
    except Exception as e:
        logger.debug(f"SIP XOR attempt failed: {e}")
    
    # 2. محاولة الفك المتقدم (Java Serialization)
    try:
        adv_result = decrypt_sip_advanced(file_data)
        if adv_result:
            return format_sip_advanced_output(adv_result, "sip_java")
    except UnsupportedSocksIPVersion:
        pass
    except Exception as e:
        logger.debug(f"SIP advanced attempt failed: {e}")
    
    # 3. محاولة الفك البسيط (AES-ECB مع المفاتيح من KEYS)
    try:
        simple_result = decrypt_sip_file(file_data)
        if simple_result:
            # محاولة تحليل JSON
            try:
                json_data = json.loads(simple_result)
                return format_sip_advanced_output(json_data, "sip_simple")
            except:
                return f"```\n{simple_result[:500]}\n```"
    except Exception as e:
        logger.debug(f"SIP simple attempt failed: {e}")
    
    return None
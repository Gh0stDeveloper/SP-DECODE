import runpy,struct,hashlib,zipfile,hmac
from pathlib import Path
from unicorn import UC_HOOK_CODE
from Crypto.Cipher import AES,ChaCha20_Poly1305
s=runpy.run_path('analysis_tls/unpack_native.py',run_name='__main__');e=s['e'];base=e.runtime_base
for va in (0x2a3cc,0x2a400):e.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:e.ret(0),begin=base+va,end=base+va)
apk=Path('analysis_tls/base.apk').read_bytes();eo=apk.rfind(b'PK\x05\x06');cd=struct.unpack_from('<I',apk,eo+16)[0]
size=struct.unpack_from('<Q',apk,cd-24)[0];start=cd-size-8;block=apk[start+8:cd]
print('signing block',len(block),block[-16:])
bp=e.alloc(len(block));e.u.mem_write(bp,block);zipctx=e.alloc(4096);e.u.mem_write(zipctx+24,struct.pack('<I',len(apk)))
e.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:e.ret(zipctx),begin=base+0x79200,end=base+0x79200)
e.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:e.ret(37),begin=base+0x4dcdc,end=base+0x4dcdc)
def sigblock(u,a,z,d):
 u.mem_write(e.r(1),struct.pack('<Q',bp));u.mem_write(e.r(2),struct.pack('<Q',len(block)));e.ret(0)
e.u.hook_add(UC_HOOK_CODE,sigblock,begin=base+0x51d00,end=base+0x51d00)
zf=zipfile.ZipFile('analysis_tls/base.apk');entries={};entry_names={}
def find(u,a,z,d):
 name=e.read(e.r(1),200).split(b'\0')[0].decode('utf-8',errors='replace');print('zip_find',name,flush=True)
 if name not in zf.namelist():e.ret(0);return
 en=e.alloc(4096);data=zf.read(name);dp=e.alloc(len(data));u.mem_write(dp,data)
 # Hand the consumer stored/uncompressed bytes; it folds at most the first 1024.
 u.mem_write(en+10,struct.pack('<H',0));u.mem_write(en+20,struct.pack('<II',len(data),len(data)))
 entries[en]=dp;entry_names[en]=name;e.ret(en)
def readentry(u,a,z,d):
 u.mem_write(e.r(2),struct.pack('<Q',entries[e.r(1)]));e.ret(0)
e.u.hook_add(UC_HOOK_CODE,find,begin=base+0x51aa8,end=base+0x51aa8)
e.u.hook_add(UC_HOOK_CODE,readentry,begin=base+0x51c3c,end=base+0x51c3c)
e.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:e.ret(0),begin=base+0x51cf0,end=base+0x51cf0)
def unwrap(u,a,z,d):
 key=e.read(e.r(0),32);cipher=e.read(e.r(1),e.r(2));print('unwrap',hex(e.r(1)-base),key.hex(),flush=True)
 for mode in (AES.MODE_KWP,AES.MODE_KW):
  try:
   plain=AES.new(key,mode).unseal(cipher);u.mem_write(e.r(3),plain);e.ret(0);print('unwrap_success',flush=True);return
  except ValueError:pass
 print('unwrap_fail',flush=True)
# capture rather than replacing this primitive initially
e.u.hook_add(UC_HOOK_CODE,unwrap,begin=base+0x2f474,end=base+0x2f474)
folds=[]
def mix(u,a,z,d):
 prk=e.read(e.r(0),32);data=e.read(e.r(1),e.r(2));salt=hmac.digest(prk,struct.pack('<Q',0x07ffcfc433e03432)+b'\1','sha256')
 result=hmac.digest(salt,data,'sha256');folds.append(data);u.mem_write(e.r(3),result);e.ret(0)
 print('mix',len(data),hashlib.sha256(data).hexdigest()[:12],flush=True)
e.u.hook_add(UC_HOOK_CODE,mix,begin=base+0x574dc,end=base+0x574dc)
ctx=e.alloc(4096)
def call(va,args):return e.call(base+va-s['BASE'],args)
call(0x4dd48,[])
call(0x20e84,[])
kp=struct.unpack('<Q',e.read(base+0xac340,8))[0];print('keys',hex(kp),e.read(kp,108).hex(),flush=True)
e.u.hook_add(UC_HOOK_CODE,lambda u,a,z,d:e.ret(0),begin=base+0x518a0,end=base+0x518a0)
call(0x790d0,[0])
# Successful ART verification in 16b60 also toggles byte 0x37 of the IKM.
e.u.mem_write(base+0xa9ae8+0x37,bytes([e.read(base+0xa9ae8+0x37,1)[0]^1]))
print('ikm',e.read(base+0xa9ae8,64).hex(),flush=True)
def stopcrc(u,a,z,d):
 print('crc flag',e.read(base+0xa9af6,1).hex(),flush=True);u.emu_stop()
e.u.hook_add(UC_HOOK_CODE,stopcrc,begin=base+0x57f38,end=base+0x57f38)
call(0x57bf4,[])
print('ikm_after_crc',e.read(base+0xa9ae8,64).hex(),flush=True)
call(0x57440,[base+0xa9b74,32,base+0xa9ae8,64,ctx])
call(0x4bc60,[ctx])
call(0x9ad44,[ctx,3])
call(0x83b58,[ctx])
info=e.alloc(4096);out=e.alloc(4096);e.u.mem_write(info,struct.pack('<Q',0x5d4e7ccff0335568))
call(0x5748c,[ctx,info,8,out,44]);v=e.read(out,44);Path('analysis_tls/assets_meta_keynonce.bin').write_bytes(v)
prk=e.read(ctx,32);i=struct.pack('<Q',0x5d4e7ccff0335568);t=hmac.digest(prk,i+b'\1','sha256');v2=t+hmac.digest(prk,t+i+b'\2','sha256')[:12];print('expand_matches',v==v2,flush=True)
Path('analysis_tls/assets_final_prk.bin').write_bytes(prk)
Path('analysis_tls/assets_matching_prk.bin').write_bytes(prk)
for j,data in enumerate(folds):Path('analysis_tls',f'fold_{j}.bin').write_bytes(data)
check=hmac.digest(prk,struct.pack('<Q',0x91a4fb076b659459)+b'\1','sha256')[:4];print('key check',check.hex(),e.read(base+0xa9b28,4).hex(),flush=True)
assert check==e.read(base+0xa9b28,4), 'APK root-key check failed'
b=Path('analysis_tls/assets.dat').read_bytes();n=b[-1]
c=ChaCha20_Poly1305.new(key=v[:32],nonce=v[32:]);c.update(b[-1:]);p=c.decrypt_and_verify(b[-17-n:-17],b[-17:-1])
Path('analysis_tls/assets_metadata.bin').write_bytes(p);print('metadata success',p.hex())

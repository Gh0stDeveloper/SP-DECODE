from pathlib import Path
import hmac,struct
from Crypto.Cipher import ChaCha20,ChaCha20_Poly1305
from chacha8 import crypt
def expand(prk,info,n):
 t=b'';out=b''
 for j in range(1,(n+31)//32+1):
  t=hmac.digest(prk,t+info+bytes([j]),'sha256');out+=t
 return out[:n]
prk=Path('analysis_tls/assets_post_java_prk.bin').read_bytes()
stages=[(5,0x873552bc11e8ff0e,44,False),(4,0xf9a939c6fcae9717,44,True),(1,0xe196de1bc97ab57a,66,True),(10,0xbf7af9a0e99cdb51,44,True),(8,0xe5cada586d49689a,36,None),(9,0x37265c912a43cdac,20,None),(2,0x9f5adc9ee0b3913b,44,True),(3,0xa68765019986f10b,44,True)]
for ty,info,n,auth in stages:
 v=expand(prk,struct.pack('<Q',info),64);prk,child=v[:32],v[32:];k=expand(child,b'',n);b=Path(f'analysis_tls/segment_{ty}.bin').read_bytes()
 Path(f'analysis_tls/segment_{ty}_key.bin').write_bytes(k)
 if auth is True:
  c=ChaCha20_Poly1305.new(key=k[:32],nonce=k[32:44]);p=c.decrypt_and_verify(b[:-16],b[-16:])
 elif auth is False:
  p=crypt(b,k[:32],k[32:44])
 else:continue
 Path(f'analysis_tls/segment_{ty}_plain.bin').write_bytes(p)
 print(ty,'SUCCESS',len(p),p[:24].hex(),flush=True)

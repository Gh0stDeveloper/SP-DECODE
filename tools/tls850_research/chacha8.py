import struct
def rot(v,n):return ((v<<n)|(v>>(32-n)))&0xffffffff
def block(key,nonce,counter):
 st=list(struct.unpack('<4I',b'expand 32-byte k'))+list(struct.unpack('<8I',key))+[counter]+list(struct.unpack('<3I',nonce));x=st.copy()
 def qr(a,b,c,d):
  x[a]=(x[a]+x[b])&0xffffffff;x[d]=rot(x[d]^x[a],16)
  x[c]=(x[c]+x[d])&0xffffffff;x[b]=rot(x[b]^x[c],12)
  x[a]=(x[a]+x[b])&0xffffffff;x[d]=rot(x[d]^x[a],8)
  x[c]=(x[c]+x[d])&0xffffffff;x[b]=rot(x[b]^x[c],7)
 for j in range(4):
  qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15)
  qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14)
 return struct.pack('<16I',*[(v+s)&0xffffffff for v,s in zip(x,st)])
def crypt(data,key,nonce):
 out=bytearray(len(data))
 for offset in range(0,len(data),64):
  k=block(key,nonce,offset//64);out[offset:offset+64]=bytes(v^k[i] for i,v in enumerate(data[offset:offset+64]))
 return bytes(out)
if __name__=='__main__':
 from pathlib import Path
 k=Path('analysis_tls/segment_5_key.bin').read_bytes();b=Path('analysis_tls/segment_5.bin').read_bytes()
 p=crypt(b,k[:32],k[32:]);print('plain',p[:32].hex(),flush=True);Path('analysis_tls/segment_5_plain.bin').write_bytes(p)

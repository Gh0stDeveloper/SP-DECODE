from pathlib import Path
import struct,hmac
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
d=DEX(Path('analysis_tls/classes.dex').read_bytes());parent=next(c for c in d.get_classes() if c.get_name()=='Lcom/tlsvpn/tlstunnel/ProtectedApp;')
method=next(m for m in parent.get_methods() if m.get_name()=='a' and m.get_descriptor()=='([B)[B')
tables=[i.get_data() for i in method.get_code().get_bc().get_instructions() if i.get_name()=='fill-array-data-payload']
b=Path('analysis_tls/libdp_loaded.bin').read_bytes()[4096:];seed=b[0xaa0fc:0xaa11c];seed=bytes(tables[0][tables[1][v]] for v in seed)
words=list(struct.unpack('<8I',seed));r={6:words}
d=DEX(Path('analysis_tls/segment_9.dex').read_bytes());method=next(m for c in d.get_classes() for m in c.get_methods() if m.get_descriptor()=='([I)V')
ins=list(method.get_code().get_bc().get_instructions());start=next(k for k,i in enumerate(ins) if i.get_name()=='aget' and i.get_output()=='v0, v6, v3')-1
for i in ins[start:]:
 n=i.get_name();args=[x[1] for x in i.get_operands()]
 if n.startswith('const'):r[args[0]]=args[1]&0xffffffff
 elif n=='aget':r[args[0]]=r[args[1]][r[args[2]]]
 elif n=='aput':r[args[1]][r[args[2]]]=r[args[0]]
 elif n=='xor-int/2addr':r[args[0]]^=r[args[1]]
 elif n=='add-int/2addr':r[args[0]]=(r[args[0]]+r[args[1]])&0xffffffff
 elif n=='ushr-int/lit8':r[args[0]]=r[args[1]]>>args[2]
 elif n=='shl-int/lit8':r[args[0]]=(r[args[1]]<<args[2])&0xffffffff
 elif n=='or-int':r[args[0]]=r[args[1]]|r[args[2]]
 elif n=='return-void':break
 else:raise ValueError((n,args))
data=struct.pack('<8I',*words);Path('analysis_tls/java_fold.bin').write_bytes(data)
prk=Path('analysis_tls/assets_matching_prk.bin').read_bytes();salt=hmac.digest(prk,struct.pack('<Q',0x07ffcfc433e03432)+b'\1','sha256');prk=hmac.digest(salt,data,'sha256')
Path('analysis_tls/assets_post_java_prk.bin').write_bytes(prk);print('java mix recovered',len(data))

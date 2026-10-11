import struct,sys,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_INTR,UC_HOOK_CODE,UC_HOOK_MEM_INVALID
from unicorn.arm64_const import *
BASE=0x1000000;HEAP=0x4000000;STACK=0x3000000;STOP=0x20000000
class Emulator:
 def __init__(self,path):
  self.path=Path(path);self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u=self.u
  f=ELFFile(self.path.open('rb'));self.f=f;self.allocs=[];self.heap=HEAP;self.imports={}
  u.mem_map(BASE,0x200000);u.mem_map(STACK,0x100000);u.mem_map(HEAP,0x10000000);u.mem_map(STOP,0x1000)
  for seg in f.iter_segments():
   if seg['p_type']=='PT_LOAD':u.mem_write(BASE+seg['p_vaddr'],seg.data())
  syms=f.get_section_by_name('.dynsym')
  for name in ('.rela.dyn','.rela.plt'):
   sec=f.get_section_by_name(name)
   if not sec:continue
   for r in sec.iter_relocations():
    sym=syms.get_symbol(r['r_info_sym']);p=sym['st_value']
    if r['r_info_type']==1027:p=BASE+r['r_addend']
    elif p:p=BASE+p
    else:
     p=STOP+0x100+4*len(self.imports);self.imports[p]=sym.name
    u.mem_write(BASE+r['r_offset'],struct.pack('<Q',p))
  u.hook_add(UC_HOOK_INTR,self.syscall);u.hook_add(UC_HOOK_CODE,self.import_hook,begin=STOP,end=STOP+0xfff)
  u.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
  u.reg_write(UC_ARM64_REG_TPIDR_EL0,STACK+0x100)
 def r(self,i):return self.u.reg_read(UC_ARM64_REG_X0+i)
 def w(self,i,v):self.u.reg_write(UC_ARM64_REG_X0+i,v&((1<<64)-1))
 def read(self,p,n):return bytes(self.u.mem_read(p,n))
 def alloc(self,n):
  p=self.heap;size=(n+4095)&~4095;self.heap+=size;self.allocs.append((p,n));return p
 def ret(self,v=0):self.w(0,v);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def invalid(self,u,k,a,s,v,d):raise RuntimeError(f'invalid {a:x}, PC {u.reg_read(UC_ARM64_REG_PC):x}')
 def syscall(self,u,no,d):
  n=self.r(8);a=[self.r(i) for i in range(6)]
  if n==222:
   v=self.alloc(a[1]);print('mmap',hex(v),hex(a[1]),flush=True)
  elif n in (167,215,226):v=0
  else:raise RuntimeError(f'syscall {n}, PC {u.reg_read(UC_ARM64_REG_PC):x}, args {a}')
  self.w(0,v)
 def import_hook(self,u,a,s,d):
  if a==STOP:u.emu_stop();return
  name=self.imports[a]
  if name=='malloc':self.ret(self.alloc(self.r(0)))
  elif name=='calloc':self.ret(self.alloc(self.r(0)*self.r(1)))
  elif name=='free':self.ret()
  elif name=='memset':
   p=self.r(0);u.mem_write(p,bytes([self.r(1)&255])*self.r(2));self.ret(p)
  elif name=='memmove':
   p=self.r(0);u.mem_write(p,self.read(self.r(1),self.r(2)));self.ret(p)
  else:raise RuntimeError('import '+name)
 def call(self,a,args=()):
  for i,v in enumerate(args):self.w(i,v)
  self.u.reg_write(UC_ARM64_REG_SP,STACK+0xf0000);self.u.reg_write(UC_ARM64_REG_LR,STOP)
  try:self.u.emu_start(BASE+a,STOP,count=100000000)
  except Exception:
   print('error_pc',hex(self.u.reg_read(UC_ARM64_REG_PC)),[hex(self.r(i)) for i in range(6)],flush=True)
   raise
  print('stop_pc',hex(self.u.reg_read(UC_ARM64_REG_PC)),'result',hex(self.r(0)),flush=True)
 def dump(self):
  stem=self.path.stem
  for i,(p,n) in enumerate(self.allocs):
   b=self.read(p,n);out=Path('analysis_tls')/f'{stem}_unpacked_{i}.bin';out.write_bytes(b)
   print('dump',str(out),hex(p),n,'magic',b[:8].hex(),flush=True)
  Path('analysis_tls',stem+'_allocs.json').write_text(json.dumps(self.allocs))
if __name__=='__main__':
 e=Emulator('analysis_tls/libdexprotector.so')
 aux=e.alloc(4096);debug=e.alloc(4096);fn=e.alloc(4096)
 e.u.mem_write(fn,bytes.fromhex('c0035fd6'))
 e.u.mem_write(debug+16,struct.pack('<Q',fn))
 e.u.hook_add(UC_HOOK_CODE,lambda u,a,s,d:e.ret(aux),begin=BASE+0x2240,end=BASE+0x2240)
 e.u.hook_add(UC_HOOK_CODE,lambda u,a,s,d:e.ret(debug),begin=BASE+0x2378,end=BASE+0x2378)
 def reloc(u,a,s,d):
  print('runtime_reloc',*[hex(e.r(i)) for i in range(4)],flush=True)
  Path('analysis_tls/libdp_loaded.bin').write_bytes(e.read(e.allocs[-1][0],e.allocs[-1][1]))
  base=e.r(1);dyn=e.r(0);D={}
  for o in range(0,4096,16):
   t,v=struct.unpack('<QQ',e.read(dyn+o,16))
   if not t:break
   D[t]=v
  cursor=0
  def relative(va):
   value=struct.unpack('<Q',e.read(base+va,8))[0]
   u.mem_write(base+va,struct.pack('<Q',base+value))
  for o in range(0,D[35],8):
   entry=struct.unpack('<Q',e.read(base+D[36]+o,8))[0]
   if not entry&1:relative(entry);cursor=entry+8
   else:
    for bit in range(1,64):
     if entry&(1<<bit):relative(cursor+(bit-1)*8)
    cursor+=63*8
  for o in range(0,D[2],24):
   va,info,add=struct.unpack('<QQq',e.read(base+D[23]+o,24));index=info>>32
   nameoff=struct.unpack('<I',e.read(base+D[6]+index*24,4))[0]
   name=e.read(base+D[5]+nameoff,128).split(b'\0')[0].decode()
   p=STOP+0x100+4*len(e.imports);e.imports[p]=name;u.mem_write(base+va,struct.pack('<Q',p))
  # The original resolver erases symbol, relocation and string metadata.
  u.mem_write(base+D[6],bytes(D[5]+D[10]-D[6]))
  u.mem_write(base+D[23],bytes(D[2]))
  u.mem_write(base+D[36],bytes(D[35]))
  e.runtime_base=base;e.runtime_D=D
  e.ret(1)
 e.u.hook_add(UC_HOOK_CODE,reloc,begin=BASE+0x169c,end=BASE+0x169c)
 def ctor(u,a,s,d):
  print('runtime_ctor',hex(e.r(8)),flush=True)
 e.u.hook_add(UC_HOOK_CODE,ctor,begin=BASE+0x25d0,end=BASE+0x25d0)
 try:
  e.call(0x380)
  Path('analysis_tls/libdp_initialized.bin').write_bytes(e.read(e.allocs[3][0],e.allocs[3][1]))
  print('JNI_Load_entry',hex(struct.unpack('<Q',e.read(BASE+0xb250,8))[0]))
 finally:e.dump()

import sys, re, os
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
def names(p):
    e=Elf(p); out=set()
    for s in ('.rodata','.data'):
        sec=e.sec(s)
        if not sec: continue
        for m in re.finditer(rb'[A-Z][A-Za-z0-9_]{5,45}', e.secdata(sec)):
            out.add(m.group().decode())
    return out
o=names(sys.argv[1]); n=names(sys.argv[2])
kw=('Thermostat','Setpoint','Program','Heat','Valve','Temperature','Boiler','Scene','Zwave','Dhw','Otgw','Otherm','Info','Get','Set')
def interesting(s): return any(k.lower() in s.lower() for k in kw)
oo=sorted(x for x in (o-n) if interesting(x))
nn=sorted(x for x in (n-o) if interesting(x))
print(f"=== identifier-like strings only in OLD ({len(oo)}) ===")
for x in oo: print("  "+x)
print(f"\n=== only in NEW ({len(nn)}) - first 40 ===")
for x in nn[:40]: print("  "+x)

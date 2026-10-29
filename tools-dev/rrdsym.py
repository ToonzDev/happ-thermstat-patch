import sys, re, os
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
def fnames(p):
    e=Elf(p); out=set()
    for s in e.symbols_full(".symtab"):
        if s["type"]==2:
            out.add(re.sub(r"\.\d+$","",s["name"]))   # drop .NNNN local suffixes
    return out
o=fnames(sys.argv[1]); n=fnames(sys.argv[2])
key=lambda s: ("rrd" in s.lower() or "htbl" in s.lower() or "logger" in s.lower())
print("=== rrd/htbl functions: OLD only ===")
for x in sorted(o-n):
    if key(x): print("   "+x)
print("=== rrd/htbl functions: NEW only ===")
for x in sorted(n-o):
    if key(x): print("   "+x)
print("=== rrd/htbl functions present in BOTH ===")
for x in sorted(o&n):
    if key(x): print("   "+x)

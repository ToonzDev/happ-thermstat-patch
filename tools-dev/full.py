import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
def s(p):
    d=Elf(p).data
    return set(m.group().decode() for m in re.finditer(rb'thermstat_[A-Za-z0-9_]+', d))
o=s(sys.argv[1]); n=s(sys.argv[2])
print(f"OLD count={len(o)}  NEW count={len(n)}")
print("\n### lowercase-style logger names (thermstat_<lower>...) ###")
lo=sorted(x for x in o if x[10:11].islower())
ln=sorted(x for x in n if x[10:11].islower())
print(f"OLD has {len(lo)}, NEW has {len(ln)}")
print("\n-- in OLD but NOT in NEW --")
for x in sorted(set(lo)-set(ln)): print("   "+x)
print("\n-- in BOTH --")
for x in sorted(set(lo)&set(ln)): print("   "+x)
print("\n-- NEW lowercase only --")
for x in sorted(set(ln)-set(lo)): print("   "+x)

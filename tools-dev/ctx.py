import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
for label,p in (("OLD",sys.argv[1]),("NEW",sys.argv[2])):
    d=Elf(p).data
    print(f"=== {label}: strings containing 'thermstat_' ===")
    hits=sorted(set(m.group().decode() for m in re.finditer(rb'[A-Za-z0-9_]*thermstat_[A-Za-z0-9_]*', d)))
    for h in hits: print("   "+h)
    print(f"--- {label}: bytes around 'boilerRetTemp' / 'boilerTemp' ---")
    for pat in (b'boilerRetTemp', b'boilerTemp'):
        for m in re.finditer(re.escape(pat), d):
            s=max(0,m.start()-120); e=min(len(d),m.end()+120)
            ctx=re.sub(rb'[^\x20-\x7e]+', b' | ', d[s:e]).decode('ascii','C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re')
            print(f"   @0x{m.start():x}: {ctx}")
    print()

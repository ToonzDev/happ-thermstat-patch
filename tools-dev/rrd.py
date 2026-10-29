import sys, re, os
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
pats = [rb'boiler[A-Za-z]*', rb'[Bb]oilerInTemp', rb'[Bb]oilerOutTemp', rb'rrd[A-Za-z_]*', rb'RRD[A-Za-z_]*',
        rb'de_[A-Za-z_]*[Rr]rd[A-Za-z_]*', rb'htbl[A-Za-z_]*', rb'Tret[A-Za-z]*', rb'Tboiler[A-Za-z]*']
for label, p in (("OLD", sys.argv[1]), ("NEW", sys.argv[2])):
    e = Elf(p); d = e.data; found = {}
    for pat in pats:
        for m in re.finditer(pat, d):
            s = m.group().decode('ascii','C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re')
            if len(s) > 3: found[s] = found.get(s,0)+1
    print(f"=== {label} ({os.path.basename(p)}) ===")
    for s in sorted(found): print(f"   {found[s]:3}x  {s}")
    print()

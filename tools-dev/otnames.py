import sys, re, os
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
for label,p in (("r2404",sys.argv[1]),("r2426",sys.argv[2])):
    d=Elf(p).data
    hits=sorted(set(m.group().decode() for m in re.finditer(rb'\b(TBoiler|Tret|Tr|TrSet|TdhwSet|MaxTSet|Tboiler|TBoiler2|Tflow|Treturn)\b', d)))
    print(f"{label}: OT id name strings -> {hits}")

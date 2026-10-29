import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
for label,p in (("OLD",sys.argv[1]),("NEW",sys.argv[2])):
    d=Elf(p).data
    hits=set()
    for pat in (rb'Current[A-Za-z]*Temp[A-Za-z]*', rb'[A-Za-z]*ReturnTemp[A-Za-z]*', rb'ThermostatInfo', rb'BoilerInfo'):
        for m in re.finditer(pat,d): hits.add(m.group().decode())
    print(f"=== {label} ===")
    for h in sorted(hits): print("   "+h)

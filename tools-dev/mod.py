import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
d=Elf(sys.argv[1]).data
for pat in (rb'Current[A-Za-z]*Modulation[A-Za-z]*', rb'[A-Za-z]*ModLevel[A-Za-z]*', rb'CurrentSetpoint', rb'CurrentTemp[A-Za-z]*'):
    for m in sorted(set(x.group() for x in re.finditer(pat,d))):
        print("   "+m.decode())

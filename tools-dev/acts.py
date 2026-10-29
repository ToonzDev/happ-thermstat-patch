import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
e=Elf(sys.argv[1]); sec=e.sec(".rodata"); d=e.secdata(sec)
acts=set()
for m in re.finditer(rb'(get|set|Get|Set)[A-Z][A-Za-z0-9]{3,40}', d):
    acts.add(m.group().decode())
print("=== action-like names in NEW .rodata ===")
for a in sorted(acts): print("   "+a)

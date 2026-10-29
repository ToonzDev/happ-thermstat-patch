import sys, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
for label,p in (("OLD",sys.argv[1]),("NEW",sys.argv[2])):
    d=Elf(p).data
    print(f"########## {label}: context of thermstat_boilerTemp ##########")
    for m in re.finditer(rb'thermstat_boilerTemp\x00', d):
        s=max(0,m.start()-300); e=min(len(d),m.end()+300)
        ctx=re.sub(rb'\x00+', b' | ', d[s:e]).decode('ascii','C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re')
        print(f"  @0x{m.start():x}:\n    {ctx}\n")

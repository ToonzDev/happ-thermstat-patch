import sys, re, os
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
d=Elf(sys.argv[1]).data
for needle in (b'BoilerInfo\x00', b'BoilerStatus\x00'):
    for m in re.finditer(re.escape(needle), d):
        s=max(0,m.start()-500); e=min(len(d),m.end()+500)
        ctx=re.sub(rb'\x00+', b' | ', d[s:e]).decode('ascii','C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re')
        ctx=re.sub(r'\x1b\[[0-9;]*m','',ctx)
        print(f"[{needle[:-1].decode()}] @0x{m.start():x}\n   {ctx}\n")

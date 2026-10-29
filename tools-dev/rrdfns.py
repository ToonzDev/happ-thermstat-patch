import sys, os, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from elfinfo import Elf
from diffsyms import demangle
for p,lbl in ((sys.argv[1],"r2429"),):
    e=Elf(p)
    want=("rrd_checkUuids","rrd_checkDevUuid","rrd_initDevicesByIntAddr","rrd_createDevice",
          "rrd_createMissing","rrd_initDevice","rrd_changeuuid","rrd_getRrdDeviceByKey",
          "rrd_init","rrd_queryLastKnownValues","rrd_configCheckRras","rrd_removeUnused")
    print(f"{lbl}:")
    for s in e.symbols_full(".symtab"):
        n=re.sub(r"\.\d+$","",demangle(s["name"]))
        if s["type"]==2 and n in want and s["value"]:
            print(f"   {n:<28} @0x{s['value']&~1:x} size={s['size']}")

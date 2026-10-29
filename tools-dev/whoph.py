import sys, os, re
sys.path.insert(0, r"C:\\Users\\joop_\\AppData\\Local\\Temp\\claude\\c--Users-joop--Documents--Toon-Root-boardgames\\605f4234-8da3-4117-b184-aebf7e14c62e\\scratchpad\\re")
from pcrel import Scan
s = Scan(sys.argv[1], "r2429")
idx = {}
for fn, a, st in s.refs():
    idx.setdefault(st, set()).add(fn)
for k in ("placeholder", "thermostatSettings", "hcb_rrd"):
    print(f"  {k!r:<24} -> {sorted(idx.get(k, set()))}")

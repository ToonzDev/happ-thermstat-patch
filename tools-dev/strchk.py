import sys, os
sys.path.insert(0, r"C:\\Users\\joop_\\Documents\\_Toon_Root\\happ_thermstat_re\\tools")
from xref import Img
img = Img(sys.argv[1])
for s in ("avg","year","last","30days","5yrhours"):
    vas = img.string_va(s)
    print(f"  {s!r:<12} copies={len(vas)}  {[hex(v) for v in vas]}")

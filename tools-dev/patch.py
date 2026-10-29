import sys, os, struct, shutil, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import Img

BASE = 0x146660
ENTRY = 0x4c
TEMPLATE = 7          # slot to clone: thermstat_boilerChPressure (double, 30days, 60/43200)
TARGETS = [
    (10, 'thermstat_boilerTemp',    'CurrentBoilerTemperature'),
    (11, 'thermstat_boilerRetTemp', 'CurrentBoilerReturnTemperature'),
]
OFF_NAME, OFF_VAR = 0x00, 0x0c

src, dst = sys.argv[1], sys.argv[2]
shutil.copyfile(src, dst)

img = Img(src)
data = bytearray(open(dst, 'rb').read())

def one_va(text):
    vas = img.string_va(text)
    if len(vas) != 1:
        raise SystemExit(f"expected exactly 1 copy of {text!r}, found {len(vas)}")
    return vas[0]

def off_of(va):
    o = img.va2off(va)
    if o is None:
        raise SystemExit(f"address 0x{va:x} not mapped to file")
    return o

tmpl_off = off_of(BASE + TEMPLATE * ENTRY)
template = bytes(data[tmpl_off:tmpl_off + ENTRY])
print(f"template = slot {TEMPLATE} @0x{BASE + TEMPLATE*ENTRY:x} ({len(template)} bytes)")

changed = []
for slot, logger, devvar in TARGETS:
    E = BASE + slot * ENTRY
    o = off_of(E)
    before = bytes(data[o:o + ENTRY])
    data[o:o + ENTRY] = template                       # clone a known-good entry
    lv, vv = one_va(logger), one_va(devvar)
    struct.pack_into('<I', data, o + OFF_NAME, lv)     # then set identity
    struct.pack_into('<I', data, o + OFF_VAR, vv)
    after = bytes(data[o:o + ENTRY])
    n = sum(1 for a, b in zip(before, after) if a != b)
    changed.append((slot, E, o, n))
    print(f"slot {slot} @0x{E:x} (file 0x{o:x}): name->0x{lv:x} {logger}, var->0x{vv:x} {devvar}  [{n} bytes differ]")

open(dst, 'wb').write(bytes(data))

orig = open(src, 'rb').read()
new = open(dst, 'rb').read()
assert len(orig) == len(new), "size changed!"
diff = [i for i in range(len(orig)) if orig[i] != new[i]]
lo, hi = (min(diff), max(diff)) if diff else (0, 0)
print(f"\ntotal bytes changed: {len(diff)}  file range 0x{lo:x}..0x{hi:x}")
allowed = set()
for _s, _E, o, _n in changed:
    allowed |= set(range(o, o + ENTRY))
stray = [i for i in diff if i not in allowed]
print(f"changes outside the two target slots: {len(stray)}  {'OK' if not stray else 'PROBLEM'}")
print(f"size: {len(new)} bytes (unchanged)")
print(f"md5 orig {hashlib.md5(orig).hexdigest()}")
print(f"md5 new  {hashlib.md5(new).hexdigest()}")

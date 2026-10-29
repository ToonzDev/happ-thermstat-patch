"""Build-independent patcher: restore thermstat_boilerTemp / thermstat_boilerRetTemp
by repurposing two ventilationHeatRecoveryDev slots in rrdDevices.

Locates everything by symbol/name, so it works on any happ_thermstat build that has
the trimmed table. Refuses to run if anything is not exactly as expected.
"""
import sys, os, struct, shutil, hashlib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr

ENTRY = 0x4c
OFF_NAME, OFF_PKG, OFF_VAR, OFF_SVC, OFF_TYPE = 0x00, 0x04, 0x0c, 0x10, 0x14

TEMPLATE_NAME = 'thermstat_boilerChPressure'
TARGETS = [
    ('ventilationHeatRecoveryDev.ActiveElectricityHours', 'thermstat_boilerTemp',    'CurrentBoilerTemperature'),
    ('ventilationHeatRecoveryDev.CurrentState',           'thermstat_boilerRetTemp', 'CurrentBoilerReturnTemperature'),
]

src, dst = sys.argv[1], sys.argv[2]
e = Elf(src)
img = Img(src)

ver = [m.group().decode() for m in re.finditer(rb'VERSION\[[^\]]{0,120}\]', img.d)]
print(f"source : {os.path.basename(src)}  {len(img.d):,} bytes")
print(f"version: {ver[0] if ver else '?'}")

base = size = None
for s in e.symbols_full('.symtab'):
    if s['name'] == 'rrdDevices' and s['value']:
        base, size = s['value'], s['size']
if base is None:
    raise SystemExit("rrdDevices symbol not found - refusing to patch")
nslots = size // ENTRY
off0 = img.va2off(base)
print(f"rrdDevices @ 0x{base:x} size={size} -> {nslots} slots")

def slot_name(i):
    o = off0 + i * ENTRY
    (w,) = struct.unpack_from('<I', img.d, o + OFF_NAME)
    return cstr(img, w)

names = {slot_name(i): i for i in range(nslots)}

def one_va(text):
    vas = img.string_va(text)
    if len(vas) != 1:
        raise SystemExit(f"expected exactly 1 copy of {text!r}, found {len(vas)} - refusing")
    return vas[0]

if TEMPLATE_NAME not in names:
    raise SystemExit(f"template slot {TEMPLATE_NAME!r} not present - refusing")
tmpl_i = names[TEMPLATE_NAME]
tmpl_off = off0 + tmpl_i * ENTRY

data = bytearray(img.d)
template = bytes(data[tmpl_off:tmpl_off + ENTRY])
print(f"template: slot {tmpl_i} ({TEMPLATE_NAME})")

touched = []
for victim, logger, devvar in TARGETS:
    if victim not in names:
        raise SystemExit(f"victim slot {victim!r} not present - refusing")
    i = names[victim]
    o = off0 + i * ENTRY
    lv, vv = one_va(logger), one_va(devvar)
    before = bytes(data[o:o + ENTRY])
    data[o:o + ENTRY] = template
    struct.pack_into('<I', data, o + OFF_NAME, lv)
    struct.pack_into('<I', data, o + OFF_VAR, vv)
    nd = sum(1 for a, b in zip(before, bytes(data[o:o + ENTRY])) if a != b)
    touched.append((i, o))
    print(f"  slot {i}: {victim}")
    print(f"        -> {logger} (0x{lv:x}) / {devvar} (0x{vv:x})   [{nd} bytes differ]")

open(dst, 'wb').write(bytes(data))

orig, new = img.d, open(dst, 'rb').read()
assert len(orig) == len(new), "size changed - aborting"
diff = [i for i in range(len(orig)) if orig[i] != new[i]]
allowed = set()
for _i, o in touched:
    allowed |= set(range(o, o + ENTRY))
stray = [i for i in diff if i not in allowed]
print(f"\nbytes changed : {len(diff)}  (range 0x{min(diff):x}..0x{max(diff):x})")
print(f"outside slots : {len(stray)}  {'OK' if not stray else 'PROBLEM'}")
print(f"size          : {len(new)} (unchanged)")
print(f"md5 stock     : {hashlib.md5(orig).hexdigest()}")
print(f"md5 patched   : {hashlib.md5(new).hexdigest()}")

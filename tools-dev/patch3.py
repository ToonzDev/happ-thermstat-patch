"""Patch v3: restore thermstat_boilerTemp / thermstat_boilerRetTemp AND give them
the real deviceUuid, so hcb_rrd binds them to the actual thermostat device instead
of the literal "placeholder" (which rrd_removeUnused culls).

usage: patch3.py <stock.bin> <out.bin> <device-uuid> <dead-string-va-hex>
"""
import sys, os, struct, hashlib, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr

ENTRY = 0x4c
OFF_NAME, OFF_PKG, OFF_UUID, OFF_VAR = 0x00, 0x04, 0x08, 0x0c
TEMPLATE = 'thermstat_boilerChPressure'
TARGETS = [
    ('ventilationHeatRecoveryDev.ActiveElectricityHours', 'thermstat_boilerTemp',    'CurrentBoilerTemperature'),
    ('ventilationHeatRecoveryDev.CurrentState',           'thermstat_boilerRetTemp', 'CurrentBoilerReturnTemperature'),
]

src, dst, devuuid, deadva = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 16)
if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', devuuid):
    raise SystemExit(f"{devuuid!r} is not a uuid")

e, img = Elf(src), Img(src)
data = bytearray(img.d)

ver = re.search(rb'VERSION\[[^\]]{0,120}\]', img.d)
print(f"source : {os.path.basename(src)}  {len(data):,} bytes")
print(f"version: {ver.group().decode() if ver else '?'}")

base = size = None
for s in e.symbols_full('.symtab'):
    if s['name'] == 'rrdDevices' and s['value']:
        base, size = s['value'], s['size']
if base is None:
    raise SystemExit("rrdDevices not found")
nslots = size // ENTRY
off0 = img.va2off(base)
print(f"rrdDevices @ 0x{base:x} -> {nslots} slots")

def one_va(t):
    v = img.string_va(t)
    if len(v) != 1:
        raise SystemExit(f"expected 1 copy of {t!r}, got {len(v)}")
    return v[0]

names = {}
for i in range(nslots):
    (w,) = struct.unpack_from('<I', img.d, off0 + i * ENTRY + OFF_NAME)
    names[cstr(img, w)] = i

# --- 1. write the uuid into dead space ---
deadoff = img.va2off(deadva)
if deadoff is None:
    raise SystemExit("dead address not mapped")
old = cstr(img, deadva, 200)
if old is None:
    raise SystemExit("no string at the dead address - refusing")
if len(old) < len(devuuid):
    raise SystemExit(f"dead string too short ({len(old)} < {len(devuuid)})")
print(f"dead string @0x{deadva:x} len={len(old)}: {old[:70]!r}")
data[deadoff:deadoff + len(devuuid) + 1] = devuuid.encode() + b'\x00'
print(f"  -> overwritten with {devuuid!r} (+NUL), {len(old)-len(devuuid)} bytes of it left as slack")

# --- 2. clone template, set name / deviceUuid / deviceVar ---
tmpl = bytes(data[off0 + names[TEMPLATE] * ENTRY:][:ENTRY])
touched = []
for victim, logger, devvar in TARGETS:
    if victim not in names:
        raise SystemExit(f"victim {victim!r} not present")
    i = names[victim]
    o = off0 + i * ENTRY
    data[o:o + ENTRY] = tmpl
    struct.pack_into('<I', data, o + OFF_NAME, one_va(logger))
    struct.pack_into('<I', data, o + OFF_VAR, one_va(devvar))
    struct.pack_into('<I', data, o + OFF_UUID, deadva)
    touched.append((i, o))
    print(f"  slot {i}: {victim}  ->  {logger} / {devvar} / deviceUuid=0x{deadva:x}")

open(dst, 'wb').write(bytes(data))

new = open(dst, 'rb').read()
assert len(new) == len(img.d)
diff = [i for i in range(len(new)) if new[i] != img.d[i]]
allowed = set(range(deadoff, deadoff + len(devuuid) + 1))
for _i, o in touched:
    allowed |= set(range(o, o + ENTRY))
stray = [i for i in diff if i not in allowed]
print(f"\nbytes changed: {len(diff)}   outside intended regions: {len(stray)} {'OK' if not stray else 'PROBLEM'}")
print(f"size {len(new)} (unchanged)")
print(f"md5 stock   {hashlib.md5(img.d).hexdigest()}")
print(f"md5 patched {hashlib.md5(new).hexdigest()}")

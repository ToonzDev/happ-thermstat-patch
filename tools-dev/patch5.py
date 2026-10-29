"""Patch v5 = v4 + stop the loggers being deleted again.

v4 restored the two rrdDevices entries and gave them the real deviceUuid, but
happ_thermstat also carries a hardcoded "remove these loggers" list which
rrd_removeUnused walks on every device-discovery event, sending RemoveRrd for
any of those names that exist. thermstat_boilerTemp and thermstat_boilerRetTemp
are in that list, so they were recreated and deleted every ~18 s.

This additionally repoints those two list entries at an empty string, so the
lookup fails and they are never added to the RemoveRrd message.

usage: patch5.py <stock.bin> <out.bin> <device-uuid> <dead-va-hex>
"""
import sys, os, re, struct, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr
from diffsyms import demangle
from capstone import *

ENTRY = 0x4c
OFF_NAME, OFF_VAR = 0x00, 0x0c
TEMPLATE = 'thermstat_boilerChPressure'
TARGETS = [
    ('ventilationHeatRecoveryDev.ActiveElectricityHours', 'thermstat_boilerTemp',    'CurrentBoilerTemperature'),
    ('ventilationHeatRecoveryDev.CurrentState',           'thermstat_boilerRetTemp', 'CurrentBoilerReturnTemperature'),
]

src, dst, devuuid, deadva = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 16)
if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', devuuid):
    raise SystemExit("not a uuid")

e, img = Elf(src), Img(src)
data = bytearray(img.d)
regions = []

ver = re.search(rb'VERSION\[[^\]]{0,120}\]', img.d)
print(f"source : {os.path.basename(src)}   {ver.group().decode() if ver else '?'}")

def one_va(t):
    v = img.string_va(t)
    if len(v) != 1:
        raise SystemExit(f"expected 1 copy of {t!r}, got {len(v)}")
    return v[0]

# ---- 1. uuid into dead space -------------------------------------------------
deadoff = img.va2off(deadva)
old = cstr(img, deadva, 200)
if old is None or len(old) < len(devuuid):
    raise SystemExit("dead string unusable")
data[deadoff:deadoff + len(devuuid) + 1] = devuuid.encode() + b'\x00'
regions.append((deadoff, len(devuuid) + 1))
print(f"uuid written at 0x{deadva:x}")

# an empty string = the NUL terminator of any existing string
empty_va = one_va(TEMPLATE) + len(TEMPLATE)
_eo = img.va2off(empty_va)
if _eo is None or img.d[_eo] != 0:
    raise SystemExit("could not locate an empty string (NUL terminator)")
print(f"empty string at 0x{empty_va:x}")

# ---- 2. rrdDevices entries ---------------------------------------------------
base = size = None
for s in e.symbols_full('.symtab'):
    if s['name'] == 'rrdDevices' and s['value']:
        base, size = s['value'], s['size']
off0 = img.va2off(base)
names = {}
for i in range(size // ENTRY):
    (w,) = struct.unpack_from('<I', img.d, off0 + i * ENTRY)
    names[cstr(img, w)] = i
tmpl = bytes(data[off0 + names[TEMPLATE] * ENTRY:][:ENTRY])
for victim, logger, devvar in TARGETS:
    o = off0 + names[victim] * ENTRY
    data[o:o + ENTRY] = tmpl
    struct.pack_into('<I', data, o + OFF_NAME, one_va(logger))
    struct.pack_into('<I', data, o + OFF_VAR, one_va(devvar))
    regions.append((o, ENTRY))
    print(f"slot {names[victim]} -> {logger}")

# ---- 3. deviceUuid fallback in rrd_createMissing ------------------------------
raw = fsize = None
for s in e.symbols_full('.symtab'):
    if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == 'rrd_createMissing' and s['value']:
        raw, fsize = s['value'], s['size']
addr, thumb = raw & ~1, bool(raw & 1)
foff = img.va2off(addr)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
ph, regs, fixed = one_va('placeholder'), {}, 0
for i in md.disasm(img.d[foff:foff + fsize], addr):
    m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
    if i.mnemonic.startswith('ldr') and m:
        imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
        regs[m.group(1)] = i.address + (4 if thumb else 8) + imm
        continue
    m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
    if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
        po = img.va2off(regs[m2.group(2)])
        (lit,) = struct.unpack_from('<I', img.d, po)
        if i.address + (4 if thumb else 8) + lit == ph and m2.group(1) == 'r3':
            struct.pack_into('<I', data, po, (deadva - i.address - (4 if thumb else 8)) & 0xffffffff)
            regions.append((po, 4))
            fixed += 1
if fixed != 1:
    raise SystemExit(f"deviceUuid fallback: patched {fixed}, expected 1")
print("deviceUuid fallback redirected")

# ---- 4. neutralise the two entries in the removal list ------------------------
removed = 0
for logger in ('thermstat_boilerTemp', 'thermstat_boilerRetTemp'):
    va = one_va(logger)
    pat = struct.pack('<I', va)
    for m in re.finditer(re.escape(pat), bytes(data)):
        o = m.start()
        v = img.off2va(o)
        if v is None:
            continue
        # skip the rrdDevices entry we just wrote
        if base <= v < base + size:
            continue
        struct.pack_into('<I', data, o, empty_va)
        regions.append((o, 4))
        removed += 1
        print(f"removal-list entry at 0x{v:x} ({logger}) -> empty string")
if removed != 2:
    raise SystemExit(f"removal list: neutralised {removed}, expected 2 - refusing")

open(dst, 'wb').write(bytes(data))
new = open(dst, 'rb').read()
assert len(new) == len(img.d)
diff = [i for i in range(len(new)) if new[i] != img.d[i]]
allowed = set()
for o, n in regions:
    allowed |= set(range(o, o + n))
stray = [i for i in diff if i not in allowed]
print(f"\nbytes changed {len(diff)}   outside intended {len(stray)} {'OK' if not stray else 'PROBLEM'}")
print(f"md5 stock   {hashlib.md5(img.d).hexdigest()}")
print(f"md5 patched {hashlib.md5(new).hexdigest()}")

"""Patch v6 = v5 + restore the 'year' RRA on the two boiler loggers.

An rrdDevices entry is 0x4c bytes: a 0x20 header, then TWO 0x14 RRA slots, then a
4-byte terminator.

    rra[0] @ E+0x20 : futureBins, binLength, bins, consolidator*, name*
    rra[1] @ E+0x34 : futureBins, binLength, bins, consolidator*, name*
            E+0x48 : 0 terminator

r2404 defined both (30days 60/43200 "last", year 3600/8765 "avg"); r2426/r2429 zero
the whole second slot. This fills it back in. The strings "avg" and "year" no longer
exist in the newer builds, so they are written into the same dead .rodata block that
holds the device uuid.

usage: patch6.py <stock.bin> <out.bin> <device-uuid> <dead-va-hex>
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
RRA1, RRA2, TERM = 0x20, 0x34, 0x48
TEMPLATE = 'thermstat_boilerChPressure'
TARGETS = [
    ('ventilationHeatRecoveryDev.ActiveElectricityHours', 'thermstat_boilerTemp',    'CurrentBoilerTemperature'),
    ('ventilationHeatRecoveryDev.CurrentState',           'thermstat_boilerRetTemp', 'CurrentBoilerReturnTemperature'),
]
YEAR_BINLEN, YEAR_BINS = 3600, 8765          # exactly what r2404 used

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

# ---- 1. dead block: uuid, then "avg" and "year" ------------------------------
deadoff = img.va2off(deadva)
old = cstr(img, deadva, 300)
need = 40 + 8 + 8
if old is None or len(old) < need:
    raise SystemExit(f"dead string too short: need {need}, have {0 if old is None else len(old)}")

def put(rel, text):
    off = deadoff + rel
    data[off:off + len(text) + 1] = text.encode() + b'\x00'
    regions.append((off, len(text) + 1))
    return deadva + rel

put(0, devuuid)
avg_va = put(40, 'avg')
year_va = put(48, 'year')
print(f"dead block 0x{deadva:x} ({len(old)} B): uuid@+0, 'avg'@+40 (0x{avg_va:x}), 'year'@+48 (0x{year_va:x})")

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

# sanity: the template must have rra[0] populated and rra[1] empty
to = off0 + names[TEMPLATE] * ENTRY
if struct.unpack_from('<I', img.d, to + RRA1 + 4)[0] != 60:
    raise SystemExit("template rra[0].binLength is not 60 - layout changed, refusing")
if any(struct.unpack_from('<I', img.d, to + RRA2 + k)[0] for k in (0, 4, 8, 12, 16)):
    raise SystemExit("template rra[1] is not empty - layout changed, refusing")

tmpl = bytes(data[to:to + ENTRY])
for victim, logger, devvar in TARGETS:
    o = off0 + names[victim] * ENTRY
    data[o:o + ENTRY] = tmpl
    struct.pack_into('<I', data, o + OFF_NAME, one_va(logger))
    struct.pack_into('<I', data, o + OFF_VAR, one_va(devvar))
    # rra[1] = the year archive
    struct.pack_into('<I', data, o + RRA2 + 0, 0)               # futureBins
    struct.pack_into('<I', data, o + RRA2 + 4, YEAR_BINLEN)
    struct.pack_into('<I', data, o + RRA2 + 8, YEAR_BINS)
    struct.pack_into('<I', data, o + RRA2 + 12, avg_va)
    struct.pack_into('<I', data, o + RRA2 + 16, year_va)
    struct.pack_into('<I', data, o + TERM, 0)                   # terminator
    regions.append((o, ENTRY))
    print(f"slot {names[victim]} -> {logger}  (+ year rra {YEAR_BINLEN}/{YEAR_BINS} avg)")

# ---- 3. deviceUuid fallback in rrd_createMissing -------------------------------
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

# ---- 4. neutralise the hardcoded removal-list entries --------------------------
empty_va = one_va(TEMPLATE) + len(TEMPLATE)
if img.d[img.va2off(empty_va)] != 0:
    raise SystemExit("no empty string found")
removed = 0
for logger in ('thermstat_boilerTemp', 'thermstat_boilerRetTemp'):
    pat = struct.pack('<I', one_va(logger))
    for m in re.finditer(re.escape(pat), bytes(data)):
        v = img.off2va(m.start())
        if v is None or (base <= v < base + size):
            continue
        struct.pack_into('<I', data, m.start(), empty_va)
        regions.append((m.start(), 4))
        removed += 1
        print(f"removal-list entry 0x{v:x} ({logger}) -> empty")
if removed != 2:
    raise SystemExit(f"removal list: {removed}, expected 2")

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

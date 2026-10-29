"""Toon 1 (qb2, ARMv5 soft-float) variant of patch6.py.

Steps 1, 2 and 4 are byte-identical to patch6.py and apply unmodified to this
build. Step 3 needed adapting: the Toon 2 build materialises the
'placeholder' fallback address once, directly into r3, immediately before
the call to rrd_createDevice ('add r3, pc, rX'). This Toon 1 build's
rrd_createMissing (happ_thermstat v0.1 r2427, master#67cc2fd682) computes
the SAME address (confirmed: both resolve to the exact 'placeholder' string
VA) but does it twice, into two different stack-spilled locals ('add r7, pc,
ip' -> [fp,#-0x40], and 'add sl, pc, sb' -> [fp,#-0x30]), of which only the
second is later loaded and passed as rrd_createDevice's 4th argument (the
deviceUuid fallback). The first is very likely dead/unused for our purposes,
but there is no harm in redirecting both: they currently compute to the same
address, so redirecting both to our injected real uuid is safe either way.

So this version relaxes patch6.py's step-3 match from "exactly one
'add r3, pc, rX'" to "every 'add rX, pc, rY' (any destination register)
that resolves to the placeholder address", and patches all of them.

usage: patch6_toon1.py <stock.bin> <out.bin> <device-uuid> <dead-va-hex>
"""
import sys, os, re, struct, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tools'))
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
YEAR_BINLEN, YEAR_BINS = 3600, 8765

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
    struct.pack_into('<I', data, o + RRA2 + 0, 0)
    struct.pack_into('<I', data, o + RRA2 + 4, YEAR_BINLEN)
    struct.pack_into('<I', data, o + RRA2 + 8, YEAR_BINS)
    struct.pack_into('<I', data, o + RRA2 + 12, avg_va)
    struct.pack_into('<I', data, o + RRA2 + 16, year_va)
    struct.pack_into('<I', data, o + TERM, 0)
    regions.append((o, ENTRY))
    print(f"slot {names[victim]} -> {logger}  (+ year rra {YEAR_BINLEN}/{YEAR_BINS} avg)")

# ---- 3. deviceUuid fallback in rrd_createMissing (Toon 1: patch ALL matches) --
raw = fsize = None
for s in e.symbols_full('.symtab'):
    if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == 'rrd_createMissing' and s['value']:
        raw, fsize = s['value'], s['size']
addr, thumb = raw & ~1, bool(raw & 1)
foff = img.va2off(addr)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
ph, lastlit, fixed = one_va('placeholder'), {}, 0
for i in md.disasm(img.d[foff:foff + fsize], addr):
    m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
    if i.mnemonic.startswith('ldr') and m:
        imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
        litaddr = i.address + (4 if thumb else 8) + imm
        litoff = img.va2off(litaddr)
        if litoff is not None:
            (litval,) = struct.unpack_from('<I', img.d, litoff)
            lastlit[m.group(1)] = (litaddr, litval)
        continue
    m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
    if i.mnemonic.startswith('add') and m2 and m2.group(2) in lastlit:
        litaddr, litval = lastlit[m2.group(2)]
        pc = i.address + (4 if thumb else 8)
        if (pc + litval) & 0xffffffff == ph:
            po = img.va2off(litaddr)
            struct.pack_into('<I', data, po, (deadva - pc) & 0xffffffff)
            regions.append((po, 4))
            fixed += 1
            print(f"  deviceUuid fallback redirected: 0x{i.address:x} {i.mnemonic} {i.op_str}"
                  f"  (literal pool @0x{litaddr:x})")
if fixed < 1:
    raise SystemExit("deviceUuid fallback: patched 0, expected at least 1")
print(f"deviceUuid fallback redirected ({fixed} occurrence(s))")

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

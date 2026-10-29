"""Patch v4 = v2 table restore + redirect the deviceUuid fallback.

rrd_createMissing passes the literal "placeholder" as the deviceUuid when the
device lookup yields nothing, and hcb_rrd then cannot bind the logger (and
rrd_removeUnused culls it). This writes the real device uuid into dead .rodata
space and repoints the fallback's literal-pool word at it.

usage: patch4.py <stock.bin> <out.bin> <device-uuid> <dead-va-hex>
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

def one_va(t):
    v = img.string_va(t)
    if len(v) != 1:
        raise SystemExit(f"expected 1 copy of {t!r}, got {len(v)}")
    return v[0]

# ---------- 1. uuid into dead space ----------
deadoff = img.va2off(deadva)
old = cstr(img, deadva, 200)
if old is None or len(old) < len(devuuid):
    raise SystemExit("dead string unusable")
data[deadoff:deadoff + len(devuuid) + 1] = devuuid.encode() + b'\x00'
print(f"uuid written at 0x{deadva:x} (was {old[:48]!r})")

# ---------- 2. table entries ----------
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
regions = [(deadoff, len(devuuid) + 1)]
for victim, logger, devvar in TARGETS:
    o = off0 + names[victim] * ENTRY
    data[o:o + ENTRY] = tmpl
    struct.pack_into('<I', data, o + OFF_NAME, one_va(logger))
    struct.pack_into('<I', data, o + OFF_VAR, one_va(devvar))
    regions.append((o, ENTRY))
    print(f"slot {names[victim]}: -> {logger} / {devvar}")

# ---------- 3. redirect the fallback literal in rrd_createMissing ----------
raw = size2 = None
for s in e.symbols_full('.symtab'):
    if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == 'rrd_createMissing' and s['value']:
        raw, size2 = s['value'], s['size']
addr, thumb = raw & ~1, bool(raw & 1)
foff = img.va2off(addr)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
insns = list(md.disasm(img.d[foff:foff + size2], addr))

ph = one_va('placeholder')
regs, fixed = {}, 0
for i in insns:
    m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
    if i.mnemonic.startswith('ldr') and m:
        imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
        pool = i.address + (4 if thumb else 8) + imm
        regs[m.group(1)] = pool
        continue
    m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
    if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
        pool = regs[m2.group(2)]
        po = img.va2off(pool)
        (lit,) = struct.unpack_from('<I', img.d, po)
        target = i.address + (4 if thumb else 8) + lit
        if target == ph and m2.group(1) == 'r3':      # the deviceUuid fallback
            newlit = (deadva - i.address - (4 if thumb else 8)) & 0xffffffff
            struct.pack_into('<I', data, po, newlit)
            regions.append((po, 4))
            print(f"fallback at 0x{i.address:x} (add {m2.group(1)}, pc, {m2.group(2)}): "
                  f"pool 0x{pool:x} 0x{lit:x} -> 0x{newlit:x}  (now resolves to the uuid)")
            fixed += 1
if fixed != 1:
    raise SystemExit(f"expected exactly 1 r3 placeholder fallback, patched {fixed} - refusing")

open(dst, 'wb').write(bytes(data))
new = open(dst, 'rb').read()
assert len(new) == len(img.d)
diff = [i for i in range(len(new)) if new[i] != img.d[i]]
allowed = set()
for o, n in regions:
    allowed |= set(range(o, o + n))
stray = [i for i in diff if i not in allowed]
print(f"\nbytes changed {len(diff)}  outside intended {len(stray)} {'OK' if not stray else 'PROBLEM'}")
print(f"md5 stock   {hashlib.md5(img.d).hexdigest()}")
print(f"md5 patched {hashlib.md5(new).hexdigest()}")

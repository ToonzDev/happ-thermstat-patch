"""Find .rodata strings of at least N chars that nothing references, checking
BOTH absolute-address literals and the pc-relative (ldr offset + add pc) idiom."""
import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

MINLEN = 40

path = sys.argv[1]
e = Elf(path)
img = Img(path)
sec = e.sec('.rodata')
d = e.secdata(sec)
base = sec['addr']

# candidate strings
cands = {}
for m in re.finditer(rb'[\x20-\x7e]{%d,}\x00' % MINLEN, d):
    va = base + m.start()
    cands[va] = m.group()[:-1].decode()
print(f"candidate strings >= {MINLEN} chars in .rodata: {len(cands)}")

# 1. absolute references anywhere in the file
abs_ref = set()
for va in cands:
    if re.search(re.escape(struct.pack('<I', va)), img.d):
        abs_ref.add(va)
print(f"  referenced by absolute literal: {len(abs_ref)}")

# 2. pc-relative references
fns = []
for s in e.symbols_full('.symtab'):
    if s['type'] == 2 and s['value'] and s['size']:
        fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size']))
pcr = set()
def word(va):
    o = img.va2off(va)
    return None if o is None or o + 4 > len(img.d) else struct.unpack_from('<I', img.d, o)[0]

for addr, thumb, size in fns:
    if size > 60000:
        continue
    off = img.va2off(addr)
    if off is None:
        continue
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    buf = img.d[off:off + size]
    regs, pos, step = {}, 0, (2 if thumb else 4)
    while pos < len(buf):
        got = False
        for i in md.disasm(buf[pos:], addr + pos):
            got = True; pos += i.size
            m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
            if i.mnemonic.startswith('ldr') and m:
                imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
                v = word(i.address + (4 if thumb else 8) + imm)
                if v is not None:
                    regs[m.group(1)] = v
                continue
            m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
            if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
                pcr.add((i.address + (4 if thumb else 8) + regs[m2.group(2)]) & 0xffffffff)
        if not got:
            pos += step
print(f"  pc-relative targets collected: {len(pcr)}")

dead = []
for va, s in cands.items():
    if va in abs_ref:
        continue
    # a pc-relative reference may land anywhere inside the string
    if any(va <= t <= va + len(s) for t in pcr):
        continue
    dead.append((va, s))
dead.sort(key=lambda t: -len(t[1]))
print(f"\nUNREFERENCED candidates: {len(dead)}")
for va, s in dead[:12]:
    print(f"  0x{va:x}  len={len(s):<4} {s[:96]!r}")

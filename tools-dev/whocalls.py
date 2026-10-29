import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

TARGETS = set(sys.argv[2].split(','))

e = Elf(sys.argv[1])
img = Img(sys.argv[1])
fns, taddr = [], {}
for s in e.symbols_full('.symtab'):
    if s['type'] == 2 and s['value']:
        n = re.sub(r'\.\d+$', '', demangle(s['name']))
        if n in TARGETS:
            taddr[s['value'] & ~1] = n
        if s['size']:
            fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size'], n))
fns.sort()

hits = {}
for addr, thumb, size, name in fns:
    if size > 60000:
        continue
    off = img.va2off(addr)
    if off is None:
        continue
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    buf = img.d[off:off + size]
    pos, step = 0, (2 if thumb else 4)
    while pos < len(buf):
        got = False
        for i in md.disasm(buf[pos:], addr + pos):
            got = True; pos += i.size
            if i.mnemonic.startswith('b'):
                m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
                if m:
                    t = int(m.group(1), 16) & ~1
                    if t in taddr:
                        hits.setdefault(taddr[t], []).append((name, i.address, i.mnemonic))
        if not got:
            pos += step

for t in sorted(TARGETS):
    lst = hits.get(t, [])
    print(f"\n=== callers of {t} ({len(lst)}) ===")
    for n, a, mn in lst:
        print(f"   {n:<34} 0x{a:x}  ({mn})")

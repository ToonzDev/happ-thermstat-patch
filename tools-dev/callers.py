import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

TARGETS = ['svar_setValue', 'svar_create', 'createSvar_double', 'createSvar_int',
           'svar_setPostNotifyHandler']

def build(path):
    e = Elf(path)
    img = Img(path)
    fns = []
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value']:
            fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size'],
                        re.sub(r'\.\d+$', '', demangle(s['name']))))
    fns.sort()
    byaddr = {a: n for a, _t, _s, n in fns}
    return e, img, fns, byaddr

def callers_of(path, targets):
    e, img, fns, byaddr = build(path)
    taddr = {}
    for a, _t, _s, n in fns:
        if n in targets:
            taddr[a] = n
    found = {}
    for a, thumb, size, name in fns:
        if not size or size > 60000:
            continue
        off = img.va2off(a)
        if off is None:
            continue
        code = img.d[off:off + size]
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        for i in md.disasm(code, a):
            if i.mnemonic.startswith('bl'):
                m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
                if m:
                    t = int(m.group(1), 16) & ~1
                    if t in taddr:
                        found.setdefault(taddr[t], set()).add(name)
    return found

def allfuncs(path):
    e = Elf(path)
    return set(re.sub(r'\.\d+$', '', demangle(s['name']))
               for s in e.symbols_full('.symtab') if s['type'] == 2 and s['value'])

old, new = sys.argv[1], sys.argv[2]
print("=== callers of svar/createSvar helpers ===")
co = callers_of(old, TARGETS)
cn = callers_of(new, TARGETS)
for t in TARGETS:
    so, sn = co.get(t, set()), cn.get(t, set())
    print(f"\n-- {t}")
    print(f"   r2404 callers ({len(so)}): {sorted(so)}")
    print(f"   r2426 callers ({len(sn)}): {sorted(sn)}")
    if so - sn:
        print(f"   *** lost in r2426: {sorted(so - sn)}")
    if sn - so:
        print(f"   +++ new in r2426: {sorted(sn - so)}")

fo, fn = allfuncs(old), allfuncs(new)
gone = sorted(fo - fn)
print(f"\n=== functions in r2404 but NOT in r2426 ({len(gone)}) ===")
for g in gone:
    print("   " + g)

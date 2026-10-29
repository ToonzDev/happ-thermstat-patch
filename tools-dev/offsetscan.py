"""Find every access to the cached svar handles at struct offsets 0x170 / 0x174
(CurrentBoilerTemperature / CurrentBoilerReturnTemperature) and report whether a
svar_setValue follows - i.e. who WRITES those variables."""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

OFFS = (0x170, 0x174)
WINDOW = 12

def scan(path, label):
    e = Elf(path)
    img = Img(path)
    setval = None
    fns = []
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value']:
            n = re.sub(r'\.\d+$', '', demangle(s['name']))
            if n == 'svar_setValue':
                setval = s['value'] & ~1
            if s['size']:
                fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size'], n))
    fns.sort()
    print(f"\n########## {label}  (svar_setValue @0x{setval:x}) ##########")
    results = []
    for addr, thumb, size, name in fns:
        if size > 60000:
            continue
        off = img.va2off(addr)
        if off is None:
            continue
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        insns = []
        pos, step = 0, (2 if thumb else 4)
        while pos < len(img.d[off:off + size]):
            got = False
            for i in md.disasm(img.d[off + pos:off + size], addr + pos):
                insns.append(i); pos += i.size; got = True
            if not got:
                pos += step
        for k, i in enumerate(insns):
            m = re.match(r'^(\w+), \[(\w+), #(0x[0-9a-f]+)\]$', i.op_str)
            if not (i.mnemonic == 'ldr' and m):
                continue
            o = int(m.group(3), 16)
            if o not in OFFS:
                continue
            follow = insns[k:k + WINDOW]
            has_set = any(j.mnemonic.startswith('bl') and
                          re.match(r'^#?(0x[0-9a-f]+)$', j.op_str.strip()) and
                          (int(j.op_str.strip().lstrip('#'), 16) & ~1) == setval
                          for j in follow)
            results.append((name, i.address, o, has_set))
    writers = [r for r in results if r[3]]
    print(f"  accesses to 0x170/0x174: {len(results)}   of which followed by svar_setValue: {len(writers)}")
    for name, a, o, _ in writers:
        print(f"    WRITER  {name:<34} at 0x{a:x}  offset 0x{o:x}")
    others = {}
    for name, a, o, has in results:
        if not has:
            others.setdefault(name, []).append(o)
    if others:
        print("  other accesses (no immediate setValue):")
        for n, os_ in sorted(others.items()):
            print(f"    {n:<34} offsets {[hex(x) for x in sorted(set(os_))]}")
    return set(n for n, _a, _o, _h in writers)

w1 = scan(sys.argv[1], 'r2404')
w2 = scan(sys.argv[2], 'r2426')
print("\n" + "=" * 70)
print(f"writers in r2404 : {sorted(w1)}")
print(f"writers in r2426 : {sorted(w2)}")
print(f"*** LOST in r2426: {sorted(w1 - w2)}")
print(f"    new in r2426 : {sorted(w2 - w1)}")

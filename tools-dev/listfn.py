import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fdiff import Func
from table import cstr

def pcrel(f, i, regs):
    m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
    if i.mnemonic.startswith('ldr') and m:
        imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
        v = f.word(i.address + (4 if f.thumb else 8) + imm)
        if v is not None:
            regs[m.group(1)] = v
        return None
    m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
    if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
        t = i.address + (4 if f.thumb else 8) + regs[m2.group(2)]
        s = cstr(f.img, t & 0xffffffff, 80)
        return f'"{s}"' if s else f"data 0x{t:x}"
    return None

fname = sys.argv[1]
for lbl, p in (('r2404', sys.argv[2]), ('r2426', sys.argv[3])):
    f = Func(p, fname, lbl)
    print(f"\n{'='*76}\n{lbl}: {fname} @0x{f.addr:x} size={f.size} insns={len(f.insns)}\n{'='*76}")
    regs = {}
    for i in f.insns:
        ann = pcrel(f, i, regs) or f.describe(i)
        print(f"  0x{i.address:x}  {i.mnemonic:<9} {i.op_str:<34} {ann}")

import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fdiff import Func
from table import cstr

def annotate(f):
    """return list of (insn, annotation) with pc-relative strings resolved"""
    regs, out = {}, []
    for i in f.insns:
        ann = None
        m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
        if i.mnemonic.startswith('ldr') and m:
            imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
            v = f.word(i.address + (4 if f.thumb else 8) + imm)
            if v is not None:
                regs[m.group(1)] = v
        else:
            m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
            if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
                t = i.address + (4 if f.thumb else 8) + regs[m2.group(2)]
                s = cstr(f.img, t & 0xffffffff, 80)
                ann = f'"{s}"' if s else None
        out.append((i, ann or f.describe(i)))
    return out

fname = sys.argv[1]
needle = sys.argv[2]
for lbl, p in (('r2404', sys.argv[3]), ('r2426', sys.argv[4])):
    f = Func(p, fname, lbl)
    ann = annotate(f)
    hits = [k for k, (i, a) in enumerate(ann) if needle in (a or '')]
    print(f"\n{'='*78}\n{lbl}: {fname} @0x{f.addr:x} size={f.size} insns={len(f.insns)}"
          f"  -- {len(hits)} hit(s) for {needle!r}\n{'='*78}")
    for k in hits:
        lo, hi = max(0, k - 10), min(len(ann), k + 14)
        print(f"\n  --- around 0x{ann[k][0].address:x} ---")
        for i, a in ann[lo:hi]:
            mark = '>>' if i.address == ann[k][0].address else '  '
            print(f"  {mark} 0x{i.address:x}  {i.mnemonic:<9} {i.op_str:<30} {a}")

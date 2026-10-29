import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

def find_func(e, name):
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == name and s['value']:
            return s['value'], s['size']
    return None, None

def disasm(path, fname):
    e = Elf(path)
    img = Img(path)
    raw, size = find_func(e, fname)
    if raw is None:
        print(f"  {fname}: not found")
        return None
    thumb = bool(raw & 1)
    addr = raw & ~1
    off = img.va2off(addr)
    code = img.d[off:off + size]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
    md.detail = True
    insns = list(md.disasm(code, addr))
    print(f"  {fname} @0x{addr:x} size={size} mode={'THUMB' if thumb else 'ARM'} insns={len(insns)}")
    return dict(img=img, e=e, insns=insns, addr=addr, size=size)

def imm_set(insns, mnem_pat=r'^(cmp|cmn|subs?|teq)'):
    """immediates used in comparisons - i.e. candidate OpenTherm data IDs"""
    out = {}
    for i in insns:
        if re.match(mnem_pat, i.mnemonic):
            for m in re.finditer(r'#(0x[0-9a-f]+|\d+)', i.op_str):
                v = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
                if 0 <= v <= 255:
                    out.setdefault(v, []).append(f"0x{i.address:x} {i.mnemonic} {i.op_str}")
    return out

def calls(insns, img, e):
    names = {}
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value']:
            names[s['value'] & ~1] = re.sub(r'\.\d+$', '', demangle(s['name']))
    out = []
    for i in insns:
        if i.mnemonic.startswith('bl'):
            m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
            if m:
                t = int(m.group(1), 16)
                out.append((i.address, t, names.get(t & ~1, '?')))
    return out

if __name__ == '__main__':
    fname = sys.argv[1]
    res = {}
    for p in sys.argv[2:]:
        lbl = os.path.basename(p)
        print(f"########## {lbl} ##########")
        r = disasm(p, fname)
        if r:
            res[lbl] = r
        print()
    labels = list(res)
    if len(labels) == 2:
        a, b = labels
        ia, ib = imm_set(res[a]['insns']), imm_set(res[b]['insns'])
        print("=" * 64)
        print(f"comparison immediates 0..255 in {a}: {sorted(ia)}")
        print(f"comparison immediates 0..255 in {b}: {sorted(ib)}")
        print(f"\nonly in {a}: {sorted(set(ia) - set(ib))}")
        print(f"only in {b}: {sorted(set(ib) - set(ia))}")
        for v in (25, 28, 0x19, 0x1c):
            pa = 'yes' if v in ia else 'NO'
            pb = 'yes' if v in ib else 'NO'
            print(f"  OT id {v:3}: {a}={pa}  {b}={pb}")
        for lbl in labels:
            c = calls(res[lbl]['insns'], res[lbl]['img'], res[lbl]['e'])
            named = {}
            for _a, _t, n in c:
                named[n] = named.get(n, 0) + 1
            print(f"\ncalls made by {lbl} ({len(c)} total):")
            for n, k in sorted(named.items(), key=lambda kv: -kv[1])[:18]:
                print(f"   {k:4}x {n}")

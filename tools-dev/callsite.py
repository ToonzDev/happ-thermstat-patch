"""Inspect call sites of a given callee inside a given function, with literal
resolution, so we can see which svar handle is being passed."""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fdiff import Func

def calls_summary(f):
    out = {}
    for i in f.insns:
        if i.mnemonic.startswith('bl'):
            m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
            if m:
                n = f.name_of(int(m.group(1), 16)) or f"local_{int(m.group(1),16):x}"
                out[n] = out.get(n, 0) + 1
    return out

def windows(f, callee, before=16, after=3):
    idx = []
    for k, i in enumerate(f.insns):
        if i.mnemonic.startswith('bl'):
            m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
            if m and (f.name_of(int(m.group(1), 16)) == callee):
                idx.append(k)
    print(f"\n### {f.label}: {len(idx)} call(s) to {callee} in this function")
    for k in idx:
        print(f"\n  --- call at 0x{f.insns[k].address:x} ---")
        for i in f.insns[max(0, k - before):k + 1 + after]:
            mark = '>>' if i.address == f.insns[k].address else '  '
            print(f"  {mark} 0x{i.address:x}  {i.mnemonic:<9} {i.op_str:<32} {f.describe(i)}")

fname, callee = sys.argv[1], sys.argv[2]
for lbl, p in (('r2404', sys.argv[3]), ('r2426', sys.argv[4])):
    f = Func(p, fname, lbl)
    print(f"\n{'='*74}\n{lbl}: {fname} @0x{f.addr:x} size={f.size} insns={len(f.insns)}")
    cs = calls_summary(f)
    print("  resolved calls: " + ", ".join(f"{v}x {k}" for k, v in
          sorted(cs.items(), key=lambda kv: -kv[1]) if not k.startswith('local_')))
    windows(f, callee)

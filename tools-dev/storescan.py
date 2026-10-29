"""Who writes the struct fields +0x148 / +0x150 (the boiler flow/return
temperature values that updateStatevars publishes)?"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle
from capstone import *

OFFS = (0x148, 0x150)

def scan(path, label):
    e = Elf(path)
    img = Img(path)
    fns = []
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value'] and s['size']:
            fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size'],
                        re.sub(r'\.\d+$', '', demangle(s['name']))))
    fns.sort()
    stores, loads = {}, {}
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
                m = re.search(r'\[(\w+), #(0x[0-9a-f]+)\]', i.op_str)
                if not m:
                    continue
                o = int(m.group(2), 16)
                if o not in OFFS:
                    continue
                mn = i.mnemonic
                if mn.startswith(('str', 'vstr', 'vstm', 'stm')):
                    stores.setdefault(name, []).append((i.address, o, mn, i.op_str))
                elif mn.startswith(('ldr', 'vldr', 'ldm', 'vldm')):
                    loads.setdefault(name, []).append((i.address, o, mn, i.op_str))
            if not got:
                pos += step
    print(f"\n########## {label} ##########")
    print(f"  STORES to +0x148/+0x150 ({sum(len(v) for v in stores.values())} in {len(stores)} functions):")
    for n in sorted(stores):
        for a, o, mn, ops in stores[n]:
            print(f"    {n:<34} 0x{a:x}  {mn:<7} {ops}")
    print(f"  loads ({sum(len(v) for v in loads.values())} in {len(loads)} functions):")
    for n in sorted(loads):
        offs = sorted(set(hex(o) for _a, o, _m, _p in loads[n]))
        print(f"    {n:<34} {offs}")
    return set(stores), set(loads)

s1, l1 = scan(sys.argv[1], 'r2404')
s2, l2 = scan(sys.argv[2], 'r2426')
print("\n" + "=" * 72)
print(f"functions STORING these fields, r2404: {sorted(s1)}")
print(f"functions STORING these fields, r2426: {sorted(s2)}")
print(f"*** STORE LOST in r2426: {sorted(s1 - s2)}")
print(f"    store new in r2426 : {sorted(s2 - s1)}")

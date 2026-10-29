import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr

def find_obj(path, label, addrs):
    e = Elf(path)
    img = Img(path)
    objs = [s for s in e.symbols_full('.symtab') if s['type'] == 1 and s['value']]
    print(f"########## {label} ##########")
    for a in addrs:
        hit = [o for o in objs if o['value'] <= a < o['value'] + max(o['size'], 1)]
        if hit:
            for o in hit:
                n = o['size'] // 0x4c
                print(f"  0x{a:x} is inside object '{o['name']}'"
                      f"  base=0x{o['value']:x} size={o['size']} ({o['size']:#x})"
                      f"  -> {n} entries of 0x4c" + (f" + {o['size'] % 0x4c} bytes spare" if o['size'] % 0x4c else ""))
        else:
            print(f"  0x{a:x}: no object symbol covers it")
            near = sorted(objs, key=lambda o: abs(o['value'] - a))[:3]
            for o in near:
                print(f"      nearby: '{o['name']}' base=0x{o['value']:x} size={o['size']}")
    # what section is it in, and what follows
    for a in addrs:
        for s in e.sections:
            if s['addr'] and s['addr'] <= a < s['addr'] + s['size']:
                print(f"  0x{a:x} lives in section {s['name']}"
                      f" (addr 0x{s['addr']:x}, size {s['size']}, ends 0x{s['addr']+s['size']:x})")
                break
    print()

find_obj(sys.argv[1], "OLD r2404", [0x70f84, 0x71100])
find_obj(sys.argv[2], "NEW r2429", [0x146630, 0x1467ac])

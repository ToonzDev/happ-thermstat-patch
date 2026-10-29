import sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

old = Elf(sys.argv[1])
new = Elf(sys.argv[2])

def vstr(e):
    d = e.data
    return [m.group().decode() for m in re.finditer(rb'VERSION\[[^\]]{0,120}\]', d)]

print("=== version strings ===")
print("  old:", vstr(old))
print("  new:", vstr(new))

print("\n=== new: smartdistrictheating symbols ===")
for name, val, size, typ, bind in new.symbols('.symtab'):
    d = demangle(name)
    if 'smartdistrictheating' in d.lower() or 'smartdistrict' in name.lower():
        if typ == 2:
            print(f"  {size:6}  {d}")

print("\n=== old: district-heating related strings (context) ===")
pats = [rb'[\x20-\x7e]*[Hh]eat[Vv]alve[\x20-\x7e]*', rb'[\x20-\x7e]*Qubino[\x20-\x7e]*',
        rb'[\x20-\x7e]*SourceTemp[\x20-\x7e]*', rb'[\x20-\x7e]*[Dd]istrict[\x20-\x7e]*']
seen = set()
for p in pats:
    for m in re.finditer(p, old.data):
        s = m.group().decode('ascii', 'replace').strip()
        if len(s) > 3 and s not in seen:
            seen.add(s)
for s in sorted(seen):
    print("  " + repr(s))

print("\n=== old binary: undefined dynamic symbols (must be provided by libs) ===")
undef = []
for name, val, size, typ, bind in old.symbols('.dynsym'):
    if val == 0 and typ in (0, 1, 2):
        undef.append(name)
undef = sorted(set(undef))
print(f"  count = {len(undef)}")
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'old_undef.txt'), 'w').write("\n".join(undef))
hcb = [u for u in undef if 'hcb' in u.lower() or u.startswith(('de_', 'hc_', 'bt_', 'com_'))]
print(f"  hcb-ish  = {len(hcb)}")
print("  sample:", ", ".join(hcb[:15]))

import sys, os, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf

here = os.path.dirname(os.path.abspath(__file__))

def undef_all(path):
    """every undefined entry in .dynsym, whatever its type/binding"""
    e = Elf(path)
    out = set()
    for name, val, size, typ, bind in e.symbols('.dynsym'):
        if val == 0:
            out.add(name.split('@')[0])
    return out

def defined(path):
    e = Elf(path)
    out = set()
    for name, val, size, typ, bind in e.symbols('.dynsym'):
        if val != 0:
            out.add(name.split('@')[0])
    return out

oldbin, newbin = sys.argv[1], sys.argv[2]

need_old = undef_all(oldbin)
need_new = undef_all(newbin)
print(f"undefined .dynsym entries:  old={len(need_old)}  new={len(need_new)}")

have = {}
for l in sorted(glob.glob(os.path.join(here, 'libs', '*.so.1'))):
    have[os.path.basename(l)] = defined(l)

allhave = set()
for v in have.values():
    allhave |= v

# Which of the old binary's imports are satisfied by the CURRENT libhcb set?
hcb_like = lambda s: (s.startswith(('de_', 'hc_', 'bt_', 'com_', 'ez', 'hcb', 'qmf', 'drv_', 'base_'))
                      or 'hcb' in s.lower())

old_hcb = sorted(s for s in need_old if hcb_like(s))
new_hcb = sorted(s for s in need_new if hcb_like(s))
print(f"hcb/qmf-style imports:      old={len(old_hcb)}  new={len(new_hcb)}")

missing_old = [s for s in old_hcb if s not in allhave]
missing_new = [s for s in new_hcb if s not in allhave]

print(f"\nold binary hcb imports NOT exported by current libs: {len(missing_old)}")
for s in missing_old:
    print("   MISSING " + s)
print(f"\n(control) new binary hcb imports NOT exported: {len(missing_new)}")
for s in missing_new:
    print("   MISSING " + s)

# does the old binary import anything the new one does not? those are the risky ones
only_old = sorted(s for s in need_old if s not in need_new)
print(f"\nimports the OLD binary uses that the NEW one does not ({len(only_old)}):")
for s in only_old:
    mark = "ok " if s in allhave else "?? "
    if hcb_like(s):
        mark = "HCB-" + ("ok" if s in allhave else "MISSING")
    print(f"   [{mark}] {s}")

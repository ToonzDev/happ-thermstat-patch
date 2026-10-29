import sys, os, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf

here = os.path.dirname(os.path.abspath(__file__))
SHN_UNDEF = 0

def imports(path):
    """symbols the file needs from elsewhere: .dynsym entries with st_shndx == SHN_UNDEF"""
    e = Elf(path)
    out = set()
    for s in e.symbols_full('.dynsym'):
        if s['shndx'] == SHN_UNDEF and s['bind'] != 2:      # skip WEAK (optional)
            out.add(s['name'].split('@')[0])
    return out

def exports(path):
    e = Elf(path)
    out = set()
    for s in e.symbols_full('.dynsym'):
        if s['shndx'] != SHN_UNDEF:
            out.add(s['name'].split('@')[0])
    return out

oldbin, newbin = sys.argv[1], sys.argv[2]
need_old, need_new = imports(oldbin), imports(newbin)
print(f"imports:  old={len(need_old)}   new={len(need_new)}")

have = {}
for l in sorted(glob.glob(os.path.join(here, 'libs', '*.so.1'))):
    have[os.path.basename(l)] = exports(l)
allhcb = set()
for k, v in have.items():
    print(f"  {k:<24} exports {len(v)}")
    allhcb |= v

# hcb symbols the old binary needs, and whether today's libs still have them
old_from_hcb = sorted(s for s in need_old if s in allhcb)
print(f"\nold binary imports satisfied by current libhcb set: {len(old_from_hcb)}")

# the real risk: hcb-looking imports that today's libs do NOT provide
def hcb_like(s):
    return (s.startswith(('de_', 'hc_', 'bt_', 'com_', 'ez', 'hcb', 'qmf', 'drv_'))
            or 'hcb' in s.lower() or 'boxtalk' in s.lower())

unresolved_hcbish = sorted(s for s in need_old if hcb_like(s) and s not in allhcb)
print(f"hcb-style imports NOT provided by current libs:     {len(unresolved_hcbish)}")
for s in unresolved_hcbish:
    print("   MISSING " + s)

only_old = sorted(s for s in need_old if s not in need_new)
print(f"\nimports the OLD build needs that the NEW build does not ({len(only_old)}):")
for s in only_old:
    where = [k for k, v in have.items() if s in v]
    tag = ("libhcb:" + ",".join(w.replace('libhcb_','').replace('.so.1','') for w in where)) if where else "system/other"
    print(f"   {s:<45} {tag}")

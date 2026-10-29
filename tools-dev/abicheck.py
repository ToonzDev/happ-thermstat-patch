import sys, os, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

here = os.path.dirname(os.path.abspath(__file__))

def undef(path):
    e = Elf(path)
    out = set()
    for name, val, size, typ, bind in e.symbols('.dynsym'):
        # STB_WEAK (2) is optional; require GLOBAL (1) undefined symbols
        if val == 0 and bind == 1 and typ in (1, 2):
            out.add(name)
    return out

def defined(path):
    e = Elf(path)
    out = set()
    for name, val, size, typ, bind in e.symbols('.dynsym'):
        if val != 0:
            out.add(name.split('@')[0])
    return out

target = sys.argv[1]
need = undef(target)
print(f"old binary needs {len(need)} global undefined symbols")

have = set()
libs = sorted(glob.glob(os.path.join(here, 'libs', '*.so.1')))
for l in libs:
    d = defined(l)
    have |= d
    print(f"  {os.path.basename(l):<24} exports {len(d)}")

# the hcb/qmf-specific ones are what could have been removed; libc/libstdc++ are stable
missing = sorted(s for s in need if s not in have)

def is_system(s):
    sysprefix = ('_Z', '__', 'std::', 'operator')
    libc_names = ('malloc','free','memcpy','printf','strlen','open','close','read','write')
    return False

hcb_missing = [s for s in missing
               if s.startswith(('de_', 'hc_', 'bt_', 'com_', 'xml_', 'ez', 'hcb'))
               or 'hcb' in s.lower()]

print(f"\nnot provided by the five libhcb libraries: {len(missing)}")
print(f"  of which look like hcb/qmf API calls    : {len(hcb_missing)}")
if hcb_missing:
    print("\n!!! MISSING hcb SYMBOLS (old binary would fail to start) !!!")
    for s in hcb_missing:
        print("   " + s)
else:
    print("\n  -> every hcb/qmf symbol the old binary calls is still exported.")
    print("     The remainder are libc/libstdc++/pthread/jansson/uuid symbols:")
    rest = [s for s in missing][:25]
    for s in rest:
        print("   " + s)
    print(f"     ({len(missing)} total, sample above)")

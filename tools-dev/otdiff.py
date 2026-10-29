import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle

PAT = re.compile(r'otherm|opentherm|\bot[_A-Z]|boilertemp|rettemp|svar|tboiler|tret',
                 re.I)

def funcs(path):
    e = Elf(path)
    out = {}
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value']:
            out[re.sub(r'\.\d+$', '', demangle(s['name']))] = (s['value'] & ~1, s['size'])
    return out

def show(path, label):
    f = funcs(path)
    hits = {k: v for k, v in f.items() if PAT.search(k)}
    print(f"########## {label}: {len(hits)} matching functions ##########")
    for k in sorted(hits):
        a, sz = hits[k]
        print(f"  0x{a:08x} +{sz:<6} {k}")
    print()
    return f

old = show(sys.argv[1], "OLD r2404")
new = show(sys.argv[2], "r2426 (.18)")

ko = {k for k in old if PAT.search(k)}
kn = {k for k in new if PAT.search(k)}
print("=" * 60)
print("matching funcs only in OLD:")
for k in sorted(ko - kn):
    print(f"   {k}")
print("\nmatching funcs only in r2426:")
for k in sorted(kn - ko):
    print(f"   {k}")

# who references the removed diagnostic strings in OLD?
img = Img(sys.argv[1])
print("\n--- OLD: function containing 'OpenTherm ID %d is not supported' ---")
for s in ['OpenTherm ID %d is not supported by the boiler!',
          'OpenTherm ID is processed with the wrong type: %d']:
    for va in img.string_va(s):
        for hva, fn in img.xrefs(va):
            print(f"   {s[:40]!r} ref 0x{hva:x} in {demangle(fn) if fn else '?'}")

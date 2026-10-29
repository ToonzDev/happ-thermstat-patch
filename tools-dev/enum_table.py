import sys, os, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import Img
from table import cstr

ENTRY = 0x4c          # size of one rrd logger definition struct
OFF_NAME = 0x30
OFF_PKG  = 0x34       # -> "thermostatSettings", used as the anchor
OFF_PLC  = 0x38
OFF_VAR  = 0x3c
OFF_SVC  = 0x40
OFF_TYPE = 0x44

def enumerate_table(path, label):
    img = Img(path)
    anchors = img.string_va('thermostatSettings')
    if not anchors:
        print(f"{label}: anchor string not found")
        return {}
    print(f"########## {label} ##########")
    print(f"  anchor 'thermostatSettings' at {[hex(a) for a in anchors]}")
    entries = {}
    for a in anchors:
        for hva, _fn in img.xrefs(a):
            base = hva - OFF_PKG
            off = img.va2off(base)
            if off is None:
                continue
            def p(o):
                (w,) = struct.unpack_from('<I', img.d, off + o)
                return w
            name = cstr(img, p(OFF_NAME))
            if not name or not name.startswith('thermstat_'):
                continue
            var = cstr(img, p(OFF_VAR))
            svc = cstr(img, p(OFF_SVC))
            typ = cstr(img, p(OFF_TYPE))
            rra1 = cstr(img, p(0x14))
            rra2 = cstr(img, p(0x28))
            entries[name] = dict(base=base, var=var, svc=svc, type=typ,
                                 rra=(rra1, rra2))
    print(f"  entries found: {len(entries)}\n")
    for n in sorted(entries):
        e = entries[n]
        rr = "+".join(x for x in e['rra'] if x)
        print(f"  0x{e['base']:08x}  {n:<40} var={e['var']:<32} svc={e['svc']} [{rr}]")
    print()
    return entries

old = enumerate_table(sys.argv[1], "OLD r2404")
new = enumerate_table(sys.argv[2], "NEW r2429")

print("=" * 78)
print("in OLD definition table but NOT in NEW:")
for n in sorted(set(old) - set(new)):
    print(f"   {n:<40} (var was {old[n]['var']})")
print("\nin NEW but not in OLD:")
for n in sorted(set(new) - set(old)):
    print(f"   {n:<40} var={new[n]['var']}")

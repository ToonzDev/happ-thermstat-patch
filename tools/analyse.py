"""Locate rrdDevices in any happ_thermstat build and list its slots."""
import sys, os, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr

ENTRY = 0x4c

def find_array(e):
    for s in e.symbols_full('.symtab'):
        if s['name'] == 'rrdDevices' and s['value']:
            return s['value'], s['size']
    return None, None

def analyse(path):
    e = Elf(path)
    img = Img(path)
    ver = [m.group().decode() for m in re.finditer(rb'VERSION\[[^\]]{0,120}\]', img.d)]
    print(f"=== {os.path.basename(path)} ===")
    print(f"  size    : {len(img.d):,}")
    print(f"  version : {ver}")
    base, size = find_array(e)
    if not base:
        print("  rrdDevices: NOT FOUND")
        return None
    n = size // ENTRY
    print(f"  rrdDevices @ 0x{base:x}  size={size} -> {n} slots"
          + (f"  (+{size % ENTRY} spare bytes)" if size % ENTRY else ""))
    off0 = img.va2off(base)
    slots = []
    for i in range(n):
        o = off0 + i * ENTRY
        w = lambda k: struct.unpack_from('<I', img.d, o + k)[0]
        name = cstr(img, w(0x00))
        pkg = cstr(img, w(0x04))
        var = cstr(img, w(0x0c))
        svc = cstr(img, w(0x10))
        typ = cstr(img, w(0x14))
        binl, bins = w(0x24), w(0x28)
        rra = cstr(img, w(0x30))
        slots.append(dict(i=i, va=base + i * ENTRY, name=name, pkg=pkg, var=var,
                          svc=svc, type=typ, binl=binl, bins=bins, rra=rra))
        print(f"  [{i:2}] 0x{base+i*ENTRY:08x} {name}")
        print(f"        pkg={pkg} var={var} svc={svc} type={typ} rra={rra} {binl}/{bins}")
    # what's immediately after the array?
    objs = sorted([s for s in e.symbols_full('.symtab') if s['type'] == 1 and s['value']],
                  key=lambda s: s['value'])
    nxt = [o for o in objs if o['value'] >= base + size]
    if nxt:
        print(f"  next object: '{nxt[0]['name']}' @0x{nxt[0]['value']:x}"
              f" -> gap {nxt[0]['value'] - (base + size)} bytes")
    for s in ('thermstat_boilerTemp', 'thermstat_boilerRetTemp',
              'CurrentBoilerTemperature', 'CurrentBoilerReturnTemperature'):
        vas = img.string_va(s)
        refs = sum(len(img.xrefs(v)) for v in vas)
        print(f"  string {s:<32} copies={len(vas)} refs={refs}")
    return slots

if __name__ == '__main__':
    for p in sys.argv[1:]:
        analyse(p)
        print()

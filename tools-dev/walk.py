import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import Img
from table import cstr

ENTRY = 0x4c
F = {  # offset -> field name  (derived from the dump, entry base = name pointer)
    0x00: 'name', 0x04: 'package', 0x08: 'placeholder', 0x0c: 'deviceVar',
    0x10: 'deviceSvc', 0x14: 'sampleType',
}

def walk(path, label, base, count):
    img = Img(path)
    off0 = img.va2off(base)
    print(f"########## {label}: rrdDevices @ 0x{base:x}, {count} slots ##########")
    rows = []
    for i in range(count):
        E = base + i * ENTRY
        o = off0 + i * ENTRY
        w = lambda k: struct.unpack_from('<I', img.d, o + k)[0]
        name = cstr(img, w(0x00)) or ('<0x%08x>' % w(0x00))
        pkg = cstr(img, w(0x04)) or '-'
        var = cstr(img, w(0x0c)) or '-'
        svc = cstr(img, w(0x10)) or '-'
        typ = cstr(img, w(0x14)) or '-'
        binlen, bins = w(0x24), w(0x28)
        cons = cstr(img, w(0x2c)) or '-'
        rra = cstr(img, w(0x30)) or '-'
        rows.append((i, E, name, pkg, var, svc, typ, binlen, bins, cons, rra))
        print(f"  [{i:2}] 0x{E:08x} {name}")
        print(f"        pkg={pkg}  var={var}  svc={svc}  type={typ}")
        print(f"        rra={rra} binLength={binlen} bins={bins} cons={cons}")
    return rows

if __name__ == '__main__':
    which = sys.argv[1]
    if which == 'new':
        walk(sys.argv[2], "NEW r2429", 0x146660, 12)
    else:
        walk(sys.argv[2], "OLD r2404", 0x70ed0, 25)

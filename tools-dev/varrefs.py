import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from diffsyms import demangle

VARS = ['CurrentSetpoint', 'CurrentTemperature', 'CurrentInternalBoilerSetpoint',
        'CurrentBoilerSetpoint', 'CurrentBoilerTemperature',
        'CurrentBoilerReturnTemperature', 'InternalTemperature', 'BoilerOpMode',
        'BoilerBurnerHours', 'BoilerChPressure', 'BoilerPumpStarts', 'ProgramState',
        'InternalSetpoint']

def scan(path, label):
    img = Img(path)
    print(f"########## {label} ##########")
    for v in VARS:
        vas = img.string_va(v)
        if not vas:
            print(f"  {v:<32} absent")
            continue
        allrefs = []
        for va in vas:
            allrefs += img.xrefs(va)
        where = []
        for hva, fn in allrefs:
            d = demangle(fn) if fn else '?'
            where.append(f"0x{hva:x}({d})")
        print(f"  {v:<32} refs={len(allrefs):<2} {', '.join(where) if where else '-'}")
    print()

def objects(path, label):
    e = Elf(path)
    print(f"--- {label}: .data/.rodata objects that look like variable tables ---")
    for s in sorted([s for s in e.symbols_full('.symtab') if s['type'] == 1 and s['value']],
                    key=lambda s: s['value']):
        n = s['name'].lower()
        if any(k in n for k in ('var', 'info', 'service', 'svc', 'therm', 'boiler', 'ot')):
            print(f"  0x{s['value']:08x} +{s['size']:<6} {s['name']}")
    print()

for i, p in enumerate(sys.argv[1:]):
    lbl = os.path.basename(p)
    scan(p, lbl)
    objects(p, lbl)

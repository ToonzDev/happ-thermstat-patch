import sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf

def ctx(path, label, needles, width=700):
    d = Elf(path).data
    print(f"########## {label} ##########")
    for needle in needles:
        for m in re.finditer(re.escape(needle) + b'\x00', d):
            s = max(0, m.start() - width)
            e = min(len(d), m.end() + width)
            txt = re.sub(rb'\x00+', b' | ', d[s:e]).decode('ascii', 'replace')
            txt = re.sub(r'\x1b\[[0-9;]*m', '', txt)
            print(f"  [{needle.decode()}] @0x{m.start():x}")
            print(f"    {txt}\n")

needles = [b'CurrentBoilerSetpoint', b'CurrentBoilerTemperature', b'CurrentBoilerReturnTemperature']
ctx(sys.argv[1], "OLD r2404", needles)
ctx(sys.argv[2], "NEW r2429", needles)

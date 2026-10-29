"""Find zero padding in .rodata big enough to hold a 36-char uuid + NUL,
and confirm nothing references inside it (absolute or pc-relative)."""
import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img

NEED = 40

path = sys.argv[1]
e = Elf(path)
img = Img(path)

for secname in ('.rodata',):
    s = e.sec(secname)
    d = e.secdata(s)
    base = s['addr']
    print(f"{secname}: 0x{base:x} .. 0x{base+len(d):x} ({len(d)} bytes)")
    runs = []
    for m in re.finditer(rb'\x00{%d,}' % NEED, d):
        runs.append((base + m.start(), m.end() - m.start()))
    print(f"  zero runs >= {NEED} bytes: {len(runs)}")
    for a, n in runs[:15]:
        print(f"    0x{a:x}  {n} bytes")

    if runs:
        # pick the largest run, offset a little to stay clear of boundaries
        a, n = max(runs, key=lambda t: t[1])
        pick = (a + 8) & ~3
        print(f"\n  largest run at 0x{a:x} ({n} bytes) -> candidate address 0x{pick:x}")
        # is anything pointing into this run?
        hits = 0
        for off in range(0, n, 4):
            va = a + off
            pat = struct.pack('<I', va)
            hits += len(re.findall(re.escape(pat), img.d))
        print(f"  absolute references into the run: {hits}")

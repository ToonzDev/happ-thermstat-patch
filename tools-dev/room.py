import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img

path = sys.argv[1]
e = Elf(path)
img = Img(path)

ARR = 0x146660
SIZE = 912
END = ARR + SIZE

print("=== .data objects sorted by address, around rrdDevices ===")
objs = sorted([s for s in e.symbols_full('.symtab') if s['type'] == 1 and s['value']],
              key=lambda s: s['value'])
for o in objs:
    a, sz = o['value'], o['size']
    if 0x146000 <= a <= 0x146c00:
        mark = '   <== rrdDevices' if a == ARR else ''
        print(f"  0x{a:08x} +{sz:<6} end=0x{a+sz:08x}  {o['name']}{mark}")

sec = [s for s in e.sections if s['name'] == '.data'][0]
print(f"\n.data: 0x{sec['addr']:x} .. 0x{sec['addr']+sec['size']:x}  (size {sec['size']})")
print(f"rrdDevices ends at 0x{END:x}; bytes to end of .data = {sec['addr']+sec['size']-END}")

# what occupies the gap right after the array?
nxt = [o for o in objs if o['value'] >= END]
if nxt:
    n = nxt[0]
    print(f"next object after array: '{n['name']}' @0x{n['value']:x} (+{n['size']})"
          f"  -> gap of {n['value']-END} bytes")

print("\n=== is the tail of the array / gap zeroed? ===")
off = img.va2off(END)
tail = img.d[off:off + 0x180]
print(f"  {sum(1 for b in tail if b == 0)} of {len(tail)} bytes after the array are zero")
print("  first 64 bytes:", tail[:64].hex())

print("\n=== who references the array base 0x%x ? ===" % ARR)
for hva, fn in img.xrefs(ARR):
    print(f"  0x{hva:x} in {fn}")
for delta in (0, 4, 8):
    pass

import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xref import Img

def cstr(img, va, maxlen=60):
    off = img.va2off(va)
    if off is None:
        return None
    end = img.d.find(b'\x00', off)
    if end < 0 or end - off > maxlen:
        return None
    s = img.d[off:end]
    try:
        t = s.decode('ascii')
    except Exception:
        return None
    if not t or any(ord(c) < 0x20 for c in t):
        return None
    return t

def dump(path, label, start, count):
    img = Img(path)
    print(f"########## {label}: table at 0x{start:x} ##########")
    off = img.va2off(start)
    if off is None:
        print("  (address not mapped)")
        return
    for i in range(count):
        va = start + i * 4
        o = off + i * 4
        (w,) = struct.unpack_from('<I', img.d, o)
        s = cstr(img, w) if w else None
        tag = ''
        if w == 0:
            tag = '  <-- NULL'
        note = f'"{s}"' if s else ''
        print(f"  0x{va:08x} : 0x{w:08x}  {note}{tag}")

if __name__ == '__main__':
    path = sys.argv[1]
    start = int(sys.argv[2], 16)
    count = int(sys.argv[3])
    dump(path, os.path.basename(path), start, count)

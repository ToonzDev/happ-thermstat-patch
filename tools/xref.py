import sys, re, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

class Img:
    def __init__(self, path):
        self.e = Elf(path)
        self.d = self.e.data
        # function ranges from .symtab
        self.funcs = []
        for s in self.e.symbols_full('.symtab'):
            if s['type'] == 2 and s['value']:
                addr = s['value'] & ~1          # clear Thumb bit
                self.funcs.append((addr, addr + max(s['size'], 1), s['name']))
        self.funcs.sort()

    def off2va(self, off):
        for s in self.e.sections:
            if s['type'] == 8 or not s['addr']:
                continue
            if s['offset'] <= off < s['offset'] + s['size']:
                return s['addr'] + (off - s['offset'])
        return None

    def va2off(self, va):
        for s in self.e.sections:
            if s['type'] == 8 or not s['addr']:
                continue
            if s['addr'] <= va < s['addr'] + s['size']:
                return s['offset'] + (va - s['addr'])
        return None

    def func_at(self, va):
        best = None
        for a, b, n in self.funcs:
            if a <= va < b:
                return n
            if a <= va and (best is None or a > best[0]):
                best = (a, n)
        return ("~" + best[1]) if best else None

    def string_va(self, text):
        needle = text.encode() + b'\x00'
        out = []
        for m in re.finditer(re.escape(needle), self.d):
            va = self.off2va(m.start())
            if va:
                out.append(va)
        return out

    def xrefs(self, va):
        """find 4-byte LE literal-pool references to this address"""
        pat = struct.pack('<I', va)
        hits = []
        for m in re.finditer(re.escape(pat), self.d):
            hva = self.off2va(m.start())
            if hva is None:
                continue
            fn = self.func_at(hva)
            hits.append((hva, fn))
        return hits

def report(path, label, strings):
    img = Img(path)
    print(f"########## {label} ##########")
    for text in strings:
        vas = img.string_va(text)
        print(f"  '{text}' -> {len(vas)} copies at {[hex(v) for v in vas]}")
        seen = set()
        for va in vas:
            for hva, fn in img.xrefs(va):
                d = demangle(fn) if fn else '?'
                key = d
                if key in seen:
                    continue
                seen.add(key)
                print(f"      referenced from 0x{hva:x}  in  {d}")
        if not seen:
            print("      (no 32-bit literal references found)")
        print()

if __name__ == '__main__':
    strings = ['CurrentBoilerTemperature', 'CurrentBoilerReturnTemperature',
               'thermstat_boilerTemp', 'thermstat_boilerRetTemp', 'CurrentBoilerSetpoint']
    report(sys.argv[1], "OLD r2404", strings)
    report(sys.argv[2], "NEW r2429", strings)

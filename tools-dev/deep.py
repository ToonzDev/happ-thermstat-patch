"""Full-coverage ARM disassembly of one function, resolving pc-relative literal
loads to symbols/strings, so two builds can be compared by what data they touch."""
import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr
from diffsyms import demangle
from capstone import *

class Fn:
    def __init__(self, path, fname):
        self.path = path
        self.e = Elf(path)
        self.img = Img(path)
        self.sym = {}          # addr -> name (funcs and objects)
        for s in self.e.symbols_full('.symtab'):
            if s['value'] and s['type'] in (1, 2):
                self.sym[s['value'] & ~1] = (re.sub(r'\.\d+$', '', demangle(s['name'])),
                                             s['type'], s['size'])
        raw = size = None
        for s in self.e.symbols_full('.symtab'):
            if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == fname and s['value']:
                raw, size = s['value'], s['size']
        if raw is None:
            raise SystemExit(f"{fname} not found in {os.path.basename(path)}")
        self.thumb = bool(raw & 1)
        self.addr = raw & ~1
        self.size = size
        self.off = self.img.va2off(self.addr)
        self.code = self.img.d[self.off:self.off + size]
        self.insns = self._decode()

    def _decode(self):
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if self.thumb else CS_MODE_ARM)
        step = 2 if self.thumb else 4
        out, pos = [], 0
        while pos < len(self.code):
            got = False
            for i in md.disasm(self.code[pos:], self.addr + pos):
                out.append(i)
                pos += i.size
                got = True
            if not got:            # undecodable word (literal pool) - skip and resume
                pos += step
        return out

    def word_at(self, va):
        o = self.img.va2off(va)
        if o is None or o + 4 > len(self.img.d):
            return None
        return struct.unpack_from('<I', self.img.d, o)[0]

    def resolve(self, v):
        """describe an address: symbol, or string, or raw"""
        if v in self.sym:
            n, t, sz = self.sym[v]
            return f"{n}{'()' if t == 2 else ''}"
        # inside an object?
        best = None
        for a, (n, t, sz) in self.sym.items():
            if t == 1 and sz and a <= v < a + sz:
                best = f"{n}+0x{v-a:x}"
        if best:
            return best
        s = cstr(self.img, v, 70)
        if s:
            return f'"{s}"'
        return None

    def literals(self):
        """addresses loaded via pc-relative literal pools, resolved"""
        out = {}
        for i in self.insns:
            m = re.search(r'\[pc, #(-?(?:0x[0-9a-f]+|\d+))\]', i.op_str)
            if not m or not i.mnemonic.startswith('ldr'):
                continue
            imm = int(m.group(1), 16) if 'x' in m.group(1) else int(m.group(1))
            pool = ((i.address + (4 if self.thumb else 8)) & (~3 if self.thumb else ~0)) + imm
            v = self.word_at(pool)
            if v is None:
                continue
            r = self.resolve(v)
            if r:
                out.setdefault(r, []).append(i.address)
        return out

    def calls(self):
        out = {}
        for i in self.insns:
            if i.mnemonic.startswith('bl'):
                m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
                if m:
                    t = int(m.group(1), 16) & ~1
                    n = self.sym.get(t, (f"sub_{t:x}", 2, 0))[0]
                    out[n] = out.get(n, 0) + 1
        return out

    def imms(self):
        out = set()
        for i in self.insns:
            if re.match(r'^(cmp|cmn|subs?|teq|mov|movw)', i.mnemonic):
                for m in re.finditer(r'#(0x[0-9a-f]+|\d+)', i.op_str):
                    v = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
                    if 0 <= v <= 300:
                        out.add(v)
        return out

fname = sys.argv[1]
A = Fn(sys.argv[2], fname)
B = Fn(sys.argv[3], fname)
for lbl, f in (("r2404", A), ("r2426", B)):
    print(f"{lbl}: {fname} @0x{f.addr:x} size={f.size} decoded={len(f.insns)} insns"
          f" ({len(f.insns)*4} of {f.size} bytes)")

la, lb = A.literals(), B.literals()
print(f"\n=== data referenced only by r2404 ({len(set(la)-set(lb))}) ===")
for k in sorted(set(la) - set(lb)):
    print(f"   {k}   @ {[hex(x) for x in la[k][:4]]}")
print(f"\n=== data referenced only by r2426 ({len(set(lb)-set(la))}) ===")
for k in sorted(set(lb) - set(la)):
    print(f"   {k}   @ {[hex(x) for x in lb[k][:4]]}")

ca, cb = A.calls(), B.calls()
print(f"\n=== calls only in r2404 ===")
for k in sorted(set(ca) - set(cb)):
    print(f"   {ca[k]}x {k}")
print(f"=== calls only in r2426 ===")
for k in sorted(set(cb) - set(ca)):
    print(f"   {cb[k]}x {k}")

ia, ib = A.imms(), B.imms()
print(f"\nimmediates only in r2404: {sorted(ia-ib)}")
print(f"immediates only in r2426: {sorted(ib-ia)}")
for v in (24, 25, 26, 27, 28, 56, 57):
    print(f"  OT id {v:3}: r2404={'yes' if v in ia else 'no ':<3} r2426={'yes' if v in ib else 'no'}")

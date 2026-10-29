"""Resolve PC-relative string references of the form
      ldr  rX, [pc, #imm]     ; literal = offset
      add  rY, pc, rX         ; rY = (addr_of_add + 8) + offset
across every function, and report which functions reference given strings.
This is how happ_thermstat names its service variables, so plain
absolute-address cross-referencing misses all of it.
"""
import sys, os, re, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr
from diffsyms import demangle
from capstone import *

class Scan:
    def __init__(self, path, label):
        self.label = label
        self.e = Elf(path)
        self.img = Img(path)
        self.fns = []
        for s in self.e.symbols_full('.symtab'):
            if s['type'] == 2 and s['value'] and s['size']:
                self.fns.append((s['value'] & ~1, bool(s['value'] & 1), s['size'],
                                 re.sub(r'\.\d+$', '', demangle(s['name']))))
        self.fns.sort()

    def word(self, va):
        o = self.img.va2off(va)
        return None if o is None or o + 4 > len(self.img.d) else struct.unpack_from('<I', self.img.d, o)[0]

    def refs(self):
        """yield (func_name, add_addr, resolved_string)"""
        out = []
        for addr, thumb, size, name in self.fns:
            off = self.img.va2off(addr)
            if off is None or size > 60000:
                continue
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
            code = self.img.d[off:off + size]
            regs = {}
            pos = 0
            step = 2 if thumb else 4
            while pos < len(code):
                got = False
                for i in md.disasm(code[pos:], addr + pos):
                    got = True
                    pos += i.size
                    m = re.match(r'^(\w+), \[pc, #(-?(?:0x[0-9a-f]+|\d+))\]$', i.op_str)
                    if i.mnemonic.startswith('ldr') and m:
                        imm = int(m.group(2), 16) if 'x' in m.group(2) else int(m.group(2))
                        base = i.address + (4 if thumb else 8)
                        if thumb:
                            base &= ~3
                        v = self.word((base + imm) & ~3 if thumb else base + imm)
                        if v is not None:
                            regs[m.group(1)] = v
                        continue
                    m2 = re.match(r'^(\w+), pc, (\w+)$', i.op_str)
                    if i.mnemonic == 'add' and m2 and m2.group(2) in regs:
                        target = i.address + (4 if thumb else 8) + regs[m2.group(2)]
                        s = cstr(self.img, target & 0xffffffff, 80)
                        if s:
                            out.append((name, i.address, s))
                        continue
                    # a write to a tracked register invalidates it
                    dst = i.op_str.split(',')[0].strip()
                    if dst in regs and not i.mnemonic.startswith(('cmp', 'str', 'b')):
                        if not (i.mnemonic.startswith('ldr') or i.mnemonic == 'add'):
                            regs.pop(dst, None)
                if not got:
                    pos += step
        return out

WANT = ['CurrentBoilerTemperature', 'CurrentBoilerReturnTemperature',
        'CurrentBoilerSetpoint', 'BoilerChPressure', 'CurrentTemperature',
        'BoilerOpMode']

res = {}
for lbl, p in (('r2404', sys.argv[1]), ('r2426', sys.argv[2])):
    s = Scan(p, lbl)
    rs = s.refs()
    print(f"{lbl}: {len(rs)} pc-relative string references resolved across {len(s.fns)} functions")
    idx = {}
    for fn, a, st in rs:
        idx.setdefault(st, set()).add(fn)
    res[lbl] = idx

print()
for w in WANT:
    a = sorted(res['r2404'].get(w, set()))
    b = sorted(res['r2426'].get(w, set()))
    print(f"=== {w} ===")
    print(f"   r2404 referenced in: {a if a else 'NONE'}")
    print(f"   r2426 referenced in: {b if b else 'NONE'}")
    if set(a) - set(b):
        print(f"   *** LOST in r2426: {sorted(set(a)-set(b))}")
    print()

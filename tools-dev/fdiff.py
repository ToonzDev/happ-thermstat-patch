"""Rigorous cross-build function diff.

1. decode fully, find literal-pool slots (targets of ldr rX,[pc,#imm]) and exclude them
2. normalise each instruction so absolute addresses do not defeat the diff
3. align the two instruction streams and print the removed / added hunks with
   calls and string/symbol references resolved
"""
import sys, os, re, struct, difflib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from xref import Img
from table import cstr
from diffsyms import demangle
from capstone import *

class Func:
    def __init__(self, path, fname, label):
        self.label = label
        self.e = Elf(path)
        self.img = Img(path)
        self.syms = {}
        for s in self.e.symbols_full('.symtab'):
            if s['value'] and s['type'] in (1, 2):
                self.syms[s['value'] & ~1] = (re.sub(r'\.\d+$', '', demangle(s['name'])), s['type'], s['size'])
        raw = size = None
        for s in self.e.symbols_full('.symtab'):
            if s['type'] == 2 and re.sub(r'\.\d+$', '', demangle(s['name'])) == fname and s['value']:
                raw, size = s['value'], s['size']
        if raw is None:
            raise SystemExit(f"{fname} not in {label}")
        self.thumb = bool(raw & 1)
        self.addr, self.size = raw & ~1, size
        self.off = self.img.va2off(self.addr)
        self.code = self.img.d[self.off:self.off + size]
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if self.thumb else CS_MODE_ARM)
        self.pools = self._find_pools()
        self.insns = self._decode(self.pools)

    def _raw_decode(self):
        out, pos, step = [], 0, (2 if self.thumb else 4)
        while pos < len(self.code):
            got = False
            for i in self.md.disasm(self.code[pos:], self.addr + pos):
                out.append(i); pos += i.size; got = True
            if not got:
                pos += step
        return out

    def _pool_target(self, i):
        m = re.search(r'\[pc, #(-?(?:0x[0-9a-f]+|\d+))\]', i.op_str)
        if not m or not i.mnemonic.startswith('ldr'):
            return None
        imm = int(m.group(1), 16) if 'x' in m.group(1) else int(m.group(1))
        base = i.address + (4 if self.thumb else 8)
        if self.thumb:
            base &= ~3
        return base + imm

    def _find_pools(self):
        pools = set()
        for i in self._raw_decode():
            t = self._pool_target(i)
            if t is not None and self.addr <= t < self.addr + self.size:
                pools.add(t & ~3)
        return pools

    def _decode(self, pools):
        out, pos, step = [], 0, (2 if self.thumb else 4)
        while pos < len(self.code):
            va = self.addr + pos
            if va in pools:          # literal pool word: data, not code
                pos += 4
                continue
            got = False
            for i in self.md.disasm(self.code[pos:pos + 4] if not self.thumb else self.code[pos:pos + 4],
                                    va):
                out.append(i); pos += i.size; got = True
                break
            if not got:
                pos += step
        return out

    def word(self, va):
        o = self.img.va2off(va)
        return None if o is None or o + 4 > len(self.img.d) else struct.unpack_from('<I', self.img.d, o)[0]

    def name_of(self, a):
        a &= ~1
        if a in self.syms:
            return self.syms[a][0]
        return None

    def describe(self, i):
        """human annotation: resolved call target or literal value"""
        if i.mnemonic.startswith('bl'):
            m = re.match(r'^#?(0x[0-9a-f]+)$', i.op_str.strip())
            if m:
                t = int(m.group(1), 16)
                return f"-> {self.name_of(t) or f'local_{t:x}'}()"
        t = self._pool_target(i)
        if t is not None:
            v = self.word(t & ~3)
            if v is not None:
                n = self.name_of(v)
                if n:
                    return f"= &{n}"
                s = cstr(self.img, v, 60)
                if s:
                    return f'= "{s}"'
                return f"= 0x{v:x}"
        return ""

    def norm(self, i):
        """canonical text so absolute addresses do not break alignment"""
        op = i.op_str
        if i.mnemonic.startswith('bl'):
            m = re.match(r'^#?(0x[0-9a-f]+)$', op.strip())
            if m:
                n = self.name_of(int(m.group(1), 16))
                return f"bl {n}" if n else "bl LOCAL"
        if i.mnemonic.startswith('b'):
            op = re.sub(r'#0x[0-9a-f]+', 'L', op)
        op = re.sub(r'\[pc, #-?(?:0x[0-9a-f]+|\d+)\]', '[pc]', op)
        def big(m):
            v = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
            return '#K' if v >= 0x1000 else f'#{v}'
        op = re.sub(r'#(0x[0-9a-f]+|\d+)', big, op)
        return f"{i.mnemonic} {op}"

def main():
  fname = sys.argv[1]
  A = Func(sys.argv[2], fname, 'r2404')
  B = Func(sys.argv[3], fname, 'r2426')
  for f in (A, B):
    print(f"{f.label}: @0x{f.addr:x} size={f.size} pools={len(f.pools)} insns={len(f.insns)}"
          f"  ({len(f.insns)*4 + len(f.pools)*4} of {f.size} bytes accounted)")

  na = [A.norm(i) for i in A.insns]
  nb = [B.norm(i) for i in B.insns]
  sm = difflib.SequenceMatcher(a=na, b=nb, autojunk=False)
  ops = sm.get_opcodes()
  same = sum(i2 - i1 for tag, i1, i2, j1, j2 in ops if tag == 'equal')
  print(f"\naligned: {same} identical instructions "
        f"({same*100//max(len(na),1)}% of r2404, {same*100//max(len(nb),1)}% of r2426)")

  print("\n" + "=" * 78)
  print("HUNKS PRESENT IN r2404 BUT DELETED IN r2426 (largest first)")
  print("=" * 78)
  dels = [(i2 - i1, i1, i2, j1) for tag, i1, i2, j1, j2 in ops if tag in ('delete', 'replace')]
  dels.sort(reverse=True)
  for n, i1, i2, j1 in dels[:8]:
      print(f"\n--- {n} instructions at r2404 0x{A.insns[i1].address:x} "
            f"(r2426 equivalent near 0x{B.insns[min(j1, len(B.insns)-1)].address:x}) ---")
      for i in A.insns[i1:i2][:70]:
          print(f"   0x{i.address:x}  {i.mnemonic:<8} {i.op_str:<34} {A.describe(i)}")
      if n > 70:
          print(f"   ... {n-70} more")


if __name__ == '__main__':
    main()

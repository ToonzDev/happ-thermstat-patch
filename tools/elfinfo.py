import struct, sys, os

SHT = {0:'NULL',1:'PROGBITS',2:'SYMTAB',3:'STRTAB',4:'RELA',5:'HASH',6:'DYNAMIC',
       7:'NOTE',8:'NOBITS',9:'REL',11:'DYNSYM',14:'INIT_ARRAY',15:'FINI_ARRAY',
       16:'PREINIT_ARRAY',17:'GROUP',18:'SYMTAB_SHNDX',0x70000001:'ARM_EXIDX',
       0x6ffffff6:'GNU_HASH',0x6fffffff:'VERNEED',0x6ffffffe:'VERNEED',0x6fffffd:'VERDEF'}
MACH = {40:'ARM', 3:'x86', 62:'x86-64', 183:'AArch64'}
ETYPE = {1:'REL(object)', 2:'EXEC', 3:'DYN(pie/so)', 4:'CORE'}

class Elf:
    def __init__(self, path):
        self.path = path
        self.data = open(path,'rb').read()
        d = self.data
        assert d[:4] == b'\x7fELF', 'not ELF'
        self.cls = d[4]          # 1=32bit 2=64bit
        self.endi = d[5]
        self.osabi = d[7]
        fmt = '<' if self.endi == 1 else '>'
        if self.cls == 1:
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from(fmt+'HHIIIIIHHHHHH', d, 16)
        else:
            (self.e_type, self.e_machine, self.e_version, self.e_entry,
             self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = struct.unpack_from(fmt+'HHIQQQIHHHHHH', d, 16)
        self.fmt = fmt
        self.sections = []
        self._read_sections()

    def _read_sections(self):
        d, fmt = self.data, self.fmt
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i*self.e_shentsize
            if self.cls == 1:
                (nm, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(fmt+'IIIIIIIIII', d, off)
            else:
                (nm, typ, flags, addr, offset, size, link, info, align,
                 entsize) = struct.unpack_from(fmt+'IIQQQQIIQQ', d, off)
            raw.append(dict(nameoff=nm, type=typ, flags=flags, addr=addr,
                            offset=offset, size=size, link=link, info=info,
                            entsize=entsize))
        if self.e_shstrndx < len(raw):
            sh = raw[self.e_shstrndx]
            strtab = d[sh['offset']:sh['offset']+sh['size']]
            for s in raw:
                e = strtab.find(b'\0', s['nameoff'])
                s['name'] = strtab[s['nameoff']:e].decode('utf8','replace')
        else:
            for s in raw:
                s['name'] = '?'
        self.sections = raw

    def sec(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def secdata(self, s):
        if s is None or s['type'] == 8:
            return b''
        return self.data[s['offset']:s['offset']+s['size']]

    def needed(self):
        dyn = self.sec('.dynamic')
        dstr = self.secdata(self.sec('.dynstr'))
        if not dyn:
            return [], None
        d = self.secdata(dyn)
        step = 8 if self.cls == 1 else 16
        pat = self.fmt + ('II' if self.cls == 1 else 'QQ')
        libs, rpath = [], None
        for i in range(0, len(d)-step+1, step):
            tag, val = struct.unpack_from(pat, d, i)
            if tag == 0:
                break
            if tag == 1:
                e = dstr.find(b'\0', val)
                libs.append(dstr[val:e].decode('utf8','replace'))
            elif tag in (15, 29):
                e = dstr.find(b'\0', val)
                rpath = dstr[val:e].decode('utf8','replace')
        return libs, rpath

    def symbols_full(self, secname):
        """same as symbols() but keeps st_shndx, which is what says 'undefined'"""
        s = self.sec(secname)
        if not s:
            return []
        strname = '.strtab' if secname == '.symtab' else '.dynstr'
        st = self.secdata(self.sec(strname))
        d = self.secdata(s)
        out = []
        if self.cls == 1:
            step, pat = 16, self.fmt+'IIIBBH'
        else:
            step, pat = 24, self.fmt+'IBBHQQ'
        for i in range(0, len(d)-step+1, step):
            if self.cls == 1:
                nm, value, size, info, other, shndx = struct.unpack_from(pat, d, i)
            else:
                nm, info, other, shndx, value, size = struct.unpack_from(pat, d, i)
            e = st.find(b'\0', nm)
            name = st[nm:e].decode('utf8','replace') if e >= 0 else ''
            if name:
                out.append(dict(name=name, value=value, size=size,
                                type=info & 0xf, bind=info >> 4, shndx=shndx))
        return out

    def symbols(self, secname):
        s = self.sec(secname)
        if not s:
            return []
        strname = '.strtab' if secname == '.symtab' else '.dynstr'
        st = self.secdata(self.sec(strname))
        d = self.secdata(s)
        out = []
        if self.cls == 1:
            step, pat = 16, self.fmt+'IIIBBH'
        else:
            step, pat = 24, self.fmt+'IBBHQQ'
        for i in range(0, len(d)-step+1, step):
            if self.cls == 1:
                nm, value, size, info, other, shndx = struct.unpack_from(pat, d, i)
            else:
                nm, info, other, shndx, value, size = struct.unpack_from(pat, d, i)
            e = st.find(b'\0', nm)
            name = st[nm:e].decode('utf8','replace') if e >= 0 else ''
            if name:
                out.append((name, value, size, info & 0xf, info >> 4))
        return out

def describe(path):
    e = Elf(path)
    print(f"=== {os.path.basename(path)} ===")
    print(f"  size        : {len(e.data):,} bytes")
    print(f"  class       : {'ELF32' if e.cls==1 else 'ELF64'}  endian={'LE' if e.endi==1 else 'BE'}")
    print(f"  type        : {ETYPE.get(e.e_type, e.e_type)}   machine={MACH.get(e.e_machine, e.e_machine)}")
    print(f"  entry       : 0x{e.e_entry:x}   flags=0x{e.e_flags:x}")
    libs, rpath = e.needed()
    print(f"  NEEDED ({len(libs)}): {', '.join(libs) if libs else '(none - static?)'}")
    if rpath:
        print(f"  RPATH       : {rpath}")
    symtab = e.sec('.symtab')
    dynsym = e.sec('.dynsym')
    print(f"  .symtab     : {'PRESENT (not stripped)' if symtab else 'absent (stripped)'}")
    if symtab:
        print(f"                {symtab['size']//16:,} entries")
    if dynsym:
        print(f"  .dynsym     : {dynsym['size']//16:,} entries")
    for nm in ('.text', '.rodata', '.data', '.bss', '.debug_info'):
        s = e.sec(nm)
        if s:
            print(f"  {nm:<12}: {s['size']:,} bytes")
    print(f"  sections    : {len(e.sections)}")
    big = sorted(e.sections, key=lambda s: -s['size'])[:8]
    print("  largest     : " + ", ".join(f"{s['name']}={s['size']:,}" for s in big))
    return e

if __name__ == '__main__':
    for p in sys.argv[1:]:
        describe(p)
        print()

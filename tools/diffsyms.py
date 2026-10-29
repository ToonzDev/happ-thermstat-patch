import sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf

def demangle(sym):
    """Enough of the Itanium ABI to recover Class::method from a mangled name."""
    if not sym.startswith('_Z'):
        return sym
    i = 2
    nested = sym[i] == 'N'
    if nested:
        i += 1
    while i < len(sym) and sym[i] in 'KVrO R':
        i += 1
    parts = []
    while i < len(sym):
        if sym[i] == 'E':
            break
        if sym[i].isdigit():
            j = i
            while j < len(sym) and sym[j].isdigit():
                j += 1
            n = int(sym[i:j])
            parts.append(sym[j:j+n])
            i = j + n
            continue
        if sym[i] == 'I':                      # template args: stop, keep base name
            parts.append('<...>')
            break
        if sym[i] == 'C' and i+1 < len(sym):   # constructor
            parts.append('{ctor}')
            i += 2
            continue
        if sym[i] == 'D' and i+1 < len(sym):   # destructor
            parts.append('{dtor}')
            i += 2
            continue
        if sym[i] == 'S':                      # substitution - unresolvable here
            j = i+1
            while j < len(sym) and sym[j] not in '_':
                j += 1
            parts.append('$')
            i = j+1
            continue
        break
    if not parts:
        return sym
    return '::'.join(p for p in parts if p != '$')

def funcs(path):
    e = Elf(path)
    out = {}
    for name, value, size, typ, bind in e.symbols('.symtab'):
        if typ != 2:            # STT_FUNC only
            continue
        out.setdefault(demangle(name), []).append((name, size))
    return out, e

def strings_of(e, minlen=6):
    out = set()
    for secname in ('.rodata', '.data'):
        s = e.sec(secname)
        if not s:
            continue
        d = e.secdata(s)
        for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, d):
            out.add(m.group().decode('ascii'))
    return out

def main(oldp, newp):
    oldf, olde = funcs(oldp)
    newf, newe = funcs(newp)
    print(f"functions: old={len(oldf)}  new={len(newf)}")

    only_old = sorted(set(oldf) - set(newf))
    only_new = sorted(set(newf) - set(oldf))
    print(f"\n### in OLD but NOT in NEW  ({len(only_old)})  <-- candidate dropped code")
    for f in only_old:
        print("   " + f)

    print(f"\n### in NEW but not in OLD  ({len(only_new)}) - showing class prefixes only")
    pref = {}
    for f in only_new:
        p = f.split('::')[0]
        pref[p] = pref.get(p, 0) + 1
    for p, c in sorted(pref.items(), key=lambda kv: -kv[1])[:40]:
        print(f"   {c:5}  {p}")

    olds, news = strings_of(olde), strings_of(newe)
    so = sorted(olds - news)
    print(f"\n### strings in OLD but NOT in NEW ({len(so)})")
    for s in so:
        print("   " + repr(s))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

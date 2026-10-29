import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

def funcs(p):
    e = Elf(p)
    return set(re.sub(r'\.\d+$', '', demangle(s['name']))
               for s in e.symbols_full('.symtab') if s['type'] == 2 and s['value'])

def strs(p):
    e = Elf(p)
    out = set()
    for sec in ('.rodata', '.data'):
        s = e.sec(sec)
        if s:
            for m in re.finditer(rb'[\x20-\x7e]{4,60}', e.secdata(s)):
                out.add(m.group().decode())
    return out

old, mid, new = sys.argv[1], sys.argv[2], sys.argv[3]
fo, fm, fn = funcs(old), funcs(mid), funcs(new)
so, sm, sn = strs(old), strs(mid), strs(new)

print(f"functions: r2404={len(fo)}  r2426={len(fm)}  r2429={len(fn)}")

GROUPS = {
 'cloud/https': ('httplib', 'nlohmann', 'Uri', 'Jwt', 'Base64', 'Gateway', 'Requests',
                 'HttpClient', 'PathElement', 'QueryElement', 'UriElement', 'Config::'),
 'smart district heating': ('smartdistrictheating', 'SlimmeWarmteBox', 'EnecoConnectionModule'),
 'issue/error reporting': ('IssueReporter', 'IssueDeterminator', 'OthermErrorReporter'),
}

def summarise(gain, label):
    print(f"\n=== {label}: {len(gain)} functions gained ===")
    claimed = set()
    for g, prefixes in GROUPS.items():
        hits = sorted(f for f in gain if any(p in f for p in prefixes))
        claimed |= set(hits)
        print(f"  {g:<26}{len(hits)}")
    openssl = sorted(f for f in (gain - claimed) if 'OPENSSL' in f or 'CRYPTO' in f
                     or f.startswith(('SHA', 'MD5', 'EVP', 'BIO', 'ERR_', 'ASN1', 'PEM', 'GENERAL')))
    claimed |= set(openssl)
    print(f"  {'openssl imports':<26}{len(openssl)}")
    rest = sorted(gain - claimed)
    print(f"  {'other':<26}{len(rest)}")
    for r in rest[:40]:
        print(f"      {r}")

summarise(fm - fo, "r2404 -> r2426 (what .18 would lose by using r2404)")

print("\n=== thermstat_* KPI logger strings: which build introduced them? ===")
kpi = sorted(s for s in (sn | sm | so) if s.startswith('thermstat_') and s[10:11].isupper())
for k in kpi:
    print(f"   {k:<40} r2404={'y' if k in so else '-'}  r2426={'y' if k in sm else '-'}  r2429={'y' if k in sn else '-'}")

print("\n=== boiler-temp logger presence by build ===")
for k in ('thermstat_boilerTemp', 'thermstat_boilerRetTemp'):
    print(f"   {k:<28} r2404={'y' if k in so else '-'}  r2426={'y' if k in sm else '-'}  r2429={'y' if k in sn else '-'}")

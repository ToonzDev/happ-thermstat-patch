import sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

def funcs(p):
    e = Elf(p)
    return set(re.sub(r'\.\d+$', '', demangle(s['name']))
               for s in e.symbols_full('.symtab') if s['type'] == 2)

def strs(p):
    e = Elf(p)
    out = set()
    for sec in ('.rodata', '.data'):
        s = e.sec(sec)
        if s:
            for m in re.finditer(rb'[\x20-\x7e]{4,80}', e.secdata(s)):
                out.add(m.group().decode())
    return out

old, new = sys.argv[1], sys.argv[2]
fo, fn = funcs(old), funcs(new)
so, sn = strs(old), strs(new)

only_new_f = fn - fo
only_new_s = sn - so

GROUPS = {
 'Cloud / HTTPS plumbing': ('httplib', 'nlohmann', 'Uri', 'DeviceUri', 'AccountUri', 'Jwt',
                            'Base64', 'CertificateGateway', 'FionaGateway', 'AuthGateway',
                            'TokenGateway', 'AccountGateway', 'DeviceGateway', 'HttpClientFactory',
                            'Requests', 'PathElement', 'QueryElement', 'UriElement'),
 'Eneco smart district heating': ('smartdistrictheating', 'SlimmeWarmteBox', 'EnecoConnectionModule'),
 'Error / issue reporting': ('IssueReporter', 'IssueDeterminator', 'OthermErrorReporter'),
}

print("=" * 70)
print("WHAT r2429 HAS THAT r2404 DOES NOT  (i.e. what a downgrade loses)")
print("=" * 70)
print(f"\nfunctions: r2404={len(fo)}  r2429={len(fn)}   new-only={len(only_new_f)}\n")

claimed = set()
for label, prefixes in GROUPS.items():
    hits = sorted(f for f in only_new_f if any(f.startswith(p) or ('::' + p) in f for p in prefixes))
    claimed |= set(hits)
    print(f"-- {label}: {len(hits)} functions")

rest = sorted(only_new_f - claimed)
print(f"-- other / thermostat logic: {len(rest)} functions")
for f in rest[:45]:
    print("     " + f)

print("\n--- new feature-ish strings (actions, toggles, rrd loggers, OT ids) ---")
pat = re.compile(r'^(FT_|thermstat_|OT|DHW|Dhw|Get|Set|Send|Configure|Disable|Mute|Max|T[A-Z])')
cand = sorted(s for s in only_new_s if pat.match(s) and len(s) < 42 and ' ' not in s)
for s in cand:
    print("     " + s)

import sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf

d = Elf(sys.argv[1]).data

print("=== http/hcom action-like names ===")
acts = sorted(set(m.group().decode() for m in
               re.finditer(rb'(get|set|add|create|remove|erase|drop|Get|Set|Add|Create|Remove)[A-Za-z0-9]{3,40}', d)))
for a in acts:
    print("   " + a)

print("\n=== logger / Rrd related strings ===")
hits = sorted(set(m.group().decode() for m in
              re.finditer(rb'[A-Za-z_]{0,20}([Ll]ogger|Rrd|RRD)[A-Za-z_]{0,25}', d)))
for h in hits:
    print("   " + h)

print("\n=== error/diagnostic messages mentioning unknown/missing ===")
for m in re.finditer(rb'[\x20-\x7e]{8,90}', d):
    s = m.group().decode()
    if re.search(r'unknown|not found|missing|no such|cannot|failed|invalid', s, re.I):
        print("   " + repr(s))

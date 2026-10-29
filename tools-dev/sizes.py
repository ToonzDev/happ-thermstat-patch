import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elfinfo import Elf
from diffsyms import demangle

WATCH = ['updateStatevars', 'subdevInitVars', 'initVars', 'parseOpenThermValue',
         'parseSlaveState', 'setOnOffFlameInfo', 'calcOnOffBoilerBurnerMinutes',
         'thermostat_store', 'postConfig', 'subdev_init', 'sendTemperatureRequest',
         'setOpenThermCommError', 'measureHeatingCoolingFactors', 'adjustLongTermOffset',
         'schedule_setProgramState', 'createSvar_double', 'createSvar_int',
         'otDataIdToString', 'thermostat_reinit', 'rrd_createMissing', 'rrd_initDevice',
         'rrd_init', 'de_fillRrdQueryQueue']

def sizes(path):
    e = Elf(path)
    out = {}
    for s in e.symbols_full('.symtab'):
        if s['type'] == 2 and s['value']:
            out[re.sub(r'\.\d+$', '', demangle(s['name']))] = s['size']
    return out

a, b = sizes(sys.argv[1]), sizes(sys.argv[2])
print(f"{'function':<34}{'r2404':>9}{'r2426':>9}{'delta':>9}")
print("-" * 61)
for w in WATCH:
    x, y = a.get(w), b.get(w)
    if x is None and y is None:
        continue
    d = '' if (x is None or y is None) else f"{y - x:+d}"
    print(f"{w:<34}{str(x):>9}{str(y):>9}{d:>9}")

print("\n=== all shared functions that SHRANK the most in r2426 ===")
shared = [(k, a[k], b[k]) for k in a if k in b and b[k] < a[k]]
for k, x, y in sorted(shared, key=lambda t: t[1] - t[2], reverse=True)[:25]:
    print(f"  {k:<44} {x:>7} -> {y:<7} ({y-x:+d})")

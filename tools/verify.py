import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyse import analyse

slots = analyse(sys.argv[1])
if slots is None:
    raise SystemExit("no table")

want = {
    'thermstat_boilerTemp': 'CurrentBoilerTemperature',
    'thermstat_boilerRetTemp': 'CurrentBoilerReturnTemperature',
}
print("\n=== acceptance checks ===")
ok = True
byname = {s['name']: s for s in slots}
for logger, var in want.items():
    s = byname.get(logger)
    if not s:
        print(f"  FAIL  {logger} absent"); ok = False; continue
    checks = [
        ('deviceVar', s['var'], var),
        ('deviceSvc', s['svc'], 'ThermostatInfo'),
        ('package', s['pkg'], 'thermostatSettings'),
        ('sampleType', s['type'], 'double'),
        ('rra', s['rra'], '30days'),
        ('binLength', s['binl'], 60),
        ('bins', s['bins'], 43200),
    ]
    bad = [(k, got, exp) for k, got, exp in checks if got != exp]
    if bad:
        ok = False
        print(f"  FAIL  {logger}: " + ", ".join(f"{k}={got!r} expected {exp!r}" for k, got, exp in bad))
    else:
        print(f"  ok    {logger} -> {var}  double/30days 60/43200")

# the loggers other modules rely on must be untouched
must_keep = ['thermstat_setpoint', 'thermstat_realTemps', 'thermstat_boilerSetpoint',
             'thermstat_programState', 'thermstat_internalSetpoint', 'thermstat_boilerOpMode',
             'thermstat_boilerBurnerHours', 'thermstat_boilerChPressure']
missing = [m for m in must_keep if m not in byname]
if missing:
    print(f"  FAIL  these must be preserved but are gone: {missing}"); ok = False
else:
    print(f"  ok    all {len(must_keep)} pre-existing thermostat loggers preserved")

vhr = [s['name'] for s in slots if s['name'] and s['name'].startswith('ventilationHeatRecovery')]
print(f"  note  VHR loggers remaining: {len(vhr)} -> {vhr}")
print("\nRESULT:", "PASS" if ok else "FAIL")

import sys, os
paths = {"r2404": sys.argv[1], "r2426": sys.argv[2], "r2429": sys.argv[3]}
needles = [b"OpenTherm ID %d is not supported by the boiler!",
           b"OpenTherm ID is processed with the wrong type: %d",
           b"TBoiler", b"Tret", b"MaxTSet",
           b"thermstat_boilerTemp", b"thermstat_boilerRetTemp",
           b"CurrentBoilerTemperature", b"CurrentBoilerReturnTemperature"]
blobs = {k: open(v, "rb").read() for k, v in paths.items()}
w = max(len(n) for n in needles) + 2
print(f"{'string':<{w}}  r2404 r2426 r2429")
for n in needles:
    row = "  ".join(("  y  " if n in blobs[k] else "  -  ") for k in ("r2404", "r2426", "r2429"))
    print(f"{n.decode():<{w}}  {row}")

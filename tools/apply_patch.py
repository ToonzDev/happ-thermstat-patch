#!/usr/bin/env python3
"""
Interactive installer for the Toon boiler-temperature logging patch.

Asks for your Toon's IP address and password once, then walks through every step
with visible feedback and stops at the first thing that looks wrong.

    python tools/apply_patch.py              # full run, asks before installing
    python tools/apply_patch.py --dry-run    # everything except the install

Nothing is changed on the Toon until you type "yes" at the confirmation.
"""
import argparse, getpass, hashlib, importlib.util, os, re, shutil, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(os.getcwd(), "toon_patch_work")
SSH_OPTS = ["-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "MACs=+hmac-sha1",
            "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]

# ---------------------------------------------------------------- pretty output
class C:
    if os.name == "nt" and not os.environ.get("WT_SESSION"):
        os.system("")            # enable ANSI on older Windows consoles
    B = "\033[1m"; G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; D = "\033[2m"; X = "\033[0m"

_step = 0
def step(title):
    global _step
    _step += 1
    print(f"\n{C.B}── Step {_step}: {title}{C.X}")

def ok(msg):    print(f"  {C.G}[ok]{C.X}   {msg}")
def info(msg):  print(f"  {C.D}       {msg}{C.X}")
def warn(msg):  print(f"  {C.Y}[warn]{C.X} {msg}")
def die(msg, hint=None):
    print(f"  {C.R}[stop]{C.X} {msg}")
    if hint:
        print(f"         {hint}")
    print(f"\n{C.R}Nothing was changed on your Toon.{C.X}")
    sys.exit(1)

# ---------------------------------------------------------------- ssh transport
class Toon:
    """Runs commands on the Toon using whichever password helper is available."""
    def __init__(self, host, user, password):
        self.host, self.user, self.password = host, user, password
        if shutil.which("plink"):
            self.mode = "plink"
        elif shutil.which("sshpass"):
            self.mode = "sshpass"
        else:
            self.mode = "ssh"

    def describe(self):
        return {"plink":   "plink (PuTTY) - password handled automatically",
                "sshpass": "sshpass - password handled automatically",
                "ssh":     "plain ssh - you will be asked for the password a few times"}[self.mode]

    def _argv(self, command):
        if self.mode == "plink":
            return ["plink", "-ssh", "-batch", "-l", self.user, "-pw", self.password,
                    self.host, command]
        if self.mode == "sshpass":
            return ["sshpass", "-p", self.password, "ssh", *SSH_OPTS,
                    f"{self.user}@{self.host}", command]
        return ["ssh", *SSH_OPTS, f"{self.user}@{self.host}", command]

    def run(self, command, stdin=None, binary=False):
        """Returns (rc, stdout, stderr). stdout is bytes when binary=True."""
        # Never let plink/ssh/sshpass inherit the real console stdin: with no
        # redirect they share our keyboard handle directly, and plink in
        # particular can leave the console's echo/line-input mode broken
        # afterwards, silently swallowing a later input() prompt. Only the
        # upload step actually needs to feed data in.
        io_kwargs = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
        p = subprocess.run(self._argv(command), capture_output=True, timeout=300, **io_kwargs)
        out = p.stdout if binary else p.stdout.decode("utf-8", "replace")
        return p.returncode, out, p.stderr.decode("utf-8", "replace")

    def check(self, command, what):
        rc, out, err = self.run(command)
        if rc != 0:
            die(f"{what} failed", err.strip() or f"exit code {rc}")
        return out.strip()

def tool(script, *args):
    p = subprocess.run([sys.executable, os.path.join(HERE, script), *args],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout + p.stderr

# ---------------------------------------------------------------- the steps
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="do everything except installing on the Toon")
    ap.add_argument("--host", help="Toon IP address (otherwise you are asked)")
    ap.add_argument("--user", help="SSH user (default root)")
    args = ap.parse_args()

    print(f"{C.B}Toon boiler-temperature logging patch{C.X}")
    print("Restores thermstat_boilerTemp and thermstat_boilerRetTemp.")
    print(f"{C.D}Ctrl-C at any time. Nothing changes until you confirm.{C.X}")

    # deadstring.py and patch7.py disassemble the binary with capstone; without it they only
    # fail halfway, after connecting and copying, so check it before anything else
    if importlib.util.find_spec("capstone") is None:
        die("the Python module capstone is not installed",
            f"install it with:  \"{sys.executable}\" -m pip install capstone")

    # ---- connection details, asked once
    def ask(prompt, secret=False):
        raw = getpass.getpass(prompt) if secret else input(prompt)
        return raw.replace("﻿", "").strip()

    step("Your Toon")
    host = args.host or ask("  IP address of your Toon: ")
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        die(f"{host!r} is not an IP address", "Expected something like 192.168.1.20")
    user = args.user or ask("  SSH user [root]: ") or "root"
    # TOON_PASSWORD lets you avoid the prompt (handy for repeat runs)
    password = os.environ.get("TOON_PASSWORD") or ask("  SSH password: ", secret=True)
    if args.host:
        info(f"host {host}, user {user} (from the command line)")

    t = Toon(host, user, password)
    info(f"using {t.describe()}")
    if t.mode == "ssh":
        warn("install PuTTY (plink) or sshpass to avoid repeated password prompts")

    name = t.check("uname -n", "Connecting to the Toon")
    ok(f"connected to {name}")

    os.makedirs(WORK, exist_ok=True)
    stock = os.path.join(WORK, "happ_thermstat.stock")
    patched = os.path.join(WORK, "happ_thermstat.patched")
    info(f"working directory: {WORK}")

    # ---- 0. which Toon is this. CPU architecture does
    # distinguish them cleanly and is only used for the label below;
    # nothing downstream depends on which model this is.
    step("Detecting your Toon's model")
    sbin, rrd_dir = "/qmf/sbin/happ_thermstat", "/qmf/var/hcb_rrd"
    rc, _, _ = t.run(f"test -f {sbin}")
    if rc != 0:
        die(f"{sbin} not found", "this Toon's layout is not one this patch understands")
    arch = t.check("uname -m", "Reading the CPU architecture").strip()
    model = {"armv5tejl": "Toon 1 (qb2)", "armv7l": "Toon 2 (nxt)"}.get(arch, f"unrecognised ({arch})")
    ok(f"{model}: {sbin}")

    # ---- 1. copy the binary
    step("Copying happ_thermstat from the Toon")
    remote_md5 = t.check(f"md5sum {sbin}", "Reading the binary").split()[0]
    rc, blob, err = t.run(f"cat {sbin}", binary=True)
    if rc != 0 or not blob:
        die("could not copy the binary", err.strip())
    local_md5 = hashlib.md5(blob).hexdigest()
    if local_md5 != remote_md5:
        die("the copy is corrupt", f"Toon says {remote_md5}, we got {local_md5}")
    open(stock, "wb").write(blob)
    ok(f"{len(blob):,} bytes, md5 {local_md5} (matches the Toon)")
    ver = re.search(rb"VERSION\[[^\]]{0,120}\]", blob)
    info(ver.group().decode() if ver else "no version string found")

    # ---- 2. is this a build we understand
    step("Checking the binary is one this patch understands")
    rc, out = tool("analyse.py", stock)
    if rc != 0:
        die("could not read the binary", out.strip()[:300])
    if "-> 12 slots" not in out:
        die("unexpected logger table", "This build differs from the supported ones; do not force it.")
    # parse the real slot list - analyse.py also prints diagnostics that mention these
    # names, so a plain substring search gives false positives
    slots = re.findall(r"^\s*\[\s*\d+\]\s+0x[0-9a-f]+\s+(\S+)\s*$", out, re.M)
    if len(slots) != 12:
        die(f"could not read the logger table (found {len(slots)} slots, expected 12)")
    info("slots: " + ", ".join(s.replace("ventilationHeatRecoveryDev.", "vhr.") for s in slots))
    if "thermstat_boilerTemp" in slots and "thermstat_boilerRetTemp" in slots:
        ok("this Toon is ALREADY PATCHED - both boiler loggers are in the table")
        info("nothing to do; to check the loggers are recording (see 'Confirm it worked' in HOWTO.md):")
        info(f"http://{host}/hcb_rrd?action=getRrdData&loggerName=thermstat_boilerTemp&rra=30days")
        sys.exit(0)
    for needed in ("thermstat_boilerChPressure", "ventilationHeatRecoveryDev.ActiveElectricityHours",
                   "ventilationHeatRecoveryDev.CurrentState"):
        if needed not in slots:
            die(f"{needed} is missing from the table",
                "This build is not supported, or the slots this patch reuses are already taken.")
    ok("12 slots, expected loggers present, boiler loggers absent (the bug)")

    # ---- 3. device uuid
    step("Finding your Toon's thermostat device uuid")
    dat = t.check(f"grep -l -a BoilerChPressure {rrd_dir}/*.dat",
                  "Looking for a working logger").splitlines()[0].strip()
    uuid = t.check(f"dd if={dat} bs=1 skip=21 count=36 2>/dev/null", "Reading the uuid").strip()
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuid):
        die(f"that does not look like a uuid: {uuid!r}")
    ok(f"device uuid {uuid}")
    info(f"read from {os.path.basename(dat)}")

    # ---- 4. free space inside the binary
    step("Finding unused space inside the binary")
    info("scanning the whole binary for a string nothing references")
    t0 = time.time()
    rc, out = tool("deadstring.py", stock)
    info(f"scan finished in {time.time()-t0:.0f}s")
    if rc != 0:
        die("the scan for unused space failed", out.strip()[-400:])
    # patch7.py writes the uuid at +0, "avg" at +40 and "year" at +48: 56 bytes is what it checks for
    cands = re.findall(r"0x([0-9a-f]+)\s+len=(\d+)", out)
    pick = next((a for a, ln in cands if int(ln) >= 56), None)
    if not pick:
        for line in out.strip().splitlines():
            info(line)
        die("no unused string of 56+ characters found",
            "This build differs from the supported ones; please send the scan output above.")
    ok(f"using 0x{pick} (unreferenced, safe to overwrite)")

    # ---- 5/6. build and verify
    step("Building your patched binary")
    rc, out = tool("patch7.py", stock, patched, uuid, "0x" + pick)
    if rc != 0 or "outside intended 0 OK" not in out:
        die("the patcher refused", out.strip()[-400:])
    new_md5 = re.search(r"md5 patched\s+([0-9a-f]{32})", out).group(1)
    for line in out.splitlines():
        if line.startswith(("slot ", "removal-list", "deviceUuid", "dead block")):
            info(line.strip())
    ok(f"built, md5 {new_md5}")

    step("Verifying the patched binary")
    rc, out = tool("verify.py", patched)
    if "RESULT: PASS" not in out:
        die("verification failed", out.strip()[-400:])
    for line in out.splitlines():
        if line.strip().startswith(("ok ", "note ")):
            info(line.strip())
    ok("all checks passed")

    if args.dry_run:
        print(f"\n{C.Y}Dry run - stopping here.{C.X} Your patched binary is at:\n  {patched}")
        return

    # ---- 7. install
    step("Installing on the Toon")
    print(f"  This replaces {sbin} and restarts the thermostat service.")
    print(f"  A backup is kept on the Toon as happ_thermstat.stock-backup.")
    print(f"  {C.D}Your heating keeps running; the boiler falls back to its own control.{C.X}")
    # some shells (PowerShell piping text to stdin) prepend a BOM - strip it,
    # same as the ask() helper does for the earlier prompts
    confirm = input(f"  {C.B}Type 'yes' to continue: {C.X}").replace("﻿", "").strip().lower()
    if confirm != "yes":
        print("  Cancelled. Nothing was changed.")
        return

    sbin_dir = sbin.rsplit("/", 1)[0]
    rc, _, err = t.run(f"cat > {sbin}.new", stdin=open(patched, "rb").read())
    if rc != 0:
        die("upload failed", err.strip())
    up = t.check(f"md5sum {sbin}.new", "Checking the upload").split()[0]
    if up != new_md5:
        t.run(f"rm -f {sbin}.new")
        die("the uploaded file is corrupt", "nothing was installed")
    ok("uploaded and verified")

    t.check(f"cd {sbin_dir} && cp -p happ_thermstat happ_thermstat.stock-backup", "Making a backup")
    ok(f"backup saved as {sbin}.stock-backup")

    t.check(f"cd {sbin_dir} && chmod 755 happ_thermstat.new && chown root:root happ_thermstat.new "
            "&& mv happ_thermstat.new happ_thermstat", "Installing")
    live = t.check(f"md5sum {sbin}", "Confirming").split()[0]
    if live != new_md5:
        die("the installed binary does not match", "restore the backup (see below)")
    ok("installed")

    t.run("killall happ_thermstat")
    info("thermostat service restarted, waiting 25s")
    time.sleep(25)
    t.run("killall hcb_rrd")
    info("logging service restarted")

    # ---- 8. did it work
    step("Checking the loggers")
    print("  Waiting up to 3 minutes for the first readings", end="", flush=True)
    good = {}
    for _ in range(18):
        time.sleep(10)
        print(".", end="", flush=True)
        for lg in ("thermstat_boilerTemp", "thermstat_boilerRetTemp"):
            if lg in good:
                continue
            try:
                url = (f"http://{host}/hcb_rrd?action=getRrdData"
                       f"&loggerName={lg}&rra=30days")
                body = urllib.request.urlopen(url, timeout=20).read().decode()
            except Exception:
                continue
            if "unknown logger" in body:
                continue
            vals = [v for _, v in re.findall(r'"(\d+)":\s*([^,}]+)', body)
                    if v.strip() != "NaN"]
            if vals:
                good[lg] = vals[-1].strip()
        if len(good) == 2:
            break
    print()
    if len(good) == 2:
        for lg, v in good.items():
            ok(f"{lg} = {v}")
        print(f"\n{C.G}{C.B}Done.{C.X} Both loggers are recording.")
        print(f"  30 days of minute values : http://{host}/hcb_rrd?action=getRrdData"
              f"&loggerName=thermstat_boilerTemp&rra=30days")
        print(f"  a year of hourly averages: ...&rra=year")
    else:
        warn("no readings yet - this can be normal if the boiler is idle and cold")
        info("re-check in a few minutes with:")
        info(f"http://{host}/hcb_rrd?action=getRrdData&loggerName=thermstat_boilerTemp&rra=30days")

    print(f"\n{C.D}To undo, on the Toon:")
    print(f"  cd {sbin_dir} && mv happ_thermstat.stock-backup happ_thermstat")
    print(f"  killall happ_thermstat ; sleep 25 ; killall hcb_rrd{C.X}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled. Nothing was changed on your Toon.")
        sys.exit(1)

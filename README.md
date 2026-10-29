# Restoring boiler flow/return temperature logging on a rooted Toon using OpenTherm protocol to boiler

## What this fixes

Newer `happ_thermstat` builds stopped logging the boiler water temperatures, so
`thermstat_boilerTemp` (flow / *aanvoer*) and `thermstat_boilerRetTemp` (return / *retour*)
temperature data were not stored anymore sincs 2020/2021.

Quby removed the two entries from a table inside the binary. The OpenTherm code itself is
untouched an the values are still read from the boiler, they just had nowhere to go.
This patch puts the two data logger entries back into happ_thermstat.

Check whether you could use the fix:

    http://<toon-ip>/hcb_rrd?action=getRrdData&loggerName=thermstat_boilerTemp&rra=30days

    if the result contains `unknown logger` means you can go forward with the patch.

## Impact of the fix

Two data loggers for Warmtepompen will be sacrificed in favour of the boiler temperatures data sets.
(`ventilationHeatRecoveryDev.ActiveElectricityHours` and `...CurrentState`)
If you ever in the future install a warmtepomp, you can simply revert back to the stock happ_thermstat module
which is kept on your Toon.

## What do you need

- A rooted Toon (model 1 or 2) with root SSH access, and its IP address.
- Python 3 on your PC, plus capstone: `python -m pip install capstone` (the script checks for it
  before it connects to your Toon)
- The `tools/` folder from this repository.
- 5 minutes of your time

## Automated patch installer

I provided an apply_patch.py python script that does everything for you. It asks for your Toon's IP address and
password **once**, then works through every step with visible progress, and stops at the first
thing that looks wrong. Nothing is changed on the Toon until you type `yes`.
Copy all the scripts from the release package into a single folder.
The tool automatically identifies the Toon model and applies the right patch accordingly.
Start the patching process from the directory with the scripts

    python apply_patch.py

...or simply try it without touching anything first:

    python apply_patch.py --dry-run

The dry run copies your binary, checks it is a build the patch understands, reads your device uuid,
builds the patched file and verifies it and then stops before installing. If that finishes cleanly,
run it again without `--dry-run`.

If you have **PuTTY (plink)** or **sshpass** installed, the script handles the password itself. With
plain `ssh` it still works, but you will be asked for the password several times.

It also recognises a Toon that is already patched and stops, so it is safe to run twice.

## Confirm it worked

The script waits some time (two or three minutes) after the patch has been deployed, then calls:

    http://<toon-ip>/hcb_rrd?action=getRrdData&loggerName=thermstat_boilerTemp&rra=30days
    http://<toon-ip>/hcb_rrd?action=getRrdData&loggerName=thermstat_boilerRetTemp&rra=30days

to check whether real values are appended at the end.

A long archive is created too at the same URL with `&rra=year` holding hourly averages for a year.

> [!CAUTION]
> ### ⚠️ Important Warning: Device-Specific Binary
> **The patched `happ_thermstat` module will only work properly on that specific Toon because as part of the process, the device-uuid of your Toon is put into the binary.**
> 
> **If you have multiple Toons, repeat this process for each Toon. Never copy the patched binary to other Toons.**
> 
> *This script has been repeatedly successfully tested on different Toon 1 and Toon 2 thermostats on multiple firmware versions.*

## If something goes wrong you can revert back to stock happ_thermstat

    start ssh terminal and execute the following commands on the Toon:
    
    cd /qmf/sbin
    mv happ_thermstat.stock-backup happ_thermstat
    killall happ_thermstat ; sleep 25 ; killall hcb_rrd

    N.B. both processes happ_thermstat and hcb_rrd will be automatically restarted by Toon

That puts you back exactly as before the change.

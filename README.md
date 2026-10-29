# happ_thermstat — restoring boilerInTemp / boilerOutTemp RRD logging

> **Just want to apply this to your own Toon? Read [HOWTO.md](HOWTO.md) instead.**
> This file is the investigation record: how the fault was found, what was ruled out, and the
> binary internals. Useful for porting the patch to a build the scripts do not recognise, and
> not needed otherwise.

Goal: get `thermstat_boilerTemp` (boilerOutTemp) and `thermstat_boilerRetTemp` (boilerInTemp)
logged again, as the `boilerstatus` QML app reads them via
`http://<toon>/hcb_rrd?action=getRrdData&loggerName=...&rra=30days`.

## Builds

| file | build | where |
|---|---|---|
| `happ_thermstat_r2404_working_from_ipk.bin` | r2404, 25 Jun 2020 | from `happ-thermstat_1.2404-master_nxt.ipk` — **the build where this worked** |
| `happ_thermstat_r2426_stock_toon18.bin` | r2426, 4 Aug 2021 | Toon .18 (production, live OpenTherm) |
| `happ_thermstat_r2429_stock_toon16.bin` | r2429, 28 Oct 2022 | Toon .16 (test, no boiler) |
| `*_patched_*.bin` | — | table patch applied (see below) |

All builds are **unstripped**, which is what made this tractable.

## How the logging actually works

1. happ_thermstat holds a static array **`rrdDevices`** in `.data`: one 0x4c (76-byte) entry per RRD
   logger — name, package, placeholder, deviceVar, deviceSvc, sampleType, then RRA settings.
2. From it, happ_thermstat creates service variables (`createSvar_double`, via `subdevInitVars`)
   and registers loggers.
3. `hcb_rrd` (separate daemon) samples `deviceUuid`/`deviceSvc`/`deviceVar` every 60 s and writes
   `/qmf/var/hcb_rrd/<loggerUuid>.dat` + `-<rra>.rra`.
4. `/mnt/data/qmf/config/config_hcb_rrd.xml` is a **state dump written by hcb_rrd**, not an input.
   Hand-editing it does nothing — proven by adding an exact clone of a working logger, which was
   also ignored.

## CORRECTION — no code was removed (rigorous disassembly, 2026-09-18)

The "second removal" described further down is **wrong**; it is kept only as a record of the dead
end. The whole value chain is present and instruction-for-instruction identical in r2426/r2429:

- `thermostat_reinit` creates both svars (`createSvar_double(..., "ThermostatInfo",
  "CurrentBoilerTemperature")`), caching the handles at struct `+0x170` / `+0x174`.
- `parseOpenThermValue` stores the parsed values: `vstr d17,[r0,#0x148]`, `vstr d28,[r0,#0x150]`.
- `updateStatevars` publishes them: `ldr r1,[r4,#0x170]; add r2,r4,#0x148; bl svar_setValue`.

`parseDataNew`'s -1124 bytes is removed **logging**. The "zero references" finding was a tool
artefact: names are loaded pc-relative (`ldr rX,[pc,#imm]` holding an *offset*, then
`add rY,pc,rX`), invisible to absolute-address cross-referencing.

**Only the `rrdDevices` table entries were ever removed.** Everything else is a knock-on effect.

### The deviceUuid problem (second obstacle, solved)

A restored logger is created with `deviceUuid` = the literal string `"placeholder"`, so hcb_rrd
cannot bind it to a device and `rrd_removeUnused` culls it. The uuid does **not** come from the
table (proved by patching `+0x08` — no effect). It is `rrd_createMissing`'s **fourth argument** to
`rrd_createDevice`:

    rrd_createMissing:   add r3, pc, sb      -> "placeholder"        (the fallback)
                         ldr r3, [r6, #8]    -> real uuid if known
                         cmp r3, #0 ; moveq r3, <fallback>
                         bl  rrd_createDevice          ; r3 = deviceUuid
    rrd_createDevice:    mov r6, r3 ; ... <deviceUuid> emitted from r6

`patch4.py` writes the real device uuid into dead .rodata space and repoints that fallback's
literal-pool word at it. **Verified on .16:** `<deviceUuid>placeholder</deviceUuid>` became
`<deviceUuid>267ab9a6-…</deviceUuid>` and the loggers began sampling.

### What is still open

On .16 the logger is still created and culled repeatedly (its `.dat` uuid keeps changing) and only
the creation-time sample lands. The likely reason is that on .16 the svar itself is `NaN` — there
is no boiler, so nothing ever assigns it — and a logger with no data looks unused. **That can only
be settled on a Toon with a live OpenTherm boiler.** If the value is real, the logger should
survive and fill.

### Device uuids (per Toon — the patch is per-device AND per-build)

| Toon | build | thermostat deviceUuid | dead .rodata va |
|---|---|---|---|
| .16 | r2429 | `267ab9a6-f6ad-4e08-a768-8474ba831923` | `0x1189b4` |
| .18 | r2426 | `ee305848-48a8-4a57-a512-fd6ceaa1703c` | `0x1179b4` |

Read a Toon's uuid without root from any working logger:
`grep -l -a BoilerChPressure /qmf/var/hcb_rrd/*.dat` then read the uuid string inside it.

Build: `python tools/patch4.py <stock.bin> <out.bin> <device-uuid> <dead-va-hex>`
Check: `python tools/verify.py <out.bin>` (must print `RESULT: PASS`)

## Why only the newest value was kept — a hardcoded removal list (2026-09-19)

happ_thermstat carries a fixed **34-entry array of logger names** (136 bytes, at `0x1455d8` in
r2426), `memcpy`'d at the top of `rrd_removeUnused`. For every name in it that currently exists it
adds an `intAddr` argument to a **`RemoveRrd`** boxtalk message and sends it to hcb_rrd. The list
holds all ten retired loggers, including `thermstat_boilerTemp` and `thermstat_boilerRetTemp`.

With the v4 patch the loggers were therefore in a create/destroy loop — `rrd_createMissing`
recreates them (they are back in `rrdDevices`), `rrd_removeUnused` deletes them on every
device-discovery event. Measured on .18: **a new logger uuid every ~18 s**, so a fresh all-`NaN`
RRA with exactly one sample, forever. Timestamps still advance because a newly created 30-day RRA
always ends "now". Orphans do not pile up, but it writes ~2 x 345 KB every ~18 s (~0.9 GB/day).

**`patch5.py` is the fix**: v4 plus repointing those two list entries at an empty string (the NUL
terminator of an existing string), so the lookup fails and they are never put in the RemoveRrd.

**Confirmed working on .18 (2026-09-19)** — `happ_thermstat_r2426_v5_toon18.bin`, md5
`45de82820339d47899feeb65e51e92dd`. The logger uuid stopped churning, `nonNaN` climbs one per
minute, and a full cycle was recorded at 1-minute resolution: idle 23.0/23.0, ignition 33.5/26.5,
ramp 54.0/31.0 (delta 23 K), steady 64.0/44.5, peak 67.0/48.0, burner off 41.5/41.0. The flash
churn is gone as well.

## v6 — also restoring the `year` archive

An `rrdDevices` entry is 0x4c bytes: a 0x20 header, then **two** 0x14 RRA slots, then a 4-byte
terminator (32 + 2*20 + 4 = 76).

    rra[0] @ E+0x20 : futureBins, binLength, bins, consolidator*, name*
    rra[1] @ E+0x34 : futureBins, binLength, bins, consolidator*, name*
            E+0x48 : 0 terminator

r2404 defined both — `30days` (60 s bins x 43200) and `year` (3600 s bins x 8765, `avg`
consolidation). r2426/r2429 zero the entire second slot, so happ-created loggers get 30 days only.
`patch6.py` fills rra[1] back in, byte-identical to r2404. The strings `avg` and `year` no longer
exist in the newer builds, so they are written into the spare room of the same dead .rodata block
that holds the device uuid (uuid at +0, `avg` at +40, `year` at +48; the block is 120 bytes).

It refuses if the template's rra[0].binLength is not 60 or its rra[1] is not empty, so a changed
layout cannot be silently mangled. For .18: `happ_thermstat_r2426_v6_toon18.bin`, md5
`46694016fa4a02c05fbde308f8187b82`, 100 bytes changed.

Query the long archive with `...&rra=year` instead of `&rra=30days`. `rrd_configCheckRras` exists
in the binary and should reconcile an existing logger that currently has only the 30-day archive.

## Applying the patch to a future happ_thermstat build

The patcher is written to **refuse rather than guess**, but it needs two manual inputs and has one
assumption that is not self-checking.

Supply yourself:
- **device uuid** — per Toon. Read it without root from any working logger:
  `grep -l -a BoilerChPressure /qmf/var/hcb_rrd/*.dat`, then read the uuid string inside that file.
- **dead .rodata address** — per build. `python tools/deadstring.py <new.bin>` lists strings that
  nothing references (checking both absolute and pc-relative idioms); take one of >= 40 chars.

Found automatically, with a hard refusal if anything is off:
- `rrdDevices` via the symbol table (**the binary must be unstripped** — all Quby builds so far are)
- the template slot `thermstat_boilerChPressure` and the two `ventilationHeatRecoveryDev` victims
- every `add rX, pc, rY` (any register) in `rrd_createMissing` that resolves to `"placeholder"` -
  the deviceUuid fallback (at least 1; some builds compute it redundantly into more than one
  register, only one of which is ever actually used - redirecting all of them is harmless)
- one removal-list reference per logger outside `rrdDevices` (exactly 2 in total)
- exactly one copy of every string it looks up

**The one thing that could go wrong silently:** the entry layout — 0x4c stride, name at `+0x00`,
deviceVar at `+0x0c`. If Quby changes that struct the patcher will cheerfully write to the wrong
offsets. So always run `python tools/analyse.py <new.bin>` first and look at the printed table: if
each slot shows a sensible name / var / svc / type, the layout still holds.

Procedure:

    python tools/analyse.py     new.bin                 # sanity-check the table layout
    python tools/deadstring.py  new.bin                 # pick a dead address
    python tools/patch7.py      new.bin out.bin <uuid> <dead-va-hex>
    python tools/verify.py      out.bin                 # must print RESULT: PASS
    # deploy: backup, upload, chmod/chown, mv (never cp), killall happ_thermstat then hcb_rrd

Or just run `python tools/apply_patch.py` - it does all of the above itself (Toon 1 and Toon 2
both, auto-detected) and asks before installing.

Then confirm the logger `.dat` uuid **stops changing** and `nonNaN` climbs by one per minute.

Also note: the patch is per-build **and** per-device (the uuid is baked in), a firmware update
silently reverts it, and if a future build has no spare VHR slots you must pick different victims
in `TARGETS` (which costs you those loggers instead).

## Root cause — two separate removals (SUPERSEDED, see the correction above)

**1. The table was trimmed.** `rrdDevices` went from 25 slots / 18 thermostat loggers (r2404) to
12 slots / 8 (r2426 and r2429). Both boiler-temperature loggers were dropped, along with
`boilerDhwBurnerHours`, `boilerFailedBurnerStarts`, `boilerPumpStarts`,
`boilerSuccesfulBurnerStarts`, `dhwBurnerStarts`, `heatingFactor`, `longTermOffset`,
`outsideRate`. Survivors also lost their `year` RRA. Tell-tale: the strings
`CurrentBoilerTemperature` / `CurrentBoilerReturnTemperature` survive but with **zero references**.

**2. The value assignment was also removed.** Fixing the table is necessary but *not sufficient*.
With the patch live on .18 and the burner firing at 75 % modulation, both loggers stayed
**0 of 43201 non-NaN**, while `thermstat_boilerChPressure` read a healthy 1.50 bar. The svars exist
and are sampled; nothing ever assigns them.

Where that code went: the svar machinery is byte-identical between r2404 and r2426
(`updateStatevars` 760, `subdevInitVars` 744, `initVars` 120, `createSvar_double` 396,
`parseSlaveState` 328 — all unchanged) and the same 17 functions call `svar_setValue`. The largest
code reduction in the binary is **`parseDataNew`: 15624 → 14500 (−1124 bytes)**, and the two
OpenTherm diagnostics `'OpenTherm ID %d is not supported by the boiler!'` and
`'OpenTherm ID is processed with the wrong type: %d'` exist **only in r2404**. That is where to look.

## The table patch (layer 1 — works, reversible)

`tools/patch2.py <stock.bin> <out.bin>` — locates everything by symbol, refuses to run if anything
is unexpected. It clones the known-good `thermstat_boilerChPressure` slot over the two
`ventilationHeatRecoveryDev` slots (`ActiveElectricityHours`, `CurrentState`) and sets only the
name and deviceVar pointers. **28 bytes change, file size unchanged, no code touched.**

Verified effect on both Toons: loggers get created, hcb_rrd serves them instead of
`"unknown logger"`, and hcb_rrd writes proper config entries itself. Cost: two VHR loggers, which
matters only if you have a heat-recovery unit — in which case just restore the stock binary.

The patch is **per build** (r2426 and r2429 have different addresses), and any firmware update
silently reverts it.

Install (replace a *running* binary with `mv`, never `cp` — in-use executables give ETXTBSY):

    cd /qmf/sbin
    cp -p happ_thermstat happ_thermstat.stock-<rev>
    cat > happ_thermstat.patched      # upload
    chmod 755 happ_thermstat.patched && chown root:root happ_thermstat.patched
    mv happ_thermstat.patched happ_thermstat
    killall happ_thermstat            # inittab respawns it
    killall hcb_rrd

Rollback: `mv happ_thermstat.stock-<rev> happ_thermstat` then the two `killall`s.

## Do not downgrade .18 to r2404

r2404 → r2426 added 585 functions, and the **heating control rework is in r2426**, not r2429:
`UpdateBurner`, `ConfigureHeating`, `SetHeatingType`, `SetChSettings`, plus 19 new algorithm KPI
loggers (`Integrator`, `PropPart`, `IntPart`, `DeadTime`, `MeasuredHeatingFactor`, `SteadyTemp`,
`AnticipatedTempRise`, `ExpectedPreheatTime`, …). Running r2404 reverts how the house is heated.

## Analysis gotchas (each of these produced a wrong conclusion first)

- "Undefined symbol" is `st_shndx == SHN_UNDEF`, **not** `st_value == 0`.
- Local symbols carry a `.NNNN` suffix that differs per build — strip `\.\d+$` before diffing.
- Never conclude from a truncated listing: uppercase sorts before lowercase in ASCII, so a
  `head`/`Select-Object -First` cut hid every lowercase logger name.
- Don't use `\b` word boundaries when testing for strings like `TBoiler` in a binary.
- A naive capstone loop stops at literal pools; skip undecodable words and resume.
- Resolving literal-pool addresses to "nearest object/string" yields heavy noise from C++ RTTI and
  mid-string offsets. Filter to exact symbol/string starts.

## v7 — Toon 1 (qb2, ARMv5 soft-float) support, and a single script for both models (2026-09-19)

`happ_thermstat` on Toon 1 (confirmed on a live unit: `r2427`, May 2022, `master#67cc2fd682`) turned
out to be the same source, same 12-slot `rrdDevices` layout, same bug, just compiled for a different
CPU (ARMv5TE soft-float vs Toon 2's ARMv7 Cortex-A9 hard-float/NEON) and installed at `/HCBv2/sbin/`
instead of `/qmf/sbin/`. Steps 1, 2 and 4 of `patch6.py` applied to it completely unmodified.

Step 3 (the `"placeholder"` deviceUuid-fallback redirect in `rrd_createMissing`) needed
generalising. `patch6.py` assumed the fallback address is computed exactly once, directly into
`r3`, via `add r3, pc, rX`. On the Toon 1 build it's computed **twice**, into two different
stack-spilled locals (`add r7, pc, ip` and `add sl, pc, sb`) - only the second is ever loaded and
passed to `rrd_createDevice`, but both resolve to the identical address. Redirecting an instruction
whose result is never used is harmless, so **`patch7.py` redirects every `add rX, pc, rY` (any
destination register) that resolves to `"placeholder"`, not just a single `r3` one.**

This also caught something on the *existing, already-deployed Toon 2 patch*: re-running the
generalised search against the live (already-patched) Toon 2 binary found a second,
still-unredirected `"placeholder"` reference (`add r2, pc, ip`) that the original `r3`-only
`patch6.py` never touched. The deployed patch works correctly without it - only the `r3` one was
ever actually consumed - but there's no reason to leave a stray sentinel reference lying around
when closing it costs nothing. Confirmed on the true pre-patch `r2429` reference binary: `patch7.py`
finds and redirects both (`add r3, pc, sb` and `add r2, pc, ip`), 102 bytes changed, `verify.py`
passes.

`apply_patch.py` now auto-detects which Toon it's talking to and uses `patch7.py` for both -
no more separate scripts or manual model selection. First attempt at detection used path existence
(`/qmf/sbin/...` vs `/HCBv2/sbin/...`), which is **wrong**: `/HCBv2` is a symlink to `/qmf` on both
models (confirmed on both a live Toon 1 and Toon 2 unit), so both paths "exist" regardless of model
and the check always matched the first entry. It happened to still work only because both paths
resolve to the same file either way. Fixed to use `uname -m` (`armv5tejl` = Toon 1, `armv7l` =
Toon 2) for the label only; the path used is always the canonical `/qmf/sbin/happ_thermstat` since
nothing else differs between models (process names, the `hcb_rrd` HTTP API, and the .dat header
format are all identical).

Also fixed while doing this: the final `y/n` install confirmation used a bare `input()` that didn't
strip a UTF-8 BOM, unlike the `ask()` helper used for the earlier prompts - piping confirmation text
into the script (as opposed to a human typing it at a real keyboard) silently canceled the install
every time. Now stripped the same way.

**Confirmed working end-to-end via the real `apply_patch.py`** (not a manual replication) against
both models with a genuine pre-patch stock binary, freshly reset for testing:
- Toon 2 `.16`, r2429: detected correctly, built, `RESULT: PASS`, installed, both loggers recording.
- Toon 1 `.47`, r2427: detected correctly, built, `RESULT: PASS`, installed, both loggers recording,
  and the newly-created `.dat` files for both loggers carry the correct real device uuid (not
  `"placeholder"`) - direct proof the step-3 fix takes effect at runtime, not just in the checker.

`patch6.py` (Toon 2 only, `r3`-only) and the intermediate `patch6_toon1.py` are superseded and moved
to `tools-dev/` for history; `tools/` now ships only `patch7.py`.

## Next step if resumed

Rigorous instruction-level comparison of `parseDataNew` (and `parseOpenThermValue`) between r2404
and r2426 to locate the removed store and judge whether a few-instruction `svar_setValue` hook is
viable. Needs normalised instruction sequences (ignore absolute addresses) and proper alignment of
the two functions. Read-only work; no device risk.

Alternative worth trying first: find a build **between** Jun 2020 and Aug 2021 that still assigns
the values but already has the newer control loop. Any such binary can be checked in minutes with
`tools/analyse.py`.

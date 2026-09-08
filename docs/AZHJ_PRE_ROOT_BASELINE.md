# AZHJ root recovery and pre-root GPU evidence baseline

Date: 2026-09-09

This document is the canonical pre-root evidence baseline for **Galaxy S26 Ultra SM-S948N / m3q** after the device updated to **S948NKSU4AZHJ**.

The current priority is **root recovery on AZHJ**. GPU undervolting work is frozen at an offline-candidate stage until root is restored and runtime/electrical evidence is reacquired.

## Safety policy

Fail closed:

- safety/correctness not proven => **FAIL**
- `UNKNOWN / UNVERIFIED / INSUFFICIENT EVIDENCE` => **FAIL**
- no blind retries
- no live voltage writes
- no blind flashing
- no mixing AZG3 kernel/boot artifacts into AZHJ without exact-target proof
- no bypass of the existing exact firmware/kernel target gate
- static evidence first; runtime evidence only after root recovery

## Current device baseline

```text
device=Galaxy S26 Ultra SM-S948N
codename=m3q/m3qksx
firmware=S948NKSU4AZHJ
android=16
security_patch=2026-08-05
kernel=6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k
active_slot=_a
vbmeta_device_state=locked
verified_boot_state=green
flash_locked=1
root_state=unavailable after AZHJ update
```

Observed identity:

```text
ro.build.fingerprint=samsung/m3qksx/m3q:16/BP4A.251205.006/S948NKSU4AZHJ_OKR4AZHJ:user/release-keys
ro.bootimage.build.fingerprint=samsung/m3qksx/qssi_64:16/BP4A.251205.006/S948NKSU4AZHJ:user/test-keys
bootloader=S948NKSU4AZHJ
```

Observed partitions:

```text
boot_a        -> /dev/block/sda27
boot_b        -> /dev/block/sda50
init_boot_a   -> /dev/block/sda28
init_boot_b   -> /dev/block/sda51
vendor_boot_a -> /dev/block/sda29
vendor_boot_b -> /dev/block/sda52
vbmeta_a      -> /dev/block/sda39
vbmeta_b      -> /dev/block/sda57
```

Shizuku/rish remains available as UID 2000 (`shell`) under SELinux enforcing. Root is unavailable. Several tracefs/proc/module/regulator reads remain SELinux-denied from shell.

## Exact AZHJ stock artifacts

Local working directory:

```text
~/storage/downloads/undervolting
```

Stock firmware:

```text
SAMFW.COM_SM-S948N_LUC_S948NKSU4AZHJ_fac.zip
```

Extracted image hashes:

```text
235aab1ef11ae1fae7dd79b7233c6563cacc61349f8c1ee9f84c4d9fff11ffcd  AZHJ_extracted/boot_AZHJ.img
a3c11b113c9ef09fbad45464d9a2e75f616e3e6cd1c1ff37c1d1d4ea4230bd86  AZHJ_extracted/init_boot_AZHJ.img
3d6f17bcd0eff055c3b190c9f7ceec6907f7b60632b5b7d5fb3f7f828ad84e6e  AZHJ_extracted/vendor_boot_AZHJ.img
cbbec49172ba2345c5249583d5532aa1d56150476a9c0bc2a3a23f5f36cdcaf6  aop_extract/aop.mbn
```

`super.img` was converted with `simg2img -> lpunpack`; `vendor_dlkm_a.img` is EROFS and modules were extracted with `/system/bin/fsck.erofs --extract=vendor_dlkm_extract`.

## Root recovery boundary

This repository's existing exact target is AZG3:

```text
SM-S948N / m3q / m3qksx
S948NKSS4AZG3_OKR4AZG3
kernel 6.12.30-android16-5-pd30ff70-abogkiS948NKSS4AZG3-4k
M3Q Root 0.5.6
```

Current device:

```text
S948NKSU4AZHJ_OKR4AZHJ
kernel 6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k
```

Therefore:

- bypassing AZG3 exact-target checks on AZHJ: **FAIL**
- reusing AZG3 kernel/boot artifacts on AZHJ without proof: **FAIL**
- blind root/exploit retry on AZHJ: **FAIL**
- AZHJ must be treated as a new exact target with its own exact image/oracle/offset validation before any kernel write attempt

## Preserved static KGSL / Gen8 GPU evidence

This section is downstream context only. Root recovery remains the priority.

### Active GPU table

Previously established through KGSL ioctl:

```text
speed_bin = 273 decimal = 0x111
active table = qcom,gpu-pwrlevels-2
levels = 19
```

Active OPP mapping:

```text
1300 MHz -> 0x1c4
1200 MHz -> 0x1c0
1100 MHz -> 0x1b0
1050 MHz -> 0x1a0
1000 MHz -> 0x180
902  MHz -> 0x100
826  MHz -> 0x0e0
726  MHz -> 0x0c0
646  MHz -> 0x090
578  MHz -> 0x080
500  MHz -> 0x050
461  MHz -> 0x04c
422  MHz -> 0x040
382  MHz -> 0x03c
342  MHz -> 0x038
282  MHz -> 0x036
222  MHz -> 0x034
191  MHz -> 0x033
160  MHz -> 0x032
```

Exact live FDT node:

```text
/soc/qcom,kgsl-3d0@3d00000/qcom,gpu-pwrlevel-bins/qcom,gpu-pwrlevels-2/qcom,gpu-pwrlevel@0
```

Live top-OPP contract:

```text
qcom,level     = 0x1c4
qcom,gpu-freq  = 0x4d7c6d00
qcom,acd-level = 0x802d5ffd
qcom,bus-max   = 0xb
qcom,bus-min   = 0xb
qcom,bus-freq  = 0xb
reg            = 0
```

`0x4d7c6d00` is 1300000000 decimal. Any string-like DTS rendering is a `dtc` representation artifact, not corrupt data.

### ACD

Observed examples:

```text
1300: level 0x1c4, ACD 0x802d5ffd
1200: level 0x1c0, ACD 0xa02e5ffd
1100/1050 share ACD 0x88295ffd
```

ACD is not a 1:1 function of logical ARC level. Keeping the 1300 MHz stock ACD is structurally conservative, but the electrical correctness of `1300 MHz / level 0x1c0 / ACD 0x802d5ffd` remains **UNVERIFIED => FAIL**.

### Command DB / RPMh ARC

Samsung `msm_kgsl.ko` analysis established:

- `adreno_rpmh_arc_cmds()` consumes `cmd_db_read_aux_data()` u16 ARC-level arrays
- `adreno_rpmh_setup_volt_dependency_tbl()` selects the first supported ARC level `>= requested`

AOP Command DB template (`static aux base 0x15410`) yielded `gfx.lvl`:

```text
0:  0x000
1:  0x032
2:  0x033
3:  0x034
4:  0x036
5:  0x038
6:  0x03c
7:  0x040
8:  0x04c
9:  0x050
10: 0x080
11: 0x090
12: 0x0c0
13: 0x0e0
14: 0x100
15: 0x180
16: 0x1a0
17: 0x1b0
18: 0x1c0
19: 0x1c4
```

Therefore:

```text
stock 1300 request 0x1c4 -> GX index 19
candidate 1300 request 0x1c0 -> GX index 18
```

`0x1c4 -> 0x1c0` is not a no-op and is not rounded back to `0x1c4`; it is exactly one supported GX ARC step downward.

Dependent rails:

```text
gmxc.lvl: 0x1c0 index 16, 0x1c4 index 17
mx.lvl:   0x1c0 index 10, 0x1c4 index 11
```

Gen8 GX dependency uses GMXC with MX fallback, so the dependent vote also moves down one supported index.

### KGSL / GMU path

Established static path:

```text
DT qcom,level
  -> gen8_build_rpmh_tables()
  -> Command DB gfx/cx/mx/gmxc aux
  -> setup_gx_arc_votes()
  -> GMU DCVS GX votes
  -> gen8_hfi_send_gpu_perf_table()
  -> GMU firmware
  -> RPMh ARC
  -> CPR/PMIC
```

`gen8_gmu_dcvs_set()` sends GPU/BW levels through HFI command ID 30. It is not a direct microvolt write.

### Physical rail identity

Live DTS established:

```text
rpmh-regulator-gfxlvl
compatible = qcom,rpmh-arc-regulator
resource-name = gfx.lvl
regulator-name = pmh0110_f_s1_level
aliases include S1F_E0_LEVEL, S1F_LEVEL, VDD_GFX_LEVEL
```

PMIC node exists as `pmh0110@5`, compatible `qcom,spmi-pmic`, `pmic-name = pmh0110_f`.

Runtime topology previously observed:

```text
PMH0110-F S1 / gfx.lvl / regulator.4
  -> GMXC GFX voter / regulator.6
  -> gxclkctl
```

Physical GX rail identity `PMH0110-F S1 / VDD_GFX`: **PASS**.

### QPT telemetry

Extracted modules:

```text
qti_power_telemetry.ko
qptf.ko
qti_ptd_share.ko
```

Static result:

- raw ADC: **PASS**
- accumulated energy [uJ]: **PASS**
- average power [uW]: **PASS**
- physical voltage getter: **NONE**
- ADC -> uV conversion: **NONE**
- GX/S1F voltage telemetry via QPT: **FAIL**

The `number of enabled voltage nodes` string is misleading/legacy naming; the sharing path enumerates QPT nodes without voltage-type filtering and exports node ID, energy, and average power only.

### CPR

Static structure establishes that CPR resolves ARC operating levels to explicit physical voltage. The known Gen8.2.1 low-corner override affects only `0x32/0x33 -> 0x34` under `cpr_rev == 0`; it does not explain the high `0x1c4/0x1c0` pair.

Still unknown:

- actual `cpr_rev`
- physical voltage at `0x1c4`
- physical voltage at `0x1c0`
- delta mV
- factory characterization of 1300 MHz at 0x1c0

## Offline undervolt candidate — do not apply

Live FDT source:

```text
/data/data/com.termux/files/home/fdt.dtb
size=981850
sha256=2e0882bab0a2bdc48c8d8dcd9d5f782354a28a5f131e4ffdbd0d41aa7987ebd3
```

Offline candidate:

```text
fdt-1300-1c0.dtb
size=981850
sha256=98235d221ac6cdb2e4ef58a584e22bd93860762cabef9cc0727a6183b22a7d75
```

Candidate generation structurally parsed the FDT token stream, resolved the exact node/property, and modified only the 4-byte `qcom,level` payload.

Resolved offsets:

```text
PAYLOAD_OFFSET_0BASED=0x35ed0 (220880)
DIFF_BYTE_OFFSET_0BASED=0x35ed3 (220883)
DIFF_BYTE_POSITION_1BASED=220884
```

Raw `cmp -l` diff:

```text
220884 304 300
```

`cmp -l` uses octal values, so this is exactly `0xc4 -> 0xc0`.

Verified property contract:

```text
original:  qcom,level = 0x1c4
candidate: qcom,level = 0x1c0
```

Unchanged:

```text
qcom,gpu-freq  = 0x4d7c6d00
qcom,acd-level = 0x802d5ffd
qcom,bus-max   = 0xb
qcom,bus-min   = 0xb
qcom,bus-freq  = 0xb
reg            = 0
```

Semantic diff is exactly:

```diff
-qcom,level = <0x1c4>;
+qcom,level = <0x1c0>;
```

Gate:

```text
OFFLINE_STRUCTURAL_GATE=PASS
ELECTRICAL_SAFETY=UNVERIFIED_FAIL
STABILITY=UNVERIFIED_FAIL
FLASH_APPLY=FAIL
```

## Current strict gate

### PASS

- AZHJ device/build/kernel identity captured
- active slot `_a` captured
- boot state `locked / green / flash_locked=1` captured
- exact AZHJ stock boot/init_boot/vendor_boot images extracted and hashed
- active KGSL speed-bin `0x111`
- active 19-level GPU table
- 1300 MHz -> logical ARC `0x1c4`
- Command DB gfx/gmxc/mx level arrays
- first-supported `>= request` ARC quantization
- candidate `0x1c4 -> 0x1c0` changes the logical RPMh vote by exactly one supported GX step
- dependent GMXC/MX vote also moves down one supported index
- physical rail identified as PMH0110-F S1 / VDD_GFX
- runtime regulator topology identified
- ACD is independent/not 1:1 with ARC level
- QPT is not a physical voltage telemetry interface
- offline candidate byte/structure/property/semantic diff gate

### UNKNOWN / UNVERIFIED => FAIL

- AZHJ exact root primitive/oracle/offset compatibility
- AZHJ kernel R/W carrier validation
- actual physical voltage at `0x1c4`
- actual physical voltage at `0x1c0`
- physical delta mV
- actual `cpr_rev`
- 1300 MHz / `0x1c0` stability
- 1300 MHz / `0x1c0` / stock ACD electrical correctness

### FAIL / prohibited

- bypassing existing AZG3 exact-target checks
- blind exploit/root retry on AZHJ
- mixing AZG3 boot/kernel artifacts into AZHJ
- blind flash
- live voltage write
- undervolt flash/apply authorization

## Next work — root recovery first

Before any undervolt runtime testing:

1. Diff exact AZG3 and AZHJ kernel/boot images and identify all image-specific root assumptions.
2. Re-establish the AZHJ physical-P0 oracle / KASLR evidence against the exact AZHJ kernel image.
3. Re-derive and validate any exploit offsets/carriers required by the root path.
4. Preserve the one-fresh-kernel-write-per-boot / fail-closed policy; no uncertain retry in the same boot.
5. Establish failure/recovery behavior before enabling any AZHJ kernel action.
6. After exact AZHJ root recovery is proven, reacquire runtime GPU evidence:
   - regulator.4 / regulator.6 read-only telemetry
   - CPR/QFPROM `cpr_rev`
   - runtime Command DB
   - GPU/GMU/RPMh traces
   - PMH0110-F S1 read-only telemetry/SPMI if safely available
7. Re-evaluate the undervolt safety gate. The offline candidate remains non-authorized until then.

## Local provenance

```text
~/storage/downloads/undervolting/evidence/2026-09-09-AZHJ-pre-root/
  device-state.txt
  SHA256SUMS
  undervolt-candidate.txt
```

Raw firmware/device artifacts should not be committed casually. Their hashes plus derived research notes are sufficient for this tracker unless a separate evidence-storage policy is adopted.

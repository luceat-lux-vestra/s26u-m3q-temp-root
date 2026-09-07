# AZHJ native root port status

Target: Korean Galaxy S26 Ultra `SM-S948N` / `m3q`, firmware AP `S948NKSU4AZHJ`.

## Static evidence completed

- Boot Image kernel release: `6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k`.
- Boot Image kernel SHA-256: `7fe7426ef90088ab778075360c678963af2d60b35cc7943d26afb05020db4263`.
- CVE-2026-43499/GhostLock is still present. AZHJ `remove_waiter()` uses `current`
  (`SP_EL0`) for `pi_lock` / `pi_blocked_on`, not `waiter->task` as the fixed implementation does.
- Exploit-relevant kallsyms RVAs used by the AZG3 target were recovered from AZHJ and match.
  This includes `configfs_read_iter`, `init_task`, `call_usermodehelper_exec_work`,
  `system_unbound_wq`, the misc/simple_attr carrier helpers, ashmem helpers and slide anchors.
- BTF layouts used by the target match AZG3 for `task_struct`, `rt_mutex_waiter`,
  `pipe_inode_info`, `configfs_buffer`, `file`, `miscdevice`, `simple_attr`, workqueue
  structures, `cred`, `seccomp` and `mm_struct`.
- The physical-P0 fingerprint table was regenerated from the exact AZHJ raw kernel Image:
  32 slide candidates x 8 qwords at probe `0x1f0000`, with independent readback verification.

## Live identity evidence completed

Read directly from the AZHJ handset before any ported kernel write:

```text
ro.build.fingerprint=samsung/m3qksx/m3q:16/BP4A.251205.006/S948NKSU4AZHJ_OKR4AZHJ:user/release-keys
ro.build.version.incremental=S948NKSU4AZHJ
ro.product.device=m3q
uname -r=6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k
ro.bootimage.build.fingerprint=samsung/m3qksx/qssi_64:16/BP4A.251205.006/S948NKSU4AZHJ:user/test-keys
ro.build.version.security_patch=2026-08-05
```

The AZHJ target's fail-closed runtime fingerprint is therefore no longer inferred from Samsung's
naming pattern; it is device-verified.

## Remaining gate: KernelSU

The Android application path and bundled KernelSU late-load binary are still AZG3-specific.
The embedded Samsung KDP KernelSU module cannot be assumed reusable as-is because its module
`vermagic` contains the exact AZG3 kernel release. AZHJ keeps the same `android16-6.12` KMI but
has a different exact kernel release string, so the embedded module must be rebuilt or audited and
retargeted before the app may hand off to KernelSU.

`.github/workflows/azhj-port-audit.yml` performs two reproducible checks on this branch:

1. inspects the existing `ksud` embedded module, prints its `.modinfo` and undefined imports, and
   creates an audit-only equal-length AZG3->AZHJ release-string retarget for inspection;
2. builds the AZHJ native exploit payloads with Android NDK 29.

The audit-only patched `ksud` is not a production artifact and is not wired into the app.

## Build

Linux:

```sh
cd android
./build-native-azhj.sh
```

Windows PowerShell:

```powershell
cd android
.\build-native-azhj.ps1
```

Outputs are written to `exploit/build/m3q-BP4A.251205.006-AZHJ/bin`.

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

## Deliberately not enabled yet

The Android app and bundled KernelSU late-load binary remain AZG3-specific. This native port does
not claim KernelSU compatibility with AZHJ and does not alter the existing AZG3 application path.

The full runtime `ro.build.fingerprint` for AZHJ must also be read from the device before wiring
AZHJ into the app's fail-closed identity gate. The expected Samsung pattern is not treated as
verified evidence here.

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

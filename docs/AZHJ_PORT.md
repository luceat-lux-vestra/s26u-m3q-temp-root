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

## Native build gate completed

GitHub Actions built the AZHJ native payloads with Android NDK `29.0.14206865`.
The build and ELF-format checks passed. Current CI hashes are:

```text
preload.app.so                09e3267138af97b1e93ac885b412eeca638daefab1c72f7fd77940e69e3b9848
slide_oracle.app.so           baf803f1973a5611de6d22b41dd00d35f8b33171d7c23c85409390056ed99c9d
su_daemon_aarch64_pie.app     5614aeece4fe3fb475ade414534336dbd0fdde791a9a52782551925754033c5f
```

These hashes are build evidence, not release hashes; any source or toolchain change invalidates them.

## Remaining gate: KernelSU

The Android application path and bundled KernelSU late-load binary are still AZG3-specific.
The existing `ksud` is KernelSU v3.2.5/32525 and embeds its `android16-6.12_kernelsu.ko` asset through
`rust-embed` compression. The asset is therefore not a raw child ELF inside the userspace binary.
KernelSU's `debug extract-binary` userspace command is the supported non-loading extraction path.

The pinned Root-My-Galaxy Samsung patchset is
`KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`. It contains an explicit Linux 6.12 KDP path using
`kdp_usecount_sub_and_test`, so the source patch is applicable to the AZHJ kernel generation.

`.github/workflows/azhj-port-audit.yml` now:

1. audits the existing compressed AZG3 `ksud` container and verifies that its expected KMI asset and
   non-loading extraction CLI are embedded;
2. builds the AZHJ native exploit payloads with Android NDK 29;
3. builds two exact-release Android 16 / Linux 6.12 KernelSU candidates from pinned KernelSU v3.2.5
   plus the pinned Samsung KDP/RKP/DEFEX patchset: the normal Samsung path and a
   `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y` variant;
4. records candidate `vermagic`, `__versions`, undefined imports and text-patching-sensitive imports.

Neither candidate is wired into the Android app until its ABI/import contract is checked against the
exact AZHJ target and the proven AZG3 module configuration is identified.

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

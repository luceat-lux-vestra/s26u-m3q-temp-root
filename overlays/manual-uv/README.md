# Manual GPU UV overlay

This branch does **not** fork M3Q Root development. It stores only a small overlay that is applied to the latest `monovibe/s26u-m3q-temp-root` `main` at build time.

## Maintenance model

- `luceat-lux-vestra/s26u-m3q-temp-root:main` remains the normal upstream-tracking fork.
- `manual-uv-overlay` stores the overlay patch, the manual apply script, and CI.
- CI checks out the latest upstream directly from `monovibe/s26u-m3q-temp-root` on every run.
- `git apply --check` is fail-closed: upstream source drift that breaks the overlay stops the build.
- The persistent source overlay modifies only `exploit/src/targets/m3q-BP4A.251205.006/pipe.c`.
- CI changes the APK application ID and label only in the temporary build workspace so the resulting APK can coexist with the normal M3Q Root APK.

## Runtime model

The overlay does not automatically undervolt the GPU.

1. Real reboot.
2. Start Shizuku.
3. Run temporary root once using the Manual UV APK.
4. Root succeeds normally.
5. A one-shot `m3q_uv_ready` child keeps the already-proven attr carrier alive for up to 300 seconds.
6. Run `apply_gpu_uv.sh` manually through KernelSU root.
7. The script discovers the current-boot `adreno_device` pointer with the already-verified `gpuclk_show` kprobe.
8. The keeper accepts the address only if the exact 20-entry stock DCVS RAM table and level counts match.
9. Only `vote` + `dep_vote` for entries 191 MHz through 1300 MHz are changed; frequency fields and the 160 MHz floor entry are never written.
10. `host_based_dcvs` is toggled `0 -> 1 -> 0`; each direction must hit `gen8_hfi_send_gpu_perf_table` and must not hit `gen8_build_rpmh_tables`.
11. The host table is revalidated before the one-shot writer closes.

If any state after a GMU refresh cannot be proven, the script reports `REAL REBOOT REQUIRED` and the boot must not be retried.

## UV mapping

Each non-floor active state copies the exact stock `vote` and `dep_vote` from the next lower state:

- 1300 <- 1200
- 1200 <- 1100
- 1100 <- 1050
- 1050 <- 1000
- 1000 <- 902
- 902 <- 826
- 826 <- 726
- 726 <- 646
- 646 <- 578
- 578 <- 500
- 500 <- 461
- 461 <- 422
- 422 <- 382
- 382 <- 342
- 342 <- 282
- 282 <- 222
- 222 <- 191
- 191 <- 160
- 160 remains stock

No millivolt value is inferred from Qualcomm corner/VLVL IDs.

## Proof gate

Do not install or run an artifact unless the `Manual UV overlay` workflow is green for the exact overlay HEAD and records the upstream SHA used for that build.

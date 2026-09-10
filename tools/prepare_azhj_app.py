#!/usr/bin/env python3
'''Fail-closed, build-time AZHJ overlay for the unchanged AZG3 app source.'''

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

EXPECTED_ENGINE_BLOB_SHA1 = "76516319bfd3d3a7a03ed308f2dfb791db715f25"
EXPECTED_GRADLE_BLOB_SHA1 = "f554159032883d83216de48765b3afa713ff4839"
AZG3_KERNEL = "6.12.30-android16-5-pd30ff70-abogkiS948NKSS4AZG3-4k"
AZHJ_KERNEL = "6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k"
AZG3_FIRMWARE = "S948NKSS4AZG3_OKR4AZG3"
AZHJ_FIRMWARE = "S948NKSU4AZHJ_OKR4AZHJ"
REBOOT_REQUIRED_MARKER = "M3Q_AZHJ_REBOOT_REQUIRED:KSU_CONTROL_WITHOUT_FOREGROUND_RECEIPT"
STANDALONE_ACTIVATION_DISABLED_MARKER = "M3Q_AZHJ_STANDALONE_ACTIVATION_DISABLED:REBOOT_REQUIRED"
KSU_PROBE_UNVERIFIED_MARKER = "M3Q_AZHJ_KSU_PROBE_UNVERIFIED:"
KSU_READY_EXACT_LINE = "KernelSU control verified version=32525 flags=0x5 uapi=2 features=0x5"
KSU_ABSENT_EXACT_LINE = "KernelSU driver fd unavailable"
KSU_CONTROL_FAIL_PREFIX = "KernelSU control failed "
CHECKROOT_HELPER_MISSING_ANCHOR = '''        File helper = nativeFile(HELPER);
        if (!helper.isFile()) {
            return new RootState(false, false, false, "helper missing");
        }'''
CHECKROOT_HELPER_MISSING_OVERLAY = '''        File helper = nativeFile(HELPER);
        if (!helper.isFile()) {
            return new RootState(false, false, true,
                    "M3Q_AZHJ_KSU_PROBE_UNVERIFIED:HELPER_MISSING");
        }'''
CHECKROOT_INTERRUPTED_ANCHOR = '''        if (Thread.currentThread().isInterrupted()) {
            return new RootState(false, false, false, "interrupted");
        }'''
CHECKROOT_INTERRUPTED_OVERLAY = '''        if (Thread.currentThread().isInterrupted()) {
            return new RootState(false, false, true,
                    "M3Q_AZHJ_KSU_PROBE_UNVERIFIED:INTERRUPTED");
        }'''
ACTIVATE_METHOD_START = "    private int activateKernelSu(File helper, File ksud) {"
ACTIVATE_METHOD_END = "    private void appendKernelSuLog(File helper) {"
ATTEMPT_METHOD_START = "    boolean markAttemptForThisBoot() {"
ATTEMPT_METHOD_END = "    boolean hasAttemptedThisBoot() {"
PUBLIC_ACTIVATE_ANCHOR = '''    int activateKernelSu() {
        return activateKernelSu(nativeFile(HELPER), nativeFile(KSUD));
    }'''
PUBLIC_ACTIVATE_OVERLAY = '''    int activateKernelSu() {
        log("M3Q_AZHJ_STANDALONE_ACTIVATION_DISABLED:REBOOT_REQUIRED");
        return 124;
    }'''
KSU_CLASSIFY_ANCHOR = '''        String ksuOutput = String.join("\\n", ksuLines);
        if (ksuCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true, ksuOutput);
        }
        boolean kernelSu = ksuCode == 0
                && ksuOutput.contains("KernelSU control verified version=32525");
'''
KSU_CLASSIFY_OVERLAY = '''        String ksuOutput = String.join("\\n", ksuLines);
        if (ksuCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true, ksuOutput);
        }

        if (!authoritativeProbe) {
            if (hasVerifiedKernelSuThisBoot()) {
                return new RootState(true, false, false,
                        "KernelSU control verified by the root daemon for this boot");
            }
            if (verbose) {
                log("AZHJ KernelSU state lacks an authoritative shell probe; refusing fresh-root.");
            }
            return new RootState(false, false, true,
                    "M3Q_AZHJ_KSU_PROBE_UNVERIFIED:NO_AUTHORITATIVE_PROBE\\n" + ksuOutput);
        }

        int exactReadyReceipts = 0;
        int readyFamilyReceipts = 0;
        int exactAbsentReceipts = 0;
        int absentFamilyReceipts = 0;
        int controlFailReceipts = 0;
        for (String line : ksuLines) {
            if (line.startsWith("KernelSU control verified ")) {
                readyFamilyReceipts++;
            }
            if ("KernelSU control verified version=32525 flags=0x5 uapi=2 features=0x5".equals(line)) {
                exactReadyReceipts++;
            }
            if (line.startsWith("KernelSU driver fd unavailable")) {
                absentFamilyReceipts++;
            }
            if ("KernelSU driver fd unavailable".equals(line)) {
                exactAbsentReceipts++;
            }
            if (line.startsWith("KernelSU control failed ")) {
                controlFailReceipts++;
            }
        }
        boolean kernelSu = ksuCode == 0
                && exactReadyReceipts == 1
                && readyFamilyReceipts == 1
                && exactAbsentReceipts == 0
                && absentFamilyReceipts == 0
                && controlFailReceipts == 0;
        boolean kernelSuAbsent = ksuCode == 13
                && exactAbsentReceipts == 1
                && absentFamilyReceipts == 1
                && exactReadyReceipts == 0
                && readyFamilyReceipts == 0
                && controlFailReceipts == 0;
        if (!kernelSu && !kernelSuAbsent) {
            if (verbose) {
                log("AZHJ KernelSU authoritative probe is ambiguous; code=" + ksuCode
                        + " ready_receipts=" + exactReadyReceipts + "/" + readyFamilyReceipts
                        + " absent_receipts=" + exactAbsentReceipts + "/" + absentFamilyReceipts
                        + " control_fail_receipts=" + controlFailReceipts);
            }
            return new RootState(false, false, true,
                    "M3Q_AZHJ_KSU_PROBE_UNVERIFIED:code=" + ksuCode + "\\n" + ksuOutput);
        }
'''
KSU_FALLBACK_ANCHOR = '''        if (!authoritativeProbe && hasVerifiedKernelSuThisBoot()) {
            return new RootState(true, false, false,
                    "KernelSU control verified by the root daemon for this boot");
        }
'''
KSU_READY_ANCHOR = '''        if (kernelSu) {
            markKernelSuVerifiedForThisBoot();
            return new RootState(true, false, false, ksuOutput);
        }'''
KSU_READY_OVERLAY = '''        if (kernelSu && hasVerifiedKernelSuThisBoot()) {
            return new RootState(true, false, false, ksuOutput);
        }
        if (kernelSu) {
            if (verbose) {
                log("AZHJ KernelSU control detected without current foreground late-load receipt; "
                        + "reboot required before retry");
            }
            return new RootState(false, false, false,
                    "M3Q_AZHJ_REBOOT_REQUIRED:KSU_CONTROL_WITHOUT_FOREGROUND_RECEIPT\\n"
                            + ksuOutput);
        }'''
GRADLE_RELEASE_ANCHOR = '''        release {
            minifyEnabled false
            signingConfig = signingConfigs.debug
        }'''
GRADLE_RELEASE_OVERLAY = '''        release {
            applicationIdSuffix '.azhjpreflight'
            versionNameSuffix '-azhj-preflight'
            minifyEnabled false
            signingConfig = signingConfigs.debug
        }'''

AZHJ_ATTEMPT_METHOD = '''    boolean markAttemptForThisBoot() {
        if (bootSettleRemainingMillis() > 0) return false;

        /* Re-check the live state immediately before arming the one-shot receipt.
         * This closes the UI-confirmation race: a KernelSU control endpoint,
         * bootstrap root, or uncertain process state appearing after the first
         * status check must stop the exploit before any kernel write begins. */
        RootState preflight = checkRoot(false);
        if (preflight.output().contains("M3Q_AZHJ_KSU_PROBE_UNVERIFIED:")) {
            log("AZHJ final pre-exploit KernelSU probe is unverified; refusing fresh-root.");
            return false;
        }
        if (preflight.terminationUnconfirmed()) {
            log("AZHJ final pre-exploit state probe termination is unconfirmed; reboot required.");
            return false;
        }
        if (preflight.output().contains(
                "M3Q_AZHJ_REBOOT_REQUIRED:KSU_CONTROL_WITHOUT_FOREGROUND_RECEIPT")) {
            log("AZHJ KernelSU control exists without this-boot foreground receipt; reboot required.");
            return false;
        }
        if (preflight.ready()) {
            log("AZHJ KernelSU is already ready for this boot; refusing a fresh root exploit.");
            return false;
        }
        if (preflight.bootstrap()) {
            log("AZHJ bootstrap root appeared before exploit start; refusing a second root attempt.");
            return false;
        }

        synchronized (ATTEMPT_LOCK) {
            String bootId = currentBootId();
            if (bootId.isEmpty()
                    || !bootId.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                log("AZHJ current boot ID 형식을 검증하지 못해 fresh-root를 거부합니다.");
                return false;
            }

            SharedPreferences prefs = preferences();
            if (bootId.equals(prefs.getString(ATTEMPT_BOOT_ID, ""))) {
                log("AZHJ app-local same-boot attempt receipt가 이미 존재합니다.");
                return false;
            }

            /* The app-local SharedPreferences receipt disappears after uninstall.
             * Arm a shell-owned, boot-scoped receipt in /data/local/tmp before any
             * exploit process can start. The existing phase journal is checked too,
             * so reinstalling a newer APK cannot erase same-boot KSU-attempt evidence.
             * Shizuku shell is therefore an explicit AZHJ safety dependency. */
            if (!ShizukuShell.isRunning() || !ShizukuShell.isGranted()) {
                log("AZHJ durable fresh-root guard에는 Shizuku shell 권한이 필요합니다.");
                return false;
            }
            int shizukuUid = ShizukuShell.uid();
            if (shizukuUid != 2000 && shizukuUid != 0) {
                log("AZHJ durable fresh-root guard가 shell/root UID가 아니므로 실행을 거부합니다. uid="
                        + shizukuUid);
                return false;
            }

            String durableGate = "set -eu\\n"
                    + "marker='/data/local/tmp/m3q-azhj-root-attempt.log'\\n"
                    + "phase='/data/local/tmp/m3q-azhj-ksu-phase.log'\\n"
                    + "boot_id=$(cat /proc/sys/kernel/random/boot_id)\\n"
                    + "if [ \\\"$boot_id\\\" != \\\"$M3Q_EXPECT_BOOT_ID\\\" ]; then "
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_BOOT_MISMATCH; exit 125; fi\\n"
                    + "validate_boot_file() {\\n"
                    + "  path=\\\"$1\\\"; label=\\\"$2\\\"\\n"
                    + "  if [ ! -e \\\"$path\\\" ] && [ ! -L \\\"$path\\\" ]; then return 0; fi\\n"
                    + "  if [ -L \\\"$path\\\" ] || [ ! -f \\\"$path\\\" ] || [ ! -r \\\"$path\\\" ]; then "
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_PROVENANCE_INVALID:$label; exit 125; fi\\n"
                    + "  count=$(grep -c '^BOOT_ID=' \\\"$path\\\" 2>/dev/null || true)\\n"
                    + "  if [ \\\"$count\\\" -ne 1 ]; then "
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_PROVENANCE_INVALID:$label; exit 125; fi\\n"
                    + "  old_boot=$(sed -n 's/^BOOT_ID=//p' \\\"$path\\\")\\n"
                    + "  if ! printf '%s\\\\n' \\\"$old_boot\\\" | grep -Eq "
                    + "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then "
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_PROVENANCE_INVALID:$label; exit 125; fi\\n"
                    + "  if [ \\\"$old_boot\\\" = \\\"$boot_id\\\" ]; then "
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_SAME_BOOT:$label:$boot_id; exit 124; fi\\n"
                    + "}\\n"
                    + "validate_boot_file \\\"$phase\\\" phase\\n"
                    + "validate_boot_file \\\"$marker\\\" marker\\n"
                    + "tmp=\\\"${marker}.tmp.$$\\\"\\n"
                    + "trap 'rm -f -- \\\"$tmp\\\"' EXIT HUP INT TERM\\n"
                    + "rm -f -- \\\"$tmp\\\"\\n"
                    + "umask 022\\n"
                    + "printf 'SCHEMA=1\\\\nBOOT_ID=%s\\\\nSTATE=ARMED\\\\n' \\\"$boot_id\\\" > \\\"$tmp\\\"\\n"
                    + "chmod 0644 \\\"$tmp\\\"\\n"
                    + "mv -f -- \\\"$tmp\\\" \\\"$marker\\\"\\n"
                    + "trap - EXIT HUP INT TERM\\n"
                    + "sync\\n"
                    + "echo M3Q_AZHJ_ROOT_ATTEMPT_ARMED:$boot_id\\n";

            String[] environment = {
                    "HOME=/data/local/tmp",
                    "TMPDIR=/data/local/tmp",
                    "PATH=/system/bin:/system/xbin",
                    "M3Q_EXPECT_BOOT_ID=" + bootId
            };
            String[] command = {"/system/bin/sh", "-c", durableGate};
            List<String> gateLines = new ArrayList<>();
            int gateCode;
            try {
                Process process = ShizukuShell.exec(command, environment, "/data/local/tmp");
                gateCode = runProcess(process, 15, gateLines, true);
            } catch (RuntimeException error) {
                log("AZHJ durable fresh-root guard 실행 오류: " + error.getMessage());
                return false;
            }
            if (gateCode == EXIT_TERMINATION_UNCONFIRMED) {
                log("AZHJ durable fresh-root guard 종료 상태가 불명확합니다. 이 boot에서 재시도하지 마세요.");
                return false;
            }

            String gateOutput = String.join("\\n", gateLines);
            if (gateOutput.contains("M3Q_AZHJ_ROOT_ATTEMPT_SAME_BOOT:")) {
                log("AZHJ durable same-boot receipt가 이미 존재합니다. 재부팅 전 fresh-root를 차단합니다.");
                return false;
            }
            if (gateOutput.contains("M3Q_AZHJ_ROOT_ATTEMPT_PROVENANCE_INVALID:")
                    || gateOutput.contains("M3Q_AZHJ_ROOT_ATTEMPT_BOOT_MISMATCH")) {
                log("AZHJ durable attempt evidence provenance를 검증하지 못했습니다.");
                return false;
            }

            String expectedReceipt = "M3Q_AZHJ_ROOT_ATTEMPT_ARMED:" + bootId;
            int receiptCount = 0;
            for (String line : gateLines) {
                if (expectedReceipt.equals(line)) receiptCount++;
            }
            if (gateCode != 0 || receiptCount != 1) {
                log("AZHJ durable fresh-root guard의 유일한 terminal receipt를 확인하지 못했습니다. code="
                        + gateCode + " receipts=" + receiptCount);
                return false;
            }

            if (!prefs.edit().putString(ATTEMPT_BOOT_ID, bootId).commit()) {
                log("AZHJ durable receipt는 기록됐지만 app-local receipt 저장에 실패했습니다. "
                        + "안전을 위해 이 boot를 소비한 것으로 처리합니다.");
                return false;
            }
            log("AZHJ durable fresh-root attempt armed boot=" + bootId);
            return true;
        }
    }'''

AZHJ_ACTIVATE_METHOD = '''    private int activateKernelSu(File helper, File ksud) {
        if (!helper.isFile() || !ksud.isFile()) {
            log("KernelSU loader를 APK에서 찾지 못했습니다.");
            return 126;
        }

        /* This private path is the uninterrupted continuation of runFreshRoot()
         * after its root process returned success. The standalone activation-only
         * entry point is disabled for AZHJ. The durable phase journal therefore
         * acts only as a same-boot re-entry/provenance lock once activation begins.
         * The helper -c client does not reliably propagate the inner shell rc;
         * this gate accepts only one exact terminal marker. */
        String journalGuard = "set -u\\n"
                + "journal='/data/local/tmp/m3q-azhj-ksu-phase.log'\\n"
                + "boot_id=$(cat /proc/sys/kernel/random/boot_id)\\n"
                + "if [ ! -e \\\"$journal\\\" ]; then "
                + "echo M3Q_AZHJ_ACTIVATION_JOURNAL_ABSENT; exit 0; fi\\n"
                + "count=$(grep -c '^BOOT_ID=' \\\"$journal\\\" 2>/dev/null || true)\\n"
                + "if [ \\\"$count\\\" -ne 1 ]; then "
                + "echo M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID; exit 0; fi\\n"
                + "old_boot=$(sed -n 's/^BOOT_ID=//p' \\\"$journal\\\")\\n"
                + "if [ \\\"$old_boot\\\" = \\\"$boot_id\\\" ]; then "
                + "echo M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS:$boot_id; exit 0; fi\\n"
                + "echo M3Q_AZHJ_PRIOR_BOOT_JOURNAL:$old_boot\\n";
        List<String> journalLines = new ArrayList<>();
        ProcessBuilder journalProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", journalGuard);
        journalProcess.redirectErrorStream(true);
        int journalCode = runProcess(journalProcess, 15, journalLines, true);
        if (journalCode == EXIT_TERMINATION_UNCONFIRMED) {
            return journalCode;
        }
        String journalOutput = String.join("\\n", journalLines);
        if (journalOutput.contains("M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS:")) {
            log("이 boot에서 KernelSU activation journal이 이미 존재합니다. 재부팅 전 재시도를 차단합니다.");
            return 124;
        }
        if (journalOutput.contains("M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID")) {
            log("AZHJ phase journal provenance가 불명확하여 증거를 덮어쓰지 않습니다.");
            return 125;
        }
        boolean journalAbsent = journalOutput.contains("M3Q_AZHJ_ACTIVATION_JOURNAL_ABSENT");
        boolean priorBoot = journalOutput.contains("M3Q_AZHJ_PRIOR_BOOT_JOURNAL:");
        if (journalCode != 0 || journalAbsent == priorBoot) {
            log("AZHJ activation journal guard의 유일한 terminal receipt를 확인하지 못했습니다.");
            return 125;
        }

        status("KernelSU 활성화 중", STATUS_WORKING);
        int code = AzhjKernelSuPreloader.activate(context, helper, ksud);
        if (code == EXIT_TERMINATION_UNCONFIRMED) {
            log("AZHJ KernelSU foreground late-load 종료 상태를 확인하지 못했습니다.");
            return code;
        }
        if (code == 124) {
            log("AZHJ KernelSU가 이미 활성화됐지만 현재 boot의 foreground receipt가 없습니다. "
                    + "재부팅 후 다시 시도해야 합니다.");
            appendKernelSuLog(helper);
            return code;
        }
        if (code != 0) {
            log("AZHJ KernelSU foreground late-load handoff 실패 code=" + code);
            appendKernelSuLog(helper);
            return code;
        }

        /* AzhjKernelSuPreloader returns 0 only after the custom foreground ksud
         * has completed embedded-KO late-load and the root-context native
         * worker has verified exact v32525 control. The helper K protocol
         * propagates that worker status as the completion barrier; no app-UID
         * KernelSU discovery syscall is issued. Only then issue this-boot ready receipt. */
        if (!markKernelSuVerifiedForThisBoot()) {
            log("KernelSU는 foreground late-load 검증됐지만 이 boot ID의 영수증을 저장하지 못했습니다.");
            return 123;
        }
        log("KernelSU 3.2.5 LKM foreground late-load 검증 완료");
        return 0;
    }'''


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def replace_exact(text: str, old: str, new: str, expected_count: int = 1) -> str:
    count = text.count(old)
    if count != expected_count:
        raise SystemExit(
            f"FAIL: expected {expected_count} occurrence(s) of {old!r}, found {count}"
        )
    return text.replace(old, new)


def replace_region_exact(text: str, start: str, end: str, replacement: str) -> str:
    if text.count(start) != 1:
        raise SystemExit(f"FAIL: region start cardinality={text.count(start)} for {start!r}")
    if text.count(end) != 1:
        raise SystemExit(f"FAIL: region end cardinality={text.count(end)} for {end!r}")
    begin = text.index(start)
    finish = text.index(end, begin)
    if finish <= begin:
        raise SystemExit("FAIL: replacement region boundary order invalid")
    return text[:begin] + replacement + "\n\n" + text[finish:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("engine", type=Path)
    parser.add_argument("gradle", type=Path)
    args = parser.parse_args()

    raw = args.engine.read_bytes()
    blob = git_blob_sha1(raw)
    print(f"ENGINE_SOURCE_GIT_BLOB_SHA1={blob}")
    if blob != EXPECTED_ENGINE_BLOB_SHA1:
        raise SystemExit(
            "FAIL: M3qRootEngine.java source changed; re-audit the overlay before building AZHJ"
        )

    text = raw.decode("utf-8")
    text = replace_exact(text, AZG3_KERNEL, AZHJ_KERNEL)
    text = replace_exact(text, AZG3_FIRMWARE, AZHJ_FIRMWARE)
    text = replace_exact(text, "AZG3 root-single", "AZHJ root-single", expected_count=2)
    text = replace_exact(text, CHECKROOT_HELPER_MISSING_ANCHOR, CHECKROOT_HELPER_MISSING_OVERLAY)
    text = replace_exact(text, CHECKROOT_INTERRUPTED_ANCHOR, CHECKROOT_INTERRUPTED_OVERLAY)
    text = replace_exact(text, KSU_CLASSIFY_ANCHOR, KSU_CLASSIFY_OVERLAY)
    text = replace_exact(text, KSU_FALLBACK_ANCHOR, "")
    text = replace_exact(text, KSU_READY_ANCHOR, KSU_READY_OVERLAY)
    text = replace_exact(text, PUBLIC_ACTIVATE_ANCHOR, PUBLIC_ACTIVATE_OVERLAY)
    text = replace_region_exact(
        text, ATTEMPT_METHOD_START, ATTEMPT_METHOD_END, AZHJ_ATTEMPT_METHOD
    )
    text = replace_region_exact(
        text, ACTIVATE_METHOD_START, ACTIVATE_METHOD_END, AZHJ_ACTIVATE_METHOD
    )

    if AZG3_KERNEL in text or AZG3_FIRMWARE in text:
        raise SystemExit("FAIL: stale AZG3 identity remains in transformed engine")
    if text.count("AzhjKernelSuPreloader.activate(context, helper, ksud)") != 1:
        raise SystemExit("FAIL: AZHJ foreground handoff hook cardinality mismatch")
    if text.count("AZHJ KernelSU control detected without current foreground late-load receipt") != 1:
        raise SystemExit("FAIL: AZHJ reboot-required recovery-state overlay cardinality mismatch")
    if text.count(REBOOT_REQUIRED_MARKER) != 2:
        raise SystemExit("FAIL: AZHJ dirty-KSU reboot-required marker cardinality mismatch")
    if text.count(STANDALONE_ACTIVATION_DISABLED_MARKER) != 1:
        raise SystemExit("FAIL: AZHJ standalone activation-only disable marker cardinality mismatch")
    if "return activateKernelSu(nativeFile(HELPER), nativeFile(KSUD));" in text:
        raise SystemExit("FAIL: AZHJ standalone activation-only entry still reaches private activation")
    if "Bootstrap-only activation intentionally bypasses" in text:
        raise SystemExit("FAIL: stale bootstrap-only recovery contract remains")
    if text.count("RootState preflight = checkRoot(false);") != 1:
        raise SystemExit("FAIL: AZHJ final pre-exploit live-state probe missing")
    if text.count("AZHJ bootstrap root appeared before exploit start") != 1:
        raise SystemExit("FAIL: AZHJ pre-exploit bootstrap race guard missing")
    if text.count("KernelSU 3.2.5 LKM foreground late-load 검증 완료") != 1:
        raise SystemExit("FAIL: AZHJ foreground-authoritative ready receipt missing")
    if text.count("M3Q_AZHJ_SAME_BOOT_ACTIVATION_EXISTS:") != 2:
        raise SystemExit("FAIL: AZHJ same-boot activation guard cardinality mismatch")
    if text.count("M3Q_AZHJ_PHASE_JOURNAL_PROVENANCE_INVALID") != 2:
        raise SystemExit("FAIL: AZHJ journal provenance guard cardinality mismatch")
    if text.count("M3Q_AZHJ_ACTIVATION_JOURNAL_ABSENT") != 2:
        raise SystemExit("FAIL: AZHJ journal-absent receipt cardinality mismatch")
    if text.count("M3Q_AZHJ_PRIOR_BOOT_JOURNAL:") != 2:
        raise SystemExit("FAIL: AZHJ prior-boot journal receipt cardinality mismatch")
    if text.count("/data/local/tmp/m3q-azhj-root-attempt.log") != 1:
        raise SystemExit("FAIL: AZHJ durable root-attempt marker path cardinality mismatch")
    if text.count("M3Q_AZHJ_ROOT_ATTEMPT_ARMED:") != 2:
        raise SystemExit("FAIL: AZHJ durable root-attempt armed receipt cardinality mismatch")
    if text.count("M3Q_AZHJ_ROOT_ATTEMPT_SAME_BOOT:") != 2:
        raise SystemExit("FAIL: AZHJ durable same-boot guard cardinality mismatch")
    if text.count("M3Q_AZHJ_ROOT_ATTEMPT_PROVENANCE_INVALID:") != 4:
        raise SystemExit("FAIL: AZHJ durable attempt provenance guard cardinality mismatch")
    if text.count("M3Q_AZHJ_ROOT_ATTEMPT_BOOT_MISMATCH") != 2:
        raise SystemExit("FAIL: AZHJ durable boot-id cross-check cardinality mismatch")
    if text.count(KSU_PROBE_UNVERIFIED_MARKER) != 5:
        raise SystemExit("FAIL: AZHJ strict KernelSU unverified-state marker cardinality mismatch")
    if text.count("readyFamilyReceipts == 1") != 1 or text.count("absentFamilyReceipts == 1") != 1:
        raise SystemExit("FAIL: AZHJ KernelSU terminal-family cardinality predicates missing")
    if "return new RootState(false, false, false, \"helper missing\")" in text:
        raise SystemExit("FAIL: AZHJ helper-missing preflight still fails open")
    if "return new RootState(false, false, false, \"interrupted\")" in text:
        raise SystemExit("FAIL: AZHJ interrupted preflight still fails open")
    if text.count(KSU_READY_EXACT_LINE) != 1:
        raise SystemExit("FAIL: AZHJ exact KernelSU ready receipt cardinality mismatch")
    if text.count(KSU_ABSENT_EXACT_LINE) != 2:
        raise SystemExit("FAIL: AZHJ exact/family KernelSU absence receipt cardinality mismatch")
    if text.count(KSU_CONTROL_FAIL_PREFIX) != 1:
        raise SystemExit("FAIL: AZHJ KernelSU control-failure discriminator cardinality mismatch")
    if "ksuOutput.contains(\"KernelSU control verified version=32525\")" in text:
        raise SystemExit("FAIL: stale substring-only KernelSU ready classification remains")
    if "if (!authoritativeProbe && hasVerifiedKernelSuThisBoot())" in text:
        raise SystemExit("FAIL: stale non-authoritative KernelSU fallback remains outside strict classifier")
    if text.count("exactReadyReceipts == 1") != 1 or text.count("exactAbsentReceipts == 1") != 1:
        raise SystemExit("FAIL: exact KernelSU terminal receipt cardinality predicates missing")
    if text.count("ksuCode == 13") != 1:
        raise SystemExit("FAIL: exact KernelSU absence return-code gate missing")
    if "recover with KernelSU activation only" in text:
        raise SystemExit("FAIL: stale same-boot recovery guidance remains")
    if "KernelSU 3.2.5 LKM late-load daemon 검증 완료" in text:
        raise SystemExit("FAIL: stale daemon-authoritative ready receipt remains")
    if "AzhjKernelSuPreloader.ensureLoaded(" in text:
        raise SystemExit("FAIL: stale AZHJ preloader sequencing remains")
    if "KernelSU module insmod 후 control 검증 실패" in text:
        raise SystemExit("FAIL: stale post-insmod Shizuku control gate remains")
    if "private int activateKernelSu(File helper, File ksud)" not in text:
        raise SystemExit("FAIL: transformed activation method missing")
    if "markKernelSuVerifiedForThisBoot();\n            return new RootState(true" in text:
        raise SystemExit("FAIL: AZHJ checkRoot still self-issues a KernelSU ready receipt")
    if AZHJ_KERNEL not in text or AZHJ_FIRMWARE not in text:
        raise SystemExit("FAIL: exact AZHJ identity missing after transform")

    encoded = text.encode("utf-8")
    args.engine.write_bytes(encoded)
    print(f"ENGINE_AZHJ_SHA256={hashlib.sha256(encoded).hexdigest()}")
    print("AZHJ_DIRTY_KSU_REBOOT_REQUIRED_GATE=PASS")
    print("AZHJ_STRICT_KSU_PREFLIGHT_GATE=PASS")
    print("AZHJ_FINAL_PRE_EXPLOIT_STATE_GATE=PASS")
    print("AZHJ_STANDALONE_ACTIVATION_DISABLED_GATE=PASS")
    print("AZHJ_DURABLE_ROOT_ATTEMPT_GUARD_OVERLAY=PASS")

    gradle_raw = args.gradle.read_bytes()
    gradle_blob = git_blob_sha1(gradle_raw)
    print(f"GRADLE_SOURCE_GIT_BLOB_SHA1={gradle_blob}")
    if gradle_blob != EXPECTED_GRADLE_BLOB_SHA1:
        raise SystemExit(
            "FAIL: app/build.gradle source changed; re-audit the AZHJ overlay before building"
        )
    gradle_text = gradle_raw.decode("utf-8")
    gradle_text = replace_exact(
        gradle_text, GRADLE_RELEASE_ANCHOR, GRADLE_RELEASE_OVERLAY
    )
    if gradle_text.count("applicationIdSuffix '.azhjpreflight'") != 1:
        raise SystemExit("FAIL: AZHJ applicationIdSuffix overlay cardinality mismatch")
    gradle_encoded = gradle_text.encode("utf-8")
    args.gradle.write_bytes(gradle_encoded)
    print(f"GRADLE_AZHJ_SHA256={hashlib.sha256(gradle_encoded).hexdigest()}")
    print("AZHJ_APP_SOURCE_OVERLAY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

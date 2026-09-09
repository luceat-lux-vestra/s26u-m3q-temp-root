package dev.indevelopment.m3qroot;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/** AZHJ-only fresh-boot KernelSU foreground late-load coordinator. */
final class AzhjKernelSuPreloader {
    private static final String TAG = "M3qRoot-AZHJ";
    private static final String MODEL = "SM-S948N";
    private static final String KERNEL =
            "6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k";
    private static final String FINGERPRINT =
            "samsung/m3qksx/m3q:16/BP4A.251205.006/" +
                    "S948NKSU4AZHJ_OKR4AZHJ:user/release-keys";

    private static final String MODULE_NATIVE_NAME = "libm3qksumodule.so";
    private static final String HELPER_STAGE =
            "/data/local/tmp/m3qroot-helper-S948NKSU4AZHJ";
    /* Must match exploit/src/su_daemon.c KSU_LOADER_PATH. */
    private static final String KSU_LOADER_STAGE =
            "/data/local/tmp/ksud-m3q-S948NKSS4AZG3-kdp";
    private static final String MODULE_WITNESS_STAGE =
            "/data/local/tmp/kernelsu-m3q-S948NKSU4AZHJ.ko";
    private static final String EMBEDDED_PROBE_STAGE =
            "/data/local/tmp/.m3q-azhj-embedded-kernelsu.ko";
    private static final String KSU_LOG = "/data/local/tmp/m3q-kernelsu-late-load.log";
    private static final String PHASE_JOURNAL =
            "/data/local/tmp/m3q-azhj-ksu-phase.log";

    private static final String HELPER_SHA256 =
            "f13f2a19d4b6b3154af68a42f8bdbc085e5295cc3700d48b25d514f51f074139";
    private static final String MODULE_SHA256 =
            "e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7";
    private static final String KSUD_SHA256 =
            "83c754dcbacf1c5bd96836cc52380dcd5b5c9273e1f6a8bedfde2ddc0b7f3ab4";

    private static final String CONTROL_OK_MARKER = "M3Q_AZHJ_DAEMON_KSU_CONTROL_OK";
    private static final String CONTROL_FAIL_PREFIX = "M3Q_AZHJ_DAEMON_KSU_CONTROL_FAIL:";
    private static final String CONTROL_EXACT_LINE =
            "KernelSU control verified version=32525 flags=0x5 uapi=2 features=0x5";
    private static final String PHASE_RECEIPT_PREFIX = "M3Q_AZHJ_PHASE_RECORDED:";
    private static final String EMBEDDED_RECEIPT_PREFIX =
            "M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:";

    private static final int EXIT_REBOOT_REQUIRED = 124;
    private static final int TIMEOUT_STAGE_SECONDS = 30;
    private static final int TIMEOUT_CONTROL_SECONDS = 20;
    private static final int TIMEOUT_LATE_LOAD_SECONDS = 180;

    private AzhjKernelSuPreloader() {}

    static int activate(Context context, File helper, File ksud) {
        if (!MODEL.equals(Build.MODEL)
                || !KERNEL.equals(System.getProperty("os.version", ""))
                || !FINGERPRINT.equals(Build.FINGERPRINT)) {
            Log.e(TAG, "refusing KernelSU activation on non-AZHJ exact target");
            return 126;
        }
        if (!helper.isFile() || !ksud.isFile()) {
            Log.e(TAG, "required AZHJ KernelSU files are missing");
            return 126;
        }

        File moduleWitness = new File(
                context.getApplicationInfo().nativeLibraryDir, MODULE_NATIVE_NAME);
        if (!moduleWitness.isFile()) {
            Log.e(TAG, "AZHJ KernelSU module witness is missing");
            return 126;
        }

        try {
            String helperHash = sha256(helper);
            String ksudHash = sha256(ksud);
            String moduleHash = sha256(moduleWitness);
            if (!HELPER_SHA256.equals(helperHash)
                    || !KSUD_SHA256.equals(ksudHash)
                    || !MODULE_SHA256.equals(moduleHash)) {
                Log.e(TAG, "refusing KernelSU activation: packaged hash mismatch helper="
                        + helperHash + " ksud=" + ksudHash + " module=" + moduleHash);
                return 125;
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "failed to hash AZHJ KernelSU packaged files", e);
            return 125;
        }

        /* Do not invoke --ksu-info directly from an untrusted_app child here.
         * KernelSU driver discovery uses the reboot magic syscall, which Samsung
         * seccomp may kill before KernelSU's always-allow GET_INFO permission
         * check is reached. All pre-write control discovery therefore runs in
         * the already-rooted bootstrap daemon context. */
        int code = stageBootstrapAssets(context, helper, ksud, moduleWitness);
        if (code != 0) return code;

        code = recordPhase(context, helper, "PRE_LATE_LOAD_CONTROL_PROBE");
        if (code != 0) return code;

        ProbeResult daemon = probeDaemonControl(context, helper);
        if (daemon.kind == ProbeKind.READY) {
            Log.e(TAG, "KernelSU already ready before authorized late-load; reboot required");
            return EXIT_REBOOT_REQUIRED;
        }
        if (daemon.kind != ProbeKind.ABSENT) {
            Log.e(TAG, "daemon KernelSU pre-probe did not prove absence code="
                    + daemon.code + " output=" + daemon.output);
            return daemon.code != 0 ? daemon.code : 125;
        }

        code = recordPhase(context, helper, "KSU_ABSENT_PROVEN");
        if (code != 0) return code;
        code = verifyEmbeddedModule(context, helper);
        if (code != 0) return code;
        code = recordPhase(context, helper, "EMBEDDED_MODULE_VERIFIED");
        if (code != 0) return code;
        code = recordPhase(context, helper, "PRE_LATE_LOAD");
        if (code != 0) return code;

        /* This is the single authorized KernelSU kernel-write entry. The native
         * helper's K protocol returns status 0 only after the custom foreground
         * ksud has completed embedded-KO late-load and the root-context worker
         * independently verifies exact KernelSU v32525 control. The successful
         * K response also causes the bootstrap daemon to unlink its socket and
         * terminate. Do not issue any post-write bootstrap-daemon command and
         * do not invoke --ksu-info from the app UID. */
        CommandResult late = runDirect(
                context,
                new String[]{helper.getAbsolutePath(), "--late-load"},
                TIMEOUT_LATE_LOAD_SECONDS);
        Log.i(TAG, "AZHJ KernelSU foreground late-load code=" + late.code
                + " output=" + late.output);
        if (late.code != 0) return late.code;

        Log.i(TAG, "M3Q_AZHJ_KSU_FOREGROUND_LATE_LOAD_OK");
        Log.i(TAG, "M3Q_AZHJ_KSU_READY:" + CONTROL_EXACT_LINE);
        return 0;
    }

    private static int stageBootstrapAssets(
            Context context, File helper, File ksud, File moduleWitness) {
        String command = "set -eu\n"
                + "helper_src=" + shellQuote(helper.getAbsolutePath()) + "\n"
                + "ksud_src=" + shellQuote(ksud.getAbsolutePath()) + "\n"
                + "module_src=" + shellQuote(moduleWitness.getAbsolutePath()) + "\n"
                + "helper_stage=" + shellQuote(HELPER_STAGE) + "\n"
                + "loader_stage=" + shellQuote(KSU_LOADER_STAGE) + "\n"
                + "module_stage=" + shellQuote(MODULE_WITNESS_STAGE) + "\n"
                + "probe_stage=" + shellQuote(EMBEDDED_PROBE_STAGE) + "\n"
                + "late_log=" + shellQuote(KSU_LOG) + "\n"
                + "journal=" + shellQuote(PHASE_JOURNAL) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "mkdir -p /data/adb\n"
                + "rm -f -- \"$helper_stage\" \"$loader_stage\" \"$module_stage\" "
                + "\"$probe_stage\" \"$late_log\" \"$journal\"\n"
                + "boot_id=$(cat /proc/sys/kernel/random/boot_id)\n"
                + "umask 022\n"
                + "printf 'SCHEMA=2\\nBOOT_ID=%s\\nHELPER_SHA256=%s\\nKSUD_SHA256=%s\\n"
                + "MODULE_SHA256=%s\\nROUTE=FOREGROUND_EMBEDDED_LATE_LOAD\\nPHASE=STAGE_BEGIN\\n' "
                + "\"$boot_id\" \"$expected_helper\" \"$expected_ksud\" "
                + "\"$expected_module\" > \"$journal\"\n"
                + "chmod 0644 \"$journal\"\n"
                + "sync\n"
                + "cp \"$helper_src\" \"$helper_stage\"\n"
                + "cp \"$ksud_src\" \"$loader_stage\"\n"
                + "cp \"$module_src\" \"$module_stage\"\n"
                + "chmod 0700 \"$helper_stage\" \"$loader_stage\"\n"
                + "chmod 0600 \"$module_stage\"\n"
                + "h_helper=$(sha256sum \"$helper_stage\"); h_helper=${h_helper%% *}\n"
                + "h_loader=$(sha256sum \"$loader_stage\"); h_loader=${h_loader%% *}\n"
                + "h_module=$(sha256sum \"$module_stage\"); h_module=${h_module%% *}\n"
                + "test \"$h_helper\" = \"$expected_helper\"\n"
                + "test \"$h_loader\" = \"$expected_ksud\"\n"
                + "test \"$h_module\" = \"$expected_module\"\n"
                + "printf 'PHASE=BOOTSTRAP_STAGE_OK\\n' >> \"$journal\"\n"
                + "sync\n"
                + "echo M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:$h_helper:$h_loader:$h_module\n";

        CommandResult result = runRootCommand(context, helper, command, TIMEOUT_STAGE_SECONDS);
        Log.i(TAG, "AZHJ bootstrap stage code=" + result.code + " output=" + result.output);
        String receipt = "M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:"
                + HELPER_SHA256 + ":" + KSUD_SHA256 + ":" + MODULE_SHA256;
        if (result.code != 0 || !result.output.contains(receipt)) {
            Log.e(TAG, "AZHJ bootstrap staging lacks exact completion receipt");
            return result.code != 0 ? result.code : 125;
        }
        return 0;
    }

    private static int verifyEmbeddedModule(Context context, File helper) {
        String command = "set -eu\n"
                + "loader=" + shellQuote(KSU_LOADER_STAGE) + "\n"
                + "witness=" + shellQuote(MODULE_WITNESS_STAGE) + "\n"
                + "extracted=" + shellQuote(EMBEDDED_PROBE_STAGE) + "\n"
                + "journal=" + shellQuote(PHASE_JOURNAL) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "current_boot=$(cat /proc/sys/kernel/random/boot_id)\n"
                + "test -f \"$journal\"\n"
                + "grep -Fqx 'SCHEMA=2' \"$journal\"\n"
                + "grep -Fqx 'ROUTE=FOREGROUND_EMBEDDED_LATE_LOAD' \"$journal\"\n"
                + "grep -Fqx \"BOOT_ID=$current_boot\" \"$journal\"\n"
                + "grep -Fqx \"KSUD_SHA256=$expected_ksud\" \"$journal\"\n"
                + "grep -Fqx \"MODULE_SHA256=$expected_module\" \"$journal\"\n"
                + "loader_hash=$(sha256sum \"$loader\"); loader_hash=${loader_hash%% *}\n"
                + "witness_hash=$(sha256sum \"$witness\"); witness_hash=${witness_hash%% *}\n"
                + "test \"$loader_hash\" = \"$expected_ksud\"\n"
                + "test \"$witness_hash\" = \"$expected_module\"\n"
                + "export loader extracted expected_module\n"
                + "unshare -m /system/bin/sh -c '"
                + "set -eu; "
                + "mount -o rslave none /; "
                + "mount --bind \"$loader\" /system/bin/logcat; "
                + "rm -f -- \"$extracted\"; "
                + "/system/bin/logcat debug extract-binary android16-6.12_kernelsu.ko \"$extracted\"; "
                + "h=$(sha256sum \"$extracted\"); h=${h%% *}; "
                + "rm -f -- \"$extracted\"; "
                + "if [ \"$h\" != \"$expected_module\" ]; then "
                + "echo M3Q_AZHJ_EMBEDDED_MODULE_HASH_MISMATCH:$h; exit 125; fi; "
                + "echo " + EMBEDDED_RECEIPT_PREFIX + "$h'\n";

        CommandResult result = runRootCommand(context, helper, command, TIMEOUT_STAGE_SECONDS);
        Log.i(TAG, "AZHJ embedded module verify code=" + result.code
                + " output=" + result.output);
        if (result.code != 0
                || !result.output.contains(EMBEDDED_RECEIPT_PREFIX + MODULE_SHA256)) {
            Log.e(TAG, "AZHJ embedded KernelSU module lacks exact verification receipt");
            return result.code != 0 ? result.code : 125;
        }
        return 0;
    }

    private static int recordPhase(Context context, File helper, String phase) {
        if (!phase.matches("[A-Z0-9_]+")) {
            Log.e(TAG, "invalid AZHJ phase journal token: " + phase);
            return 125;
        }
        String receipt = PHASE_RECEIPT_PREFIX + phase;
        String command = "set -eu\n"
                + "journal=" + shellQuote(PHASE_JOURNAL) + "\n"
                + "phase=" + shellQuote(phase) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "current_boot=$(cat /proc/sys/kernel/random/boot_id)\n"
                + "test -f \"$journal\"\n"
                + "grep -Fqx 'SCHEMA=2' \"$journal\"\n"
                + "grep -Fqx 'ROUTE=FOREGROUND_EMBEDDED_LATE_LOAD' \"$journal\"\n"
                + "grep -Fqx \"BOOT_ID=$current_boot\" \"$journal\"\n"
                + "grep -Fqx \"HELPER_SHA256=$expected_helper\" \"$journal\"\n"
                + "grep -Fqx \"KSUD_SHA256=$expected_ksud\" \"$journal\"\n"
                + "grep -Fqx \"MODULE_SHA256=$expected_module\" \"$journal\"\n"
                + "printf 'PHASE=%s\\n' \"$phase\" >> \"$journal\"\n"
                + "chmod 0644 \"$journal\"\n"
                + "sync\n"
                + "echo " + shellQuote(receipt) + "\n";

        CommandResult result = runRootCommand(context, helper, command, TIMEOUT_STAGE_SECONDS);
        Log.i(TAG, "AZHJ phase journal " + phase + " code=" + result.code
                + " output=" + result.output);
        if (result.code != 0 || !result.output.contains(receipt)) {
            Log.e(TAG, "AZHJ phase journal lacks exact durable receipt for " + phase);
            return result.code != 0 ? result.code : 125;
        }
        return 0;
    }

    private static ProbeResult probeDaemonControl(Context context, File helper) {
        String command = "set -u\n"
                + "helper_stage=" + shellQuote(HELPER_STAGE) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "if [ ! -f \"$helper_stage\" ]; then "
                + "echo M3Q_AZHJ_DAEMON_KSU_CONTROL_STAGE_MISSING; exit 0; fi\n"
                + "h=$(sha256sum \"$helper_stage\"); h=${h%% *}\n"
                + "if [ \"$h\" != \"$expected_helper\" ]; then "
                + "echo M3Q_AZHJ_DAEMON_KSU_CONTROL_HELPER_HASH_MISMATCH:$h; exit 0; fi\n"
                + "export helper_stage\n"
                + "unshare -m /system/bin/sh -c '"
                + "set -u; mount -o rslave none / || exit 126; "
                + "mount --bind \"$helper_stage\" /system/bin/logcat || exit 126; "
                + "set +e; output=$(/system/bin/logcat --ksu-info 2>&1); rc=$?; set -e; "
                + "printf \"%s\\n\" \"$output\"; "
                + "if [ \"$rc\" -eq 0 ]; then echo " + CONTROL_OK_MARKER + "; "
                + "else echo " + CONTROL_FAIL_PREFIX + "$rc; fi'\n";

        CommandResult result = runRootCommand(context, helper, command, TIMEOUT_CONTROL_SECONDS);
        Log.i(TAG, "AZHJ daemon control probe code=" + result.code + " output=" + result.output);
        if (result.code != 0) {
            return new ProbeResult(ProbeKind.FAIL, result.code, result.output);
        }
        if (result.output.contains(CONTROL_OK_MARKER)
                && result.output.contains(CONTROL_EXACT_LINE)) {
            return new ProbeResult(ProbeKind.READY, 0, result.output);
        }
        if (result.output.contains(CONTROL_FAIL_PREFIX + "13")
                && result.output.contains("KernelSU driver fd unavailable")) {
            return new ProbeResult(ProbeKind.ABSENT, 13, result.output);
        }
        return new ProbeResult(ProbeKind.FAIL, 125, result.output);
    }

    private static CommandResult runRootCommand(
            Context context, File helper, String command, int timeoutSeconds) {
        return runDirect(
                context,
                new String[]{helper.getAbsolutePath(), "-c", command},
                timeoutSeconds);
    }

    private static CommandResult runDirect(
            Context context, String[] command, int timeoutSeconds) {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.directory(context.getFilesDir());
        builder.redirectErrorStream(true);
        builder.environment().put("HOME", "/data/local/tmp");
        builder.environment().put("TMPDIR", "/data/local/tmp");
        builder.environment().put("PATH", "/system/bin:/system/xbin");

        try {
            Process process = builder.start();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Thread reader = new Thread(
                    () -> drain(process.getInputStream(), output), "m3q-azhj-ksu-reader");
            reader.setDaemon(true);
            reader.start();

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroy();
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    if (!process.waitFor(2, TimeUnit.SECONDS)) {
                        joinQuietly(reader);
                        return new CommandResult(
                                M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED,
                                outputText(output));
                    }
                }
                joinQuietly(reader);
                return new CommandResult(
                        M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED,
                        outputText(output));
            }

            joinQuietly(reader);
            return new CommandResult(process.exitValue(), outputText(output));
        } catch (IOException e) {
            Log.e(TAG, "AZHJ KernelSU process failed", e);
            return new CommandResult(127, e.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Log.e(TAG, "AZHJ KernelSU process interrupted", e);
            return new CommandResult(
                    M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED, e.toString());
        }
    }

    private enum ProbeKind { READY, ABSENT, FAIL }

    private static final class ProbeResult {
        final ProbeKind kind;
        final int code;
        final String output;

        ProbeResult(ProbeKind kind, int code, String output) {
            this.kind = kind;
            this.code = code;
            this.output = output;
        }
    }

    private static final class CommandResult {
        final int code;
        final String output;

        CommandResult(int code, String output) {
            this.code = code;
            this.output = output;
        }
    }

    private static void drain(InputStream input, ByteArrayOutputStream output) {
        try (InputStream in = input) {
            in.transferTo(output);
        } catch (IOException e) {
            Log.w(TAG, "AZHJ KernelSU output reader failed", e);
        }
    }

    private static void joinQuietly(Thread reader) throws InterruptedException {
        reader.join(TimeUnit.SECONDS.toMillis(2));
    }

    private static String outputText(ByteArrayOutputStream output) {
        return new String(output.toByteArray(), StandardCharsets.UTF_8).trim();
    }

    private static String sha256(File file)
            throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        byte[] hash = digest.digest();
        StringBuilder hex = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            hex.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return hex.toString();
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }
}

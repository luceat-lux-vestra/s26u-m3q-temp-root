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

/** AZHJ-only staged KernelSU activation coordinator injected by the audited build. */
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
    private static final String MODULE_STAGE =
            "/data/local/tmp/kernelsu-m3q-S948NKSU4AZHJ.ko";
    /* Must match exploit/src/su_daemon.c KSU_LOADER_PATH. */
    private static final String KSU_LOADER_STAGE =
            "/data/local/tmp/ksud-m3q-S948NKSS4AZG3-kdp";
    private static final String KSU_LATE_STAGE = "/data/local/tmp/.ksud-stage";
    private static final String KSU_LOG = "/data/local/tmp/m3q-kernelsu-late-load.log";

    private static final String HELPER_SHA256 =
            "a3bc95af6b31a988da0f19b4285c20af31735569dd0c9abd64752e26622bc08f";
    private static final String MODULE_SHA256 =
            "e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7";
    private static final String KSUD_SHA256 =
            "3ce5753203c93f4d733fbc10eebd7a69152189afb1d2a15bfd855bd6b5d4f622";

    private static final String CONTROL_OK_MARKER =
            "M3Q_AZHJ_DAEMON_KSU_CONTROL_OK";
    private static final String CONTROL_FAIL_PREFIX =
            "M3Q_AZHJ_DAEMON_KSU_CONTROL_FAIL:";
    private static final String CONTROL_STAGE_MISSING =
            "M3Q_AZHJ_DAEMON_KSU_CONTROL_STAGE_MISSING";
    private static final String CONTROL_EXACT_LINE =
            "KernelSU control verified version=32525 flags=0x5 uapi=2 features=0x5";

    private static final int TIMEOUT_STAGE_SECONDS = 30;
    private static final int TIMEOUT_INSMOD_SECONDS = 60;
    private static final int TIMEOUT_CONTROL_SECONDS = 20;
    private static final int TIMEOUT_LATE_LOAD_SECONDS = 180;

    private AzhjKernelSuPreloader() {
    }

    static int activate(Context context, File helper, File ksud) {
        if (!MODEL.equals(Build.MODEL)
                || !KERNEL.equals(System.getProperty("os.version", ""))
                || !FINGERPRINT.equals(Build.FINGERPRINT)) {
            Log.e(TAG, "refusing KernelSU activation on non-AZHJ exact target");
            return 126;
        }
        if (!helper.isFile() || !ksud.isFile()) {
            Log.e(TAG, "required AZHJ KernelSU helper files are missing");
            return 126;
        }

        File nativeDir = new File(context.getApplicationInfo().nativeLibraryDir);
        File module = new File(nativeDir, MODULE_NATIVE_NAME);
        if (!module.isFile()) {
            Log.e(TAG, "AZHJ KernelSU native module is missing");
            return 126;
        }

        try {
            String helperHash = sha256(helper);
            String moduleHash = sha256(module);
            String ksudHash = sha256(ksud);
            if (!HELPER_SHA256.equals(helperHash)
                    || !MODULE_SHA256.equals(moduleHash)
                    || !KSUD_SHA256.equals(ksudHash)) {
                Log.e(TAG, "refusing KernelSU activation: packaged hash mismatch "
                        + "helper=" + helperHash
                        + " module=" + moduleHash
                        + " ksud=" + ksudHash);
                return 125;
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "failed to hash AZHJ KernelSU packaged files", e);
            return 125;
        }

        ProbeResult probe = probeDaemonControl(context, helper);
        if (probe.kind == ProbeKind.FAIL) {
            Log.e(TAG, "AZHJ bootstrap-daemon KernelSU pre-probe failed code="
                    + probe.code + " output=" + probe.output);
            return probe.code;
        }

        if (probe.kind == ProbeKind.READY) {
            int verifyCode = verifyRecoveryStages(context, helper);
            if (verifyCode != 0) return verifyCode;
            Log.i(TAG, "M3Q_AZHJ_KSU_ALREADY_LOADED");
            return runLateLoad(context, helper);
        }

        /* Module is absent or no staged daemon-control helper exists yet.
         * Refresh every bootstrap asset from this exact APK before any write. */
        int stageCode = stageBootstrapAssets(context, helper, ksud, module);
        if (stageCode != 0) return stageCode;

        probe = probeDaemonControl(context, helper);
        if (probe.kind == ProbeKind.READY) {
            int verifyCode = verifyRecoveryStages(context, helper);
            if (verifyCode != 0) return verifyCode;
            Log.i(TAG, "M3Q_AZHJ_KSU_ALREADY_LOADED_AFTER_STAGE");
            return runLateLoad(context, helper);
        }
        if (probe.kind != ProbeKind.ABSENT) {
            Log.e(TAG, "AZHJ daemon control probe did not prove module absence code="
                    + probe.code + " output=" + probe.output);
            return probe.code != 0 ? probe.code : 125;
        }

        int insmodCode = runInsmod(context, helper);
        if (insmodCode != 0) return insmodCode;

        probe = probeDaemonControl(context, helper);
        if (probe.kind != ProbeKind.READY) {
            Log.e(TAG, "AZHJ KernelSU insmod completed without daemon control receipt code="
                    + probe.code + " output=" + probe.output);
            return probe.code != 0 ? probe.code : 125;
        }
        Log.i(TAG, "M3Q_AZHJ_KSU_MODULE_OK:" + MODULE_SHA256);

        return runLateLoad(context, helper);
    }

    private static int stageBootstrapAssets(
            Context context, File helper, File ksud, File module) {
        String command = "set -eu\n"
                + "helper_src=" + shellQuote(helper.getAbsolutePath()) + "\n"
                + "ksud_src=" + shellQuote(ksud.getAbsolutePath()) + "\n"
                + "module_src=" + shellQuote(module.getAbsolutePath()) + "\n"
                + "helper_stage=" + shellQuote(HELPER_STAGE) + "\n"
                + "loader_stage=" + shellQuote(KSU_LOADER_STAGE) + "\n"
                + "late_stage=" + shellQuote(KSU_LATE_STAGE) + "\n"
                + "module_stage=" + shellQuote(MODULE_STAGE) + "\n"
                + "late_log=" + shellQuote(KSU_LOG) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "mkdir -p /data/adb\n"
                + "rm -f -- \"$helper_stage\" \"$loader_stage\" \"$late_stage\" "
                + "\"$module_stage\" \"$late_log\"\n"
                + "cp \"$helper_src\" \"$helper_stage\"\n"
                + "cp \"$ksud_src\" \"$loader_stage\"\n"
                + "cp \"$ksud_src\" \"$late_stage\"\n"
                + "cp \"$module_src\" \"$module_stage\"\n"
                + "chmod 0700 \"$helper_stage\" \"$loader_stage\" \"$late_stage\"\n"
                + "chmod 0600 \"$module_stage\"\n"
                + "h_helper=$(sha256sum \"$helper_stage\"); h_helper=${h_helper%% *}\n"
                + "h_loader=$(sha256sum \"$loader_stage\"); h_loader=${h_loader%% *}\n"
                + "h_late=$(sha256sum \"$late_stage\"); h_late=${h_late%% *}\n"
                + "h_module=$(sha256sum \"$module_stage\"); h_module=${h_module%% *}\n"
                + "test \"$h_helper\" = \"$expected_helper\"\n"
                + "test \"$h_loader\" = \"$expected_ksud\"\n"
                + "test \"$h_late\" = \"$expected_ksud\"\n"
                + "test \"$h_module\" = \"$expected_module\"\n"
                + "echo M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:$h_helper:$h_loader:$h_module\n";

        CommandResult result = runRootCommand(
                context, helper, command, TIMEOUT_STAGE_SECONDS);
        Log.i(TAG, "AZHJ bootstrap stage code=" + result.code
                + " output=" + result.output);
        if (result.code != 0
                || !result.output.contains(
                "M3Q_AZHJ_KSU_BOOTSTRAP_STAGE_OK:"
                        + HELPER_SHA256 + ":" + KSUD_SHA256 + ":" + MODULE_SHA256)) {
            Log.e(TAG, "AZHJ bootstrap staging lacks exact completion receipt");
            return result.code != 0 ? result.code : 125;
        }
        return 0;
    }

    private static int verifyRecoveryStages(Context context, File helper) {
        String command = "set -eu\n"
                + "helper_stage=" + shellQuote(HELPER_STAGE) + "\n"
                + "loader_stage=" + shellQuote(KSU_LOADER_STAGE) + "\n"
                + "late_stage=" + shellQuote(KSU_LATE_STAGE) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "h_helper=$(sha256sum \"$helper_stage\"); h_helper=${h_helper%% *}\n"
                + "h_loader=$(sha256sum \"$loader_stage\"); h_loader=${h_loader%% *}\n"
                + "h_late=$(sha256sum \"$late_stage\"); h_late=${h_late%% *}\n"
                + "test \"$h_helper\" = \"$expected_helper\"\n"
                + "test \"$h_loader\" = \"$expected_ksud\"\n"
                + "test \"$h_late\" = \"$expected_ksud\"\n"
                + "echo M3Q_AZHJ_KSU_RECOVERY_STAGE_OK:$h_helper:$h_loader\n";

        CommandResult result = runRootCommand(
                context, helper, command, TIMEOUT_STAGE_SECONDS);
        Log.i(TAG, "AZHJ recovery stage verify code=" + result.code
                + " output=" + result.output);
        if (result.code != 0
                || !result.output.contains(
                "M3Q_AZHJ_KSU_RECOVERY_STAGE_OK:"
                        + HELPER_SHA256 + ":" + KSUD_SHA256)) {
            Log.e(TAG, "AZHJ recovery staging receipt missing");
            return result.code != 0 ? result.code : 125;
        }
        return 0;
    }

    private static int runInsmod(Context context, File helper) {
        String command = "set -eu\n"
                + "loader=" + shellQuote(KSU_LOADER_STAGE) + "\n"
                + "stage=" + shellQuote(MODULE_STAGE) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "loader_hash=$(sha256sum \"$loader\"); loader_hash=${loader_hash%% *}\n"
                + "module_hash=$(sha256sum \"$stage\"); module_hash=${module_hash%% *}\n"
                + "test \"$loader_hash\" = \"$expected_ksud\"\n"
                + "test \"$module_hash\" = \"$expected_module\"\n"
                + "export loader stage expected_module\n"
                + "unshare -m /system/bin/sh -c '"
                + "set -eu; "
                + "module_alias=/system/bin/app_process64; "
                + "if [ ! -f \"$module_alias\" ] || [ -L \"$module_alias\" ]; then "
                + "echo M3Q_AZHJ_KSU_MODULE_ALIAS_TARGET_INVALID:$module_alias; exit 126; fi; "
                + "mount -o rslave none /; "
                + "mount --bind \"$loader\" /system/bin/logcat; "
                + "mount --bind \"$stage\" \"$module_alias\"; "
                + "alias_hash=$(sha256sum \"$module_alias\"); alias_hash=${alias_hash%% *}; "
                + "if [ \"$alias_hash\" != \"$expected_module\" ]; then "
                + "echo M3Q_AZHJ_KSU_MODULE_ALIAS_HASH_MISMATCH:$alias_hash; exit 125; fi; "
                + "echo M3Q_AZHJ_KSU_MODULE_ALIAS_OK:$alias_hash; "
                + "/system/bin/logcat insmod \"$module_alias\"; "
                + "echo M3Q_AZHJ_KSU_BIND_EXEC_OK'\n";

        CommandResult result = runRootCommand(
                context, helper, command, TIMEOUT_INSMOD_SECONDS);
        Log.i(TAG, "AZHJ KernelSU insmod code=" + result.code
                + " output=" + result.output);
        if (result.code != 0) return result.code;
        if (!result.output.contains("M3Q_AZHJ_KSU_MODULE_ALIAS_OK:" + MODULE_SHA256)
                || !result.output.contains("M3Q_AZHJ_KSU_BIND_EXEC_OK")) {
            Log.e(TAG, "AZHJ KernelSU insmod lacks exact bind completion receipt");
            return 125;
        }
        return 0;
    }

    private static ProbeResult probeDaemonControl(Context context, File helper) {
        String command = "set -u\n"
                + "helper_stage=" + shellQuote(HELPER_STAGE) + "\n"
                + "expected_helper=" + shellQuote(HELPER_SHA256) + "\n"
                + "if [ ! -f \"$helper_stage\" ]; then\n"
                + "  echo " + CONTROL_STAGE_MISSING + "\n"
                + "  exit 0\n"
                + "fi\n"
                + "h=$(sha256sum \"$helper_stage\"); h=${h%% *}\n"
                + "if [ \"$h\" != \"$expected_helper\" ]; then\n"
                + "  echo M3Q_AZHJ_DAEMON_KSU_CONTROL_HELPER_HASH_MISMATCH:$h\n"
                + "  exit 0\n"
                + "fi\n"
                + "export helper_stage\n"
                + "unshare -m /system/bin/sh -c '"
                + "set -u; "
                + "mount -o rslave none / || exit 126; "
                + "mount --bind \"$helper_stage\" /system/bin/logcat || exit 126; "
                + "set +e; output=$(/system/bin/logcat --ksu-info 2>&1); rc=$?; set -e; "
                + "printf \"%s\\n\" \"$output\"; "
                + "if [ \"$rc\" -eq 0 ]; then "
                + "echo " + CONTROL_OK_MARKER + "; "
                + "else echo " + CONTROL_FAIL_PREFIX + "$rc; fi'\n";

        CommandResult result = runRootCommand(
                context, helper, command, TIMEOUT_CONTROL_SECONDS);
        Log.i(TAG, "AZHJ daemon control probe code=" + result.code
                + " output=" + result.output);
        if (result.code != 0) {
            return new ProbeResult(ProbeKind.FAIL, result.code, result.output);
        }
        if (result.output.contains(CONTROL_STAGE_MISSING)) {
            return new ProbeResult(ProbeKind.STAGE_MISSING, 0, result.output);
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

    private static int runLateLoad(Context context, File helper) {
        int verifyCode = verifyRecoveryStages(context, helper);
        if (verifyCode != 0) return verifyCode;

        CommandResult result = runDirect(
                context,
                new String[]{helper.getAbsolutePath(), "--late-load"},
                TIMEOUT_LATE_LOAD_SECONDS);
        Log.i(TAG, "AZHJ KernelSU late-load code=" + result.code
                + " output=" + result.output);
        if (result.code != 0) return result.code;

        /* su_daemon.c returns status 0 only after ksud late-load exits 0 and
         * verify_kernelsu_control() accepts exact v32525 control. */
        Log.i(TAG, "M3Q_AZHJ_KSU_LATE_LOAD_OK");
        return 0;
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
            Thread reader = new Thread(() -> drain(process.getInputStream(), output),
                    "m3q-azhj-ksu-reader");
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

    private enum ProbeKind {
        READY,
        ABSENT,
        STAGE_MISSING,
        FAIL
    }

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

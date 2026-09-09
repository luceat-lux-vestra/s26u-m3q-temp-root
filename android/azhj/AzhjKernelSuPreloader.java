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

/** AZHJ-only KernelSU LKM pre-loader injected by the audited AZHJ APK build. */
final class AzhjKernelSuPreloader {
    private static final String TAG = "M3qRoot-AZHJ";
    private static final String MODEL = "SM-S948N";
    private static final String KERNEL =
            "6.12.30-android16-5-pd30ff70-abogkiS948NKSU4AZHJ-4k";
    private static final String FINGERPRINT =
            "samsung/m3qksx/m3q:16/BP4A.251205.006/" +
                    "S948NKSU4AZHJ_OKR4AZHJ:user/release-keys";
    private static final String MODULE_NATIVE_NAME = "libm3qksumodule.so";
    private static final String MODULE_STAGE =
            "/data/local/tmp/kernelsu-m3q-S948NKSU4AZHJ.ko";
    private static final String KSUD_STAGE =
            "/data/local/tmp/ksud-m3q-S948NKSU4AZHJ-preload";
    private static final String MODULE_SHA256 =
            "e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7";
    private static final String KSUD_SHA256 =
            "3ce5753203c93f4d733fbc10eebd7a69152189afb1d2a15bfd855bd6b5d4f622";
    private static final int TIMEOUT_SECONDS = 60;

    private AzhjKernelSuPreloader() {
    }

    static int ensureLoaded(Context context, File helper, File ksud) {
        if (!MODEL.equals(Build.MODEL)
                || !KERNEL.equals(System.getProperty("os.version", ""))
                || !FINGERPRINT.equals(Build.FINGERPRINT)) {
            Log.e(TAG, "refusing KernelSU module load on non-AZHJ exact target");
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
            String moduleHash = sha256(module);
            String ksudHash = sha256(ksud);
            if (!MODULE_SHA256.equals(moduleHash) || !KSUD_SHA256.equals(ksudHash)) {
                Log.e(TAG, "refusing KernelSU module load: packaged hash mismatch "
                        + "module=" + moduleHash + " ksud=" + ksudHash);
                return 125;
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            Log.e(TAG, "failed to hash AZHJ KernelSU native files", e);
            return 125;
        }

        return runInsmod(context, helper, ksud, module);
    }

    private static int runInsmod(Context context, File helper, File ksud, File module) {
        String command = "set -eu\n"
                + "helper=" + shellQuote(helper.getAbsolutePath()) + "\n"
                + "ksud=" + shellQuote(ksud.getAbsolutePath()) + "\n"
                + "source_module=" + shellQuote(module.getAbsolutePath()) + "\n"
                + "stage=" + shellQuote(MODULE_STAGE) + "\n"
                + "loader=" + shellQuote(KSUD_STAGE) + "\n"
                + "expected_module=" + shellQuote(MODULE_SHA256) + "\n"
                + "expected_ksud=" + shellQuote(KSUD_SHA256) + "\n"
                + "cleanup() { rm -f -- \"$stage\" \"$loader\"; }\n"
                + "trap cleanup EXIT HUP INT TERM\n"
                + "if \"$helper\" --ksu-info >/dev/null 2>&1; then\n"
                + "  echo M3Q_AZHJ_KSU_ALREADY_LOADED\n"
                + "  exit 0\n"
                + "fi\n"
                + "ksud_hash=$(sha256sum \"$ksud\"); ksud_hash=${ksud_hash%% *}\n"
                + "if [ \"$ksud_hash\" != \"$expected_ksud\" ]; then\n"
                + "  echo M3Q_AZHJ_KSUD_HASH_MISMATCH:$ksud_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "source_hash=$(sha256sum \"$source_module\"); source_hash=${source_hash%% *}\n"
                + "if [ \"$source_hash\" != \"$expected_module\" ]; then\n"
                + "  echo M3Q_AZHJ_KSU_SOURCE_HASH_MISMATCH:$source_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "rm -f -- \"$stage\" \"$loader\"\n"
                + "cp \"$source_module\" \"$stage\"\n"
                + "cp \"$ksud\" \"$loader\"\n"
                + "chmod 0600 \"$stage\"\n"
                + "chmod 0755 \"$loader\"\n"
                + "module_hash=$(sha256sum \"$stage\"); module_hash=${module_hash%% *}\n"
                + "loader_hash=$(sha256sum \"$loader\"); loader_hash=${loader_hash%% *}\n"
                + "if [ \"$module_hash\" != \"$expected_module\" ]; then\n"
                + "  echo M3Q_AZHJ_KSU_STAGE_HASH_MISMATCH:$module_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "if [ \"$loader_hash\" != \"$expected_ksud\" ]; then\n"
                + "  echo M3Q_AZHJ_KSUD_STAGE_HASH_MISMATCH:$loader_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "echo M3Q_AZHJ_KSU_STAGE_OK:$module_hash:$loader_hash\n"
                + "export loader stage\n"
                + "unshare -m /system/bin/sh -c '"
                + "set -eu; "
                + "mount -o rslave none /; "
                + "mount --bind \"$loader\" /system/bin/logcat; "
                + "/system/bin/logcat insmod \"$stage\"; "
                + "echo M3Q_AZHJ_KSU_BIND_EXEC_OK'\n"
                + "\"$helper\" --ksu-info\n"
                + "echo M3Q_AZHJ_KSU_MODULE_OK:$module_hash\n";

        ProcessBuilder builder = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", command);
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

            if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroy();
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
                joinQuietly(reader);
                Log.e(TAG, "AZHJ KernelSU insmod timed out: " + outputText(output));
                return 124;
            }

            joinQuietly(reader);
            String text = outputText(output);
            int code = process.exitValue();
            Log.i(TAG, "AZHJ KernelSU pre-load code=" + code + " output=" + text);
            if (code != 0) {
                return code;
            }
            if (!text.contains("M3Q_AZHJ_KSU_MODULE_OK:" + MODULE_SHA256)
                    && !text.contains("M3Q_AZHJ_KSU_ALREADY_LOADED")) {
                Log.e(TAG, "AZHJ KernelSU pre-load lacks verified completion marker");
                return 125;
            }
            if (!text.contains("M3Q_AZHJ_KSU_ALREADY_LOADED")
                    && !text.contains("M3Q_AZHJ_KSU_BIND_EXEC_OK")) {
                Log.e(TAG, "AZHJ KernelSU pre-load lacks bind-exec completion marker");
                return 125;
            }
            return 0;
        } catch (IOException e) {
            Log.e(TAG, "AZHJ KernelSU pre-load process failed", e);
            return 127;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Log.e(TAG, "AZHJ KernelSU pre-load interrupted", e);
            return 130;
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

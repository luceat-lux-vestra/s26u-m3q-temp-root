#!/usr/bin/env python3
"""Apply the minimal AZHJ-only KernelSU userspace patch for synchronous late-load.

The stock KernelSU late-load command daemonizes before loading the LKM. That is
correct for normal KernelSU use, but the M3Q temporary-root handoff needs the
native bootstrap helper to wait for the *actual* late-load process through
module load, userspace initialization, and final control verification.

This patch adds a hidden --m3q-foreground flag while preserving the upstream
default daemonized behavior for every invocation that does not pass that flag.
For that foreground-only path it also verifies the exact embedded AZHJ module
bytes in memory immediately before the single load_module kernel-write entry.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

EXPECTED_CLI_BLOB = "a423158363c65b4be8c5889df6e446e567df8515"
EXPECTED_LATE_LOAD_BLOB = "0a71aca35b84bfc142f40c3f699ba6da03c1f992"
EXPECTED_AZHJ_KO_SHA256 = "e947f91c986e6594b965c7e65871bf8287542198484334945fe461d886a701c7"
EXPECTED_AZHJ_KO_NAME = "android16-6.12_kernelsu.ko"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def require_blob(path: Path, expected: str) -> str:
    data = path.read_bytes()
    actual = git_blob_sha1(data)
    print(f"AZHJ_KSUD_PATCH_SOURCE_{path.name.upper().replace('.', '_')}_BLOB={actual}")
    if actual != expected:
        raise SystemExit(f"FAIL: unexpected upstream {path.name} blob {actual} != {expected}")
    return data.decode("utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"FAIL: {label} anchor cardinality={count}, expected 1")
    return text.replace(old, new)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} KERNELSU_CHECKOUT")

    root = Path(sys.argv[1]).resolve()
    cli_path = root / "userspace/ksud/src/cli.rs"
    late_path = root / "userspace/ksud/src/late_load.rs"

    cli = require_blob(cli_path, EXPECTED_CLI_BLOB)
    late = require_blob(late_path, EXPECTED_LATE_LOAD_BLOB)

    # Anchor the entire tail of Commands::LateLoad. `package_name` also exists
    # under Commands::Uninstall, so matching only that field is intentionally
    # forbidden by the exact-cardinality gate.
    cli = replace_once(
        cli,
        '''        /// Specify kernel KMI version instead of auto-detection\n        #[arg(long)]\n        kmi: Option<String>,\n\n        /// manager package name\n        #[arg(long, default_value_t = String::from("me.weishu.kernelsu"))]\n        package_name: String,\n    },\n\n    /// Emulate system reboot\n''',
        '''        /// Specify kernel KMI version instead of auto-detection\n        #[arg(long)]\n        kmi: Option<String>,\n\n        /// manager package name\n        #[arg(long, default_value_t = String::from("me.weishu.kernelsu"))]\n        package_name: String,\n\n        /// M3Q temporary-root handoff: do not daemonize the late-load worker.\n        #[arg(long, hide = true)]\n        m3q_foreground: bool,\n    },\n\n    /// Emulate system reboot\n''',
        "Commands::LateLoad hidden flag",
    )
    cli = replace_once(
        cli,
        '''        Commands::LateLoad {\n            magica,\n            allow_shell,\n            post_magica,\n            kmi,\n            package_name,\n        } => {\n''',
        '''        Commands::LateLoad {\n            magica,\n            allow_shell,\n            post_magica,\n            kmi,\n            package_name,\n            m3q_foreground,\n        } => {\n''',
        "Commands::LateLoad destructure",
    )
    cli = replace_once(
        cli,
        '''            let result = crate::late_load::run(&package_name, kmi, allow_shell);\n''',
        '''            let result = crate::late_load::run(\n                &package_name, kmi, allow_shell, m3q_foreground,\n            );\n''',
        "Commands::LateLoad dispatch",
    )

    late = replace_once(
        late,
        '''pub fn run(package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {\n    utils::daemonize(false)?;\n    info!("late-load command triggered!");\n''',
        '''pub fn run(\n    package_name: &String,\n    kmi: Option<String>,\n    allow_shell: bool,\n    m3q_foreground: bool,\n) -> Result<()> {\n    if m3q_foreground {\n        info!("M3Q_AZHJ_KSUD_FOREGROUND_LATE_LOAD");\n    } else {\n        utils::daemonize(false)?;\n    }\n    info!("late-load command triggered!");\n''',
        "late-load daemonization",
    )

    late = replace_once(
        late,
        '''        let ko_data = assets::get_asset_data(&ko_name)\n            .with_context(|| format!("Failed to get {ko_name} from assets"))?;\n\n        // 4. Load kernelsu.ko from memory with manual relocation\n''',
        f'''        let ko_data = assets::get_asset_data(&ko_name)\n            .with_context(|| format!("Failed to get {{ko_name}} from assets"))?;\n\n        // M3Q foreground is an exact-device handoff. Verify the bytes that will\n        // be passed directly to load_module; do not rely on a second filesystem\n        // extraction path as proof of the embedded module identity.\n        if m3q_foreground {{\n            const EXPECTED_M3Q_KO_NAME: &str = "{EXPECTED_AZHJ_KO_NAME}";\n            const EXPECTED_M3Q_KO_SHA256: &str = "{EXPECTED_AZHJ_KO_SHA256}";\n            if ko_name != EXPECTED_M3Q_KO_NAME {{\n                anyhow::bail!(\n                    "M3Q AZHJ unexpected embedded module name: {{ko_name}} != {{EXPECTED_M3Q_KO_NAME}}"\n                );\n            }}\n            let ko_sha256 = sha256::digest(ko_data.as_ref());\n            if ko_sha256 != EXPECTED_M3Q_KO_SHA256 {{\n                anyhow::bail!(\n                    "M3Q AZHJ embedded module SHA-256 mismatch: {{ko_sha256}} != {{EXPECTED_M3Q_KO_SHA256}}"\n                );\n            }}\n            println!("M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:{{ko_sha256}}");\n        }}\n\n        // 4. Load kernelsu.ko from memory with manual relocation\n''',
        "foreground in-memory module identity gate",
    )

    cli_path.write_text(cli, encoding="utf-8")
    late_path.write_text(late, encoding="utf-8")

    # Fail closed on the exact semantic shape of the patched source.
    cli_after = cli_path.read_text(encoding="utf-8")
    late_after = late_path.read_text(encoding="utf-8")
    requirements = {
        "cli hidden flag": cli_after.count("m3q_foreground: bool") == 1,
        "cli dispatch": cli_after.count("allow_shell, m3q_foreground") == 1,
        "late foreground marker": late_after.count("M3Q_AZHJ_KSUD_FOREGROUND_LATE_LOAD") == 1,
        "late foreground conditions": late_after.count("if m3q_foreground") == 2,
        "stock daemonize retained": late_after.count("utils::daemonize(false)?;") == 1,
        "exact module name": late_after.count(EXPECTED_AZHJ_KO_NAME) == 1,
        "exact module sha": late_after.count(EXPECTED_AZHJ_KO_SHA256) == 1,
        "in-memory module digest": late_after.count("sha256::digest(ko_data.as_ref())") == 1,
        "in-memory verification receipt": late_after.count("M3Q_AZHJ_EMBEDDED_MODULE_VERIFIED:") == 1,
        "load remains after gate": late_after.index("sha256::digest(ko_data.as_ref())")
        < late_after.index("ksuinit::load_module(&ko_data, params)"),
    }
    for label, ok in requirements.items():
        if not ok:
            raise SystemExit(f"FAIL: patched invariant missing: {label}")

    print(f"AZHJ_KSUD_PATCHED_CLI_SHA256={hashlib.sha256(cli_path.read_bytes()).hexdigest()}")
    print(f"AZHJ_KSUD_PATCHED_LATE_LOAD_SHA256={hashlib.sha256(late_path.read_bytes()).hexdigest()}")
    print("AZHJ_KSUD_FOREGROUND_SOURCE_PATCH=PASS")
    print("AZHJ_KSUD_IN_MEMORY_MODULE_IDENTITY_GATE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
exploit_root="$repo_root/exploit"
sdk_root=${ANDROID_HOME:-"$HOME/Android/Sdk"}
ndk_root=${ANDROID_NDK_HOME:-"$sdk_root/ndk/29.0.14206865"}
compiler="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
project="m3q-BP4A.251205.006-AZHJ"
source_project="m3q-BP4A.251205.006"
output_dir="$exploit_root/build/$project/bin"

if [ ! -x "$compiler" ]; then
    echo "Android NDK compiler not found: $compiler" >&2
    exit 1
fi

mkdir -p "$output_dir"
cd "$exploit_root"

"$compiler" \
    -O2 -g0 -Wall -Wextra -Werror -Isrc -fPIE -pie \
    src/su_daemon.c -ldl \
    -o "build/$project/bin/su_daemon_aarch64_pie.app"

"$compiler" \
    -O2 -g0 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -DAPP_PAYLOAD=1 -fPIC -Ivendor/root-my-galaxy/src \
    '-DTARGET_HEADER="targets/m3q-S948NKSU4AZHJ/target.h"' \
    vendor/root-my-galaxy/src/main.c \
    vendor/root-my-galaxy/src/util.c \
    vendor/root-my-galaxy/src/slide_app.c \
    vendor/root-my-galaxy/src/fops.c \
    vendor/root-my-galaxy/src/pipe.c \
    vendor/root-my-galaxy/src/root.c \
    vendor/root-my-galaxy/src/preload.c \
    -shared -pthread \
    -o "build/$project/bin/slide_oracle.app.so"

# AZHJ statically matches the audited AZG3 exploit-relevant BTF layouts and
# RVAs. Reuse the audited m3q source while selecting the AZHJ exact-image
# target header at compile time. fops.c is AZHJ-specific because its teardown
# must restore the exact stock NULL splice_read slot after the shared carrier
# temporarily installs COPY_SPLICE_READ.
"$compiler" \
    -O2 -g0 -Wall -Wextra -Werror \
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    -Isrc -fPIC \
    '-DTARGET_CONFIG_H="targets/m3q-BP4A.251205.006-AZHJ/target.h"' \
    "src/targets/$source_project/main.c" \
    "src/targets/$source_project/util.c" \
    "src/targets/$source_project/slide.c" \
    "src/targets/$project/fops.c" \
    "src/targets/$source_project/pipe.c" \
    src/faketables.c \
    src/stage3.c \
    "src/targets/$source_project/root.c" \
    src/app_preload.c \
    src/stage3_loop.S \
    src/stage3_poll.S \
    -shared -pthread \
    -o "build/$project/bin/preload.app.so"

sha256sum \
    "build/$project/bin/su_daemon_aarch64_pie.app" \
    "build/$project/bin/slide_oracle.app.so" \
    "build/$project/bin/preload.app.so"

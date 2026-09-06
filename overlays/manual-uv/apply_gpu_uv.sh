#!/system/bin/sh
# Galaxy S26 Ultra SM-S948N / AZG3 manual GPU UV apply helper.
# Requires an APK built from overlays/manual-uv/carrier-handoff.patch.
# No kernel address or vote is trusted without exact in-kernel stock-table validation.

set -u

TR=/sys/kernel/tracing
DBG=/sys/kernel/debug
DCVS=$DBG/kgsl/kgsl-3d0/host_based_dcvs
REQ=/data/local/tmp/m3q_uv_request
KEEPER=""

say() { echo "[m3q-uv] $*"; }
fail() { say "FAIL: $*" >&2; exit 1; }
reboot_required() {
  say "FAIL: $*" >&2
  say "REAL REBOOT REQUIRED; do not retry in this boot" >&2
  exit 2
}

remove_probes() {
  echo 0 > "$TR/tracing_on" 2>/dev/null || true
  echo 0 > "$TR/events/m3quv/gpuclk/enable" 2>/dev/null || true
  echo 0 > "$TR/events/m3quv/send/enable" 2>/dev/null || true
  echo 0 > "$TR/events/m3quv/build/enable" 2>/dev/null || true
  echo '-:m3quv/gpuclk' > "$TR/kprobe_events" 2>/dev/null || true
  echo '-:m3quv/send' > "$TR/kprobe_events" 2>/dev/null || true
  echo '-:m3quv/build' > "$TR/kprobe_events" 2>/dev/null || true
}

keeper_state() {
  [ -n "$KEEPER" ] && [ -r "/proc/$KEEPER/comm" ] || return 1
  cat "/proc/$KEEPER/comm" 2>/dev/null
}

wait_for_state() {
  want1=$1
  want2=${2:-}
  i=0
  while [ $i -lt 80 ]; do
    state=$(keeper_state 2>/dev/null || true)
    [ "$state" = "$want1" ] && return 0
    [ -n "$want2" ] && [ "$state" = "$want2" ] && return 0
    [ "$state" = "m3q_uv_dirty" ] && return 2
    [ -d "/proc/$KEEPER" ] || return 1
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

rollback_fail() {
  reason=$1
  remove_probes
  rm -f "$REQ"

  [ -n "$KEEPER" ] && [ -d "/proc/$KEEPER" ] || \
    reboot_required "$reason; keeper disappeared before rollback proof"

  kill -TERM "$KEEPER" 2>/dev/null || \
    reboot_required "$reason; cannot request rollback"

  if wait_for_state m3q_uv_stock; then
    fail "$reason; stock table rollback verified"
  fi

  state=$(keeper_state 2>/dev/null || true)
  [ "$state" = "m3q_uv_dirty" ] && \
    reboot_required "$reason; kernel-table rollback failed"
  reboot_required "$reason; rollback state was not proven"
}

fatal_after_refresh() {
  reason=$1
  say "FAIL: $reason" >&2
  echo 0 > "$TR/tracing_on" 2>/dev/null || true
  remove_probes
  rm -f "$REQ"

  # Best effort only. Once a GMU refresh starts, failed proof means firmware
  # state cannot be proven stock without a real reboot.
  if [ -r "$DCVS" ]; then
    mode=$(cat "$DCVS" 2>/dev/null || true)
    [ "$mode" = "0" ] || echo 0 > "$DCVS" 2>/dev/null || true
  fi
  [ -n "$KEEPER" ] && [ -d "/proc/$KEEPER" ] && \
    kill -TERM "$KEEPER" 2>/dev/null || true
  reboot_required "$reason"
}

[ "$(id -u)" = "0" ] || fail "run through KernelSU root"

if [ ! -d "$TR" ]; then
  mkdir -p "$TR" 2>/dev/null || true
fi
[ -e "$TR/kprobe_events" ] || mount -t tracefs tracefs "$TR" 2>/dev/null || true
[ -e "$TR/kprobe_events" ] || fail "tracefs unavailable"

if [ ! -d "$DBG" ]; then
  mkdir -p "$DBG" 2>/dev/null || true
fi
[ -r "$DCVS" ] || mount -t debugfs debugfs "$DBG" 2>/dev/null || true
[ -r "$DCVS" ] || fail "host_based_dcvs unavailable"

PIDS=$(pidof m3q_uv_ready 2>/dev/null || true)
set -- $PIDS
[ "$#" -eq 1 ] || fail "expected exactly one m3q_uv_ready keeper; got '${PIDS:-none}'"
KEEPER=$1
say "keeper pid=$KEEPER"

MODE=$(cat "$DCVS" 2>/dev/null || true)
[ "$MODE" = "0" ] || fail "expected host_based_dcvs=0 before apply; got '$MODE'"

# Discover the current-boot adreno_device pointer. This is read-only.
remove_probes
: > "$TR/trace" || fail "cannot clear trace"
echo 'p:m3quv/gpuclk msm_kgsl:gpuclk_show adreno=+0x98(%x0):x64' \
  > "$TR/kprobe_events" || fail "cannot install gpuclk kprobe"
echo 1 > "$TR/events/m3quv/gpuclk/enable" || {
  remove_probes
  fail "cannot enable gpuclk kprobe"
}
echo 1 > "$TR/tracing_on" || {
  remove_probes
  fail "cannot enable tracing"
}
cat /sys/class/kgsl/kgsl-3d0/gpuclk >/dev/null 2>&1 || {
  remove_probes
  fail "gpuclk trigger failed"
}
sleep 0.05
echo 0 > "$TR/tracing_on" 2>/dev/null || true
ADRENO=$(grep -o 'adreno=0x[0-9a-fA-F]*' "$TR/trace" 2>/dev/null | \
  tail -n 1 | cut -d= -f2)
echo 0 > "$TR/events/m3quv/gpuclk/enable" 2>/dev/null || true
echo '-:m3quv/gpuclk' > "$TR/kprobe_events" 2>/dev/null || true

case "$ADRENO" in
  0xffff????????????) ;;
  *) fail "invalid adreno pointer from kprobe: '${ADRENO:-none}'" ;;
esac
say "current-boot adreno=$ADRENO"

printf '%s\n' "$ADRENO" > "$REQ" || fail "cannot write request file"
chmod 0644 "$REQ" || fail "cannot chmod request file"

say "requesting bounded 18-state patch"
kill -USR1 "$KEEPER" || fail "cannot signal keeper"

if ! wait_for_state m3q_uv_patched m3q_uv_stock; then
  state=$(keeper_state 2>/dev/null || true)
  [ "$state" = "m3q_uv_dirty" ] && \
    reboot_required "kernel-table state became uncertain during patch"
  reboot_required "keeper disappeared before a verified patched/stock state"
fi

STATE=$(keeper_state 2>/dev/null || true)
if [ "$STATE" = "m3q_uv_stock" ]; then
  fail "request refused or write failed; stock table was verified"
fi
[ "$STATE" = "m3q_uv_patched" ] || \
  reboot_required "unexpected keeper state '$STATE' after patch request"
say "stock signature + 18-state write/readback PASS"

# Set up proof probes before the first GMU refresh. Any failure here can still
# be rolled back without having sent the modified table to firmware.
remove_probes
: > "$TR/trace" || rollback_fail "cannot clear trace before refresh"
echo 'p:m3quv/send msm_kgsl:gen8_hfi_send_gpu_perf_table' \
  > "$TR/kprobe_events" || rollback_fail "cannot install send kprobe"
echo 'p:m3quv/build msm_kgsl:gen8_build_rpmh_tables' \
  >> "$TR/kprobe_events" || rollback_fail "cannot install build kprobe"
echo 1 > "$TR/events/m3quv/send/enable" || \
  rollback_fail "cannot enable send probe"
echo 1 > "$TR/events/m3quv/build/enable" || \
  rollback_fail "cannot enable build probe"

# Proven stock power-cycle path: 0 -> 1.
: > "$TR/trace" || rollback_fail "cannot clear trace for 0->1"
echo 1 > "$TR/tracing_on" || rollback_fail "cannot enable tracing for 0->1"
echo 1 > "$DCVS" || fatal_after_refresh "host_based_dcvs 0->1 write failed"
sleep 0.15
echo 0 > "$TR/tracing_on" 2>/dev/null || true
MODE=$(cat "$DCVS" 2>/dev/null || true)
SEND=$(grep -cE 'm3quv:send| send:' "$TR/trace" 2>/dev/null || true)
BUILD=$(grep -cE 'm3quv:build| build:' "$TR/trace" 2>/dev/null || true)
SEND=${SEND:-0}
BUILD=${BUILD:-0}
say "0->1 mode=$MODE send=$SEND build=$BUILD"
[ "$MODE" = "1" ] || fatal_after_refresh "0->1 mode readback failed"
[ "$SEND" -ge 1 ] || fatal_after_refresh "0->1 did not resend GPU perf table"
[ "$BUILD" -eq 0 ] || fatal_after_refresh "0->1 rebuilt DCVS table"

# Proven stock power-cycle path: 1 -> 0.
: > "$TR/trace" || fatal_after_refresh "cannot clear trace for 1->0"
echo 1 > "$TR/tracing_on" || fatal_after_refresh "cannot enable tracing for 1->0"
echo 0 > "$DCVS" || fatal_after_refresh "host_based_dcvs 1->0 write failed"
sleep 0.15
echo 0 > "$TR/tracing_on" 2>/dev/null || true
MODE=$(cat "$DCVS" 2>/dev/null || true)
SEND=$(grep -cE 'm3quv:send| send:' "$TR/trace" 2>/dev/null || true)
BUILD=$(grep -cE 'm3quv:build| build:' "$TR/trace" 2>/dev/null || true)
SEND=${SEND:-0}
BUILD=${BUILD:-0}
say "1->0 mode=$MODE send=$SEND build=$BUILD"
[ "$MODE" = "0" ] || fatal_after_refresh "final host_based_dcvs is not 0"
[ "$SEND" -ge 1 ] || fatal_after_refresh "1->0 did not resend GPU perf table"
[ "$BUILD" -eq 0 ] || fatal_after_refresh "1->0 rebuilt DCVS table"

remove_probes
rm -f "$REQ"

say "committing only after final host-table revalidation"
kill -USR2 "$KEEPER" || fatal_after_refresh "cannot signal COMMIT"
if ! wait_for_state m3q_uv_commit m3q_uv_stock; then
  state=$(keeper_state 2>/dev/null || true)
  [ "$state" = "m3q_uv_dirty" ] && \
    fatal_after_refresh "final host-table verification became uncertain"
  fatal_after_refresh "keeper disappeared without a verified COMMIT state"
fi
STATE=$(keeper_state 2>/dev/null || true)
[ "$STATE" = "m3q_uv_commit" ] || \
  fatal_after_refresh "final host-table revalidation failed"

say "PASS: 18-state manual GPU UV applied; host_based_dcvs=0"
say "writer is closing; reboot returns to stock"
exit 0

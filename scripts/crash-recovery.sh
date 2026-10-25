#!/usr/bin/env bash
# scripts/crash-recovery.sh — root-required integration test.
#
# Verifies that sloth-daemon cleans up leftover cgroups from a prior crash on
# the next startup, and that throttled processes are restored to their original
# cgroup after the daemon is killed with SIGKILL.
#
# Run from the repo root:   sudo ./scripts/crash-recovery.sh
#                           sudo ./scripts/crash-recovery.sh --build
#
# What it does:
#   1. Starts the daemon, waits for `yes` to be throttled.
#   2. Kills the daemon with SIGKILL (simulates a crash) — cgroups are left behind.
#   3. Confirms the leftover cgroup exists after the crash.
#   4. Starts the daemon again — it should clean up leftovers on startup.
#   5. Confirms the leftover cgroup is gone and `yes` is back in its original cgroup.
#   6. Shuts down cleanly.
#
# ROOT REQUIRED — this script must be run as root (or with sudo).

set -euo pipefail

BIN=./target/release/sloth-daemon
CGROOT=/sys/fs/cgroup/sloth-daemon
WAIT_SECS=${WAIT_SECS:-90}
WORK=$(mktemp -d)
CFG=$WORK/sloth.toml
LOG1=$WORK/daemon1.log
LOG2=$WORK/daemon2.log
YES_PID=""
D1_PID=""
D2_PID=""
declare -a RESULTS=()

record() { RESULTS+=("$1|$2|$3"); }

die() { echo "ABORT: $*" >&2; exit 1; }

stop_daemon() {
    local pid=$1 sig=${2:-INT}
    [ -d "/proc/$pid" ] || return 0
    kill "-$sig" "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
        [ -d "/proc/$pid" ] || return 0
        sleep 0.5
    done
    return 1
}

cleanup() {
    [ -n "$YES_PID" ] && kill "$YES_PID" 2>/dev/null || true
    [ -n "$D1_PID" ] && kill -KILL "$D1_PID" 2>/dev/null || true
    [ -n "$D2_PID" ] && kill -INT  "$D2_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ---- preflight ---------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must be run as root"
[ -f sloth.toml ] || die "run from the repo root (sloth.toml not found)"
if [ "${1:-}" = "--build" ]; then
    cargo build --release -p sloth-daemon || die "build failed"
fi
[ -x "$BIN" ] || die "$BIN not found; build first or pass --build"
[ "$(stat -fc %T /sys/fs/cgroup)" = "cgroup2fs" ] || die "cgroup v2 not mounted"

# Build a test config: dry_run=false, only throttle `yes`, short sustained time.
cat > "$CFG" << 'EOF'
dry_run = false

[sampling]
interval_secs = 2
cpu_threshold_pct = 50.0
sustained_secs = 6

[throttle]
quota_pct = 20
max_concurrent = 5
ttl_secs = 600
release_below_pct = 10.0

[ai]
provider = "rules"
fallback_to_rules = true
throttle_candidates = ["yes"]

[protected]
extra_names = []
EOF

echo "=== Phase 1: start daemon and throttle yes ==="
$BIN --config "$CFG" > "$LOG1" 2>&1 &
D1_PID=$!
echo "Daemon 1 PID: $D1_PID"

# Wait for sampling loop
for _ in $(seq 1 30); do grep -q 'sampling loop' "$LOG1" 2>/dev/null && break; sleep 0.5; done
grep -q 'sampling loop' "$LOG1" || { cat "$LOG1"; die "daemon 1 never reached sampling loop"; }

yes > /dev/null &
YES_PID=$!
echo "yes PID: $YES_PID. Waiting up to ${WAIT_SECS}s for throttle..."

START=$(date +%s)
THROTTLED=0
ORIG_CGROUP=""
while [ $(( $(date +%s) - START )) -lt "$WAIT_SECS" ]; do
    if [ -d "$CGROOT/pid-$YES_PID" ]; then
        THROTTLED=1
        ORIG_CGROUP=$(grep -oP '(?<=::).*' "/proc/$YES_PID/cgroup" 2>/dev/null || echo "")
        break
    fi
    sleep 2
done

if [ "$THROTTLED" -eq 1 ]; then
    record "yes throttled in phase 1" PASS "cgroup $CGROOT/pid-$YES_PID created"
else
    record "yes throttled in phase 1" FAIL "no throttle after ${WAIT_SECS}s"
    cat "$LOG1"
    die "cannot test crash recovery without an active throttle"
fi

echo "=== Phase 2: SIGKILL the daemon (simulate crash) ==="
kill -KILL "$D1_PID" 2>/dev/null || true
sleep 1
D1_PID=""

if [ -d "$CGROOT/pid-$YES_PID" ]; then
    record "leftover cgroup exists after crash" PASS "$CGROOT/pid-$YES_PID"
else
    record "leftover cgroup exists after crash" FAIL "pid-$YES_PID already gone (unexpected)"
fi

echo "=== Phase 3: restart daemon — it must clean up the leftover ==="
$BIN --config "$CFG" > "$LOG2" 2>&1 &
D2_PID=$!
echo "Daemon 2 PID: $D2_PID"

# Wait for startup cleanup to run (it happens before the sampling loop)
for _ in $(seq 1 30); do grep -q 'startup cleanup\|sampling loop' "$LOG2" 2>/dev/null && break; sleep 0.5; done

# Give it one extra second to remove the cgroup directory
sleep 2

if [ ! -d "$CGROOT/pid-$YES_PID" ]; then
    record "leftover cgroup cleaned on restart" PASS "pid-$YES_PID removed"
else
    record "leftover cgroup cleaned on restart" FAIL "pid-$YES_PID still present after restart"
fi

# Check that yes is no longer in the sloth cgroup
CURRENT_CG=$(cat "/proc/$YES_PID/cgroup" 2>/dev/null || echo "exited")
if echo "$CURRENT_CG" | grep -q "sloth-daemon"; then
    record "yes restored to original cgroup" FAIL "still in sloth cgroup: $CURRENT_CG"
else
    record "yes restored to original cgroup" PASS "cgroup: $CURRENT_CG"
fi

echo "=== Phase 4: clean shutdown ==="
kill "$YES_PID" 2>/dev/null || true
YES_PID=""

stop_daemon "$D2_PID" INT && record "clean shutdown" PASS "" || record "clean shutdown" FAIL "still running"
D2_PID=""

if ls -d "$CGROOT"/pid-* > /dev/null 2>&1; then
    record "no leftover cgroups after clean shutdown" FAIL "$(ls -d "$CGROOT"/pid-*)"
else
    record "no leftover cgroups after clean shutdown" PASS "none"
fi

# ---- report ------------------------------------------------------------------
echo
echo "================ CRASH RECOVERY RESULT ================"
ALL_PASS=true
for r in "${RESULTS[@]}"; do
    IFS='|' read -r name status detail <<< "$r"
    printf '%-6s  %-44s %s\n' "$status" "$name" "$detail"
    [ "$status" = "PASS" ] || ALL_PASS=false
done
echo "========================================================"
echo
echo "--- Daemon 1 log (crash run) ---"
tail -20 "$LOG1"
echo "--- Daemon 2 log (recovery run) ---"
tail -20 "$LOG2"
echo
$ALL_PASS && echo "OVERALL: PASS" || { echo "OVERALL: FAIL"; exit 1; }

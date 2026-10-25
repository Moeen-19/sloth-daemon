#!/usr/bin/env bash
# End-to-end check for sloth-daemon (Phase 5). Single terminal, no manual steps.
#
# Run from the repo root:   ./e2e-phase5.sh            (uses the existing release build)
#                           ./e2e-phase5.sh --build    (runs cargo build --release first)
#
# What it does: copies sloth.toml to a temp file with dry_run = false and
# throttle_candidates = ["yes"], starts the daemon as root, starts a `yes` busy loop,
# waits for it to be throttled, checks cpu.max / CPU use / release / cleanup, then stops
# everything and prints a PASS/FAIL report. Only `yes` is a throttle candidate, so your
# other processes are not touched. It needs sudo (it asks for your password once).

set -u

BIN=./target/release/sloth-daemon
CGROOT=/sys/fs/cgroup/sloth-daemon
WAIT_SECS=${WAIT_SECS:-90}      # how long to wait for the throttle to appear
WORK=$(mktemp -d)
CFG=$WORK/sloth.toml
LOG=$WORK/daemon.log
PIDFILE=$WORK/daemon.pid
YES_PID=""
DAEMON_PID=""
declare -a RESULTS=()

record() { RESULTS+=("$1|$2|$3"); }   # name|PASS/FAIL|detail

stop_daemon() {
    if [ -n "$DAEMON_PID" ] && [ -d "/proc/$DAEMON_PID" ]; then
        sudo kill -INT "$DAEMON_PID" 2>/dev/null
        for _ in $(seq 1 20); do
            [ -d "/proc/$DAEMON_PID" ] || return 0
            sleep 0.5
        done
        return 1
    fi
    return 0
}

cleanup() {
    [ -n "$YES_PID" ] && kill "$YES_PID" 2>/dev/null
    stop_daemon >/dev/null 2>&1
}
trap cleanup EXIT

die() { echo "ABORT: $*" >&2; exit 1; }

# ---- preflight --------------------------------------------------------------
[ -f sloth.toml ] || die "run this from the repo root (sloth.toml not found)"
if [ "${1:-}" = "--build" ]; then
    cargo build --release -p sloth-daemon || die "build failed"
fi
[ -x "$BIN" ] || die "$BIN not found; run: cargo build --release -p sloth-daemon (or use --build)"
[ "$(stat -fc %T /sys/fs/cgroup)" = "cgroup2fs" ] || die "cgroup v2 is not mounted at /sys/fs/cgroup"
sudo -v || die "sudo is required"

cp sloth.toml "$CFG"
sed -i 's/dry_run = true/dry_run = false/; s/throttle_candidates = \[\]/throttle_candidates = ["yes"]/' "$CFG"
grep -q 'dry_run = false' "$CFG" || die "config edit failed: dry_run is not false in $CFG"
grep -q 'throttle_candidates = \["yes"\]' "$CFG" \
    || die "config edit failed: throttle_candidates not set. Edit $CFG by hand, or fix the sed pattern"
echo "Config:  $CFG"
grep -nE 'dry_run|throttle_candidates|provider|sustained_secs|quota_pct|ttl_secs' "$CFG"

if ls -d "$CGROOT"/pid-* >/dev/null 2>&1; then
    echo "Note: leftover pid-* directories exist before the run (the daemon should clean them up at startup):"
    ls -d "$CGROOT"/pid-*
fi

# ---- start the daemon -------------------------------------------------------
sudo bash -c 'echo $$ > "$1"; exec "$2" --config "$3"' _ "$PIDFILE" "$BIN" "$CFG" >"$LOG" 2>&1 &
for _ in $(seq 1 20); do [ -s "$PIDFILE" ] && break; sleep 0.25; done
DAEMON_PID=$(cat "$PIDFILE" 2>/dev/null || true)
[ -n "$DAEMON_PID" ] || die "daemon did not start; see $LOG"
for _ in $(seq 1 30); do
    grep -q 'sampling loop' "$LOG" && break
    [ -d "/proc/$DAEMON_PID" ] || { cat "$LOG"; die "daemon exited early"; }
    sleep 0.5
done
grep -q 'sampling loop' "$LOG" || { cat "$LOG"; die "daemon never reached its sampling loop"; }
echo "Daemon running (pid $DAEMON_PID). Starting the yes busy loop..."

# ---- start the victim and wait for the throttle -----------------------------
yes > /dev/null &
YES_PID=$!
echo "yes PID: $YES_PID. Waiting up to ${WAIT_SECS}s for it to be throttled (needs about 30s of sustained load)..."

START=$(date +%s)
THROTTLED=0
while [ $(( $(date +%s) - START )) -lt "$WAIT_SECS" ]; do
    if [ -d "$CGROOT/pid-$YES_PID" ]; then THROTTLED=1; break; fi
    sleep 2
done
ELAPSED=$(( $(date +%s) - START ))

if [ "$THROTTLED" -eq 1 ]; then
    record "yes throttled" PASS "after ${ELAPSED}s"
    CPUMAX=$(cat "$CGROOT/pid-$YES_PID/cpu.max" 2>/dev/null || echo "unreadable")
    if echo "$CPUMAX" | grep -Eq '^[0-9]+ [0-9]+$'; then
        record "cpu.max written" PASS "$CPUMAX"
    else
        record "cpu.max written" FAIL "$CPUMAX"
    fi
    CG=$(cat "/proc/$YES_PID/cgroup" 2>/dev/null || echo "gone")
    if echo "$CG" | grep -q "sloth-daemon/pid-$YES_PID"; then
        record "process moved into sloth cgroup" PASS "$CG"
    else
        record "process moved into sloth cgroup" FAIL "$CG"
    fi
    sleep 4
    CPU=$(top -b -n 2 -d 2 -p "$YES_PID" 2>/dev/null | awk -v p="$YES_PID" '$1 == p {c = $9} END {print c}')
    if [ -n "$CPU" ] && awk -v c="$CPU" 'BEGIN{exit !(c+0 < 40)}'; then
        record "CPU reduced" PASS "yes at ${CPU}% (was about 100%)"
    else
        record "CPU reduced" FAIL "yes at ${CPU:-unknown}%"
    fi
else
    record "yes throttled" FAIL "no throttle after ${ELAPSED}s"
    record "cpu.max written" FAIL "skipped"
    record "process moved into sloth cgroup" FAIL "skipped"
    record "CPU reduced" FAIL "skipped"
fi

# ---- release after the process exits ----------------------------------------
kill "$YES_PID" 2>/dev/null
RELEASED=0
for _ in $(seq 1 15); do
    if [ ! -d "$CGROOT/pid-$YES_PID" ]; then RELEASED=1; break; fi
    sleep 2
done
if [ "$THROTTLED" -eq 1 ]; then
    if [ "$RELEASED" -eq 1 ]; then
        record "released after yes exited" PASS "pid-$YES_PID directory removed"
    else
        record "released after yes exited" FAIL "pid-$YES_PID still present 30s after kill"
    fi
fi
YES_DONE=$YES_PID
YES_PID=""

# ---- shutdown and leftovers ---------------------------------------------------
if stop_daemon; then
    record "daemon exits on Ctrl+C (SIGINT)" PASS "clean exit"
else
    record "daemon exits on Ctrl+C (SIGINT)" FAIL "still running after 10s"
fi
if ls -d "$CGROOT"/pid-* >/dev/null 2>&1; then
    record "no leftover pid-* directories" FAIL "$(ls -d "$CGROOT"/pid-* | tr '\n' ' ')"
else
    record "no leftover pid-* directories" PASS "none"
fi

# tracing colours its output with ANSI escapes even in a file; strip them before grepping
CLEAN=$WORK/daemon.clean.log
sed 's/\x1b\[[0-9;]*m//g' "$LOG" > "$CLEAN"
OTHERS=$(grep 'Process throttled successfully' "$CLEAN" | grep -v 'comm="yes"' || true)
if [ -z "$OTHERS" ]; then
    record "only yes was throttled" PASS "no other process affected"
else
    record "only yes was throttled" FAIL "see log lines below"
fi

# ---- report ---------------------------------------------------------------------
echo
echo "================ RESULT ================"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r name status detail <<<"$r"
    printf '%-4s  %-36s %s\n' "$status" "$name" "$detail"
done
echo "========================================"
echo
echo "---- Key log lines (paste these if anything failed) ----"
grep -E 'Policy decision.*comm=yes' "$CLEAN" | grep -v 'action=None'
grep -E 'Policy decision.*comm=yes.*near quota' "$CLEAN" | head -2
grep -E 'Process (throttled|released)|shutdown|WARN|ERROR' "$CLEAN" | tail -15
if [ -n "$OTHERS" ]; then
    echo "---- OTHER processes throttled (unexpected) ----"
    echo "$OTHERS"
fi
echo
echo "Full daemon log: $LOG"
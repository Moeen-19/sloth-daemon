#!/usr/bin/env bash
# Live LLM-mode check for sloth-daemon. DRY RUN ONLY: nothing is written to cgroups.
#
# Run from the repo root:   ./scripts/llm-check.sh              (model qwen2.5:0.5b)
#                           ./scripts/llm-check.sh <model>      (another pulled model)
#
# Needs Ollama running with the model pulled, and a built release binary:
#   sudo systemctl start ollama && ollama pull qwen2.5:0.5b
#   cargo build --release -p sloth-daemon
#
# What it does: makes a temp config (provider = "ollama", dry_run stays true, only `yes`
# is a throttle candidate), starts the daemon with sudo, runs a `yes` busy loop, waits for
# the daemon to log a real verdict for it, then stops everything and prints a report.

set -u

MODEL=${1:-qwen2.5:0.5b}
URL=${OLLAMA_URL:-http://localhost:11434}
BIN=./target/release/sloth-daemon
CGROOT=/sys/fs/cgroup/sloth-daemon
WAIT_SECS=${WAIT_SECS:-180}     # sustained time (30s) + cold model load + inference
WORK=$(mktemp -d)
CFG=$WORK/sloth.toml
LOG=$WORK/daemon.log
CLEAN=$WORK/daemon.clean.log
PIDFILE=$WORK/daemon.pid
YES_PID=""
DAEMON_PID=""
declare -a RESULTS=()

record() { RESULTS+=("$1|$2|$3"); }
die() { echo "ABORT: $*" >&2; exit 1; }
strip_ansi() { sed 's/\x1b\[[0-9;]*m//g' "$LOG" > "$CLEAN"; }

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

# ---- preflight --------------------------------------------------------------
[ -f sloth.toml ] || die "run this from the repo root (sloth.toml not found)"
[ -x "$BIN" ] || die "$BIN not found; run: cargo build --release -p sloth-daemon"
TAGS=$(curl -s --max-time 5 "$URL/api/tags" || true)
[ -n "$TAGS" ] || die "Ollama not reachable at $URL (try: sudo systemctl start ollama)"
echo "$TAGS" | grep -qF "\"$MODEL\"" || die "model $MODEL is not pulled (run: ollama pull $MODEL)"
sudo -v || die "sudo is required"

cp sloth.toml "$CFG"
sed -i \
    -e 's/^provider = .*/provider = "ollama"/' \
    -e "s|^model = .*|model = \"$MODEL\"|" \
    -e 's/^timeout_secs = .*/timeout_secs = 120/' \
    -e 's/^throttle_candidates = .*/throttle_candidates = ["yes"]/' \
    "$CFG"
grep -q '^dry_run = true' "$CFG" || die "dry_run is not true in sloth.toml; this check must stay in dry-run"
grep -q '^provider = "ollama"' "$CFG" || die "config edit failed (provider)"
grep -q "^model = \"$MODEL\"" "$CFG" || die "config edit failed (model)"
grep -q '^throttle_candidates = \["yes"\]' "$CFG" || die "config edit failed (throttle_candidates)"
echo "Config: $CFG"
grep -nE '^(dry_run|provider|model|timeout_secs|throttle_candidates|fallback_to_rules)' "$CFG"

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
echo "Daemon running (pid $DAEMON_PID), provider ollama, model $MODEL."

# ---- start the victim and wait for a real verdict -------------------------------
yes > /dev/null &
YES_PID=$!
echo "yes PID: $YES_PID. Waiting up to ${WAIT_SECS}s for a verdict (30s sustained load, then the model answers)..."

START=$(date +%s)
GOT_VERDICT=0
while [ $(( $(date +%s) - START )) -lt "$WAIT_SECS" ]; do
    strip_ansi
    if grep 'Policy decision' "$CLEAN" | grep 'comm=yes' | grep -qv 'not sustained long enough'; then
        GOT_VERDICT=1
        break
    fi
    sleep 3
done
ELAPSED=$(( $(date +%s) - START ))
sleep 6     # let a couple more decisions through
kill "$YES_PID" 2>/dev/null
YES_PID=""
OLLAMA_MB=$(ps -o rss= -C ollama 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s/1024}')

if stop_daemon; then
    record "daemon exits on Ctrl+C (SIGINT)" PASS "clean exit"
else
    record "daemon exits on Ctrl+C (SIGINT)" FAIL "still running after 10s"
fi
strip_ansi

# ---- evaluate ----------------------------------------------------------------
DECISIONS=$(grep 'Policy decision' "$CLEAN" | grep 'comm=yes' | grep -v 'not sustained long enough' || true)
if [ "$GOT_VERDICT" -eq 1 ]; then
    record "daemon logged a decision after model call" PASS "after ${ELAPSED}s"
else
    record "daemon logged a decision after model call" FAIL "none within ${WAIT_SECS}s"
fi
if echo "$DECISIONS" | grep -q 'classification=\(Essential\|Interactive\|Background\|Runaway\)'; then
    record "model returned a usable verdict" PASS "typed verdict parsed"
elif [ -n "$DECISIONS" ]; then
    record "model returned a usable verdict" FAIL "only Unknown (model failed or answered badly)"
else
    record "model returned a usable verdict" FAIL "no decisions"
fi
# Independent proof that the model was really called: Ollama's own server log.
CHAT_LINES=$(sudo journalctl -u ollama --no-pager --since "$(date -d "@$START" '+%Y-%m-%d %H:%M:%S')" 2>/dev/null \
    | grep -E 'POST +"/api/(chat|generate)"' || true)
if [ -n "$CHAT_LINES" ]; then
    record "Ollama served a model request" PASS "$(echo "$CHAT_LINES" | wc -l) request(s) in the Ollama journal"
else
    record "Ollama served a model request" FAIL "no /api/chat request in 'journalctl -u ollama' (is Ollama running as the systemd service?)"
fi
BAD=$(grep -E ' (WARN|ERROR) ' "$CLEAN" || true)
if [ -z "$BAD" ]; then
    record "no WARN/ERROR lines" PASS "none"
else
    record "no WARN/ERROR lines" FAIL "$(echo "$BAD" | wc -l) line(s), shown below"
fi
if ls -d "$CGROOT"/pid-* >/dev/null 2>&1; then
    record "dry run wrote nothing to cgroups" FAIL "$(ls -d "$CGROOT"/pid-* | tr '\n' ' ')"
else
    record "dry run wrote nothing to cgroups" PASS "no pid-* directories"
fi

# ---- report ----------------------------------------------------------------------
echo
echo "================ LLM CHECK RESULT ================"
for r in "${RESULTS[@]}"; do
    IFS='|' read -r name status detail <<<"$r"
    printf '%-4s  %-44s %s\n' "$status" "$name" "$detail"
done
echo "=================================================="
echo "Model: $MODEL | Ollama memory in use: ${OLLAMA_MB:-?} MB"
echo "---- Ollama server log: requests during the run (paste these) ----"
echo "${CHAT_LINES:-none}" | tail -5
echo "---- ollama ps ----"
ollama ps 2>&1 | head -5
echo
echo "---- Decisions for yes after the model call (paste these) ----"
echo "$DECISIONS" | tail -6
if [ -n "$BAD" ]; then
    echo "---- WARN/ERROR lines ----"
    echo "$BAD" | tail -10
fi
echo
echo "Full daemon log: $LOG"
echo "Tip: stop Ollama when you are done to free memory: sudo systemctl stop ollama"
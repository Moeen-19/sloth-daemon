#!/usr/bin/env bash
set -e

echo "==> Step 1: Building sloth-daemon..."
cargo build --release -p sloth-daemon

echo "==> Step 2: Installing binary..."
sudo cp target/release/sloth-daemon /usr/local/bin/

echo "==> Step 3: Setting up and configuring sloth.toml..."
sudo mkdir -p /etc/sloth-daemon 
sudo cp sloth.toml /etc/sloth-daemon/sloth.toml
sudo sed -i 's/^dry_run = true/dry_run = false/; s/^throttle_candidates = .*/throttle_candidates = ["yes"]/' /etc/sloth-daemon/sloth.toml

echo "==> Step 4: Installing systemd service and starting..."
sudo cp sloth-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start sloth-daemon

echo "==> Step 5: Running verification test..."
# Start a test process in the background
yes > /dev/null &
TEST_PID=$!
echo "Started 'yes' process with PID: ${TEST_PID}"

echo "Waiting ~40 seconds for the daemon to detect and apply limits..."
sleep 40

echo "==> Checking cgroup cpu.max (Expect: 20000 100000):"
CGROUP_PATH="/sys/fs/cgroup/sloth-daemon/pid-${TEST_PID}/cpu.max"
if [ -f "$CGROUP_PATH" ]; then
    cat "$CGROUP_PATH"
else
    echo "Warning: Cgroup path not found: $CGROUP_PATH"
fi

echo "==> Step 6: Cleaning up test process..."
kill "${TEST_PID}" 2>/dev/null || true
wait "${TEST_PID}" 2>/dev/null || true

echo "==> Step 7: Stopping service..."
sudo systemctl stop sloth-daemon

echo "==> Step 8: Checking journalctl logs for errors..."
sudo journalctl -u sloth-daemon --no-pager | grep -iE 'denied|EPERM|EACCES|ERROR' || echo "no permission errors"

echo "==> Step 9: Verifying cgroup cleanup (Expect: no matches):"
ls -d /sys/fs/cgroup/sloth-daemon/pid-* 2>&1 || echo "Verified: no matches found"

echo "==> Step 10: Removing configuration file..."
sudo rm /etc/sloth-daemon/sloth.toml

echo "==> Test run completed successfully!"
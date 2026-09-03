#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/tmp/dsnitch_e2e.log"
BINARY="./target/release/dsnitch"

echo "=========================================================="
echo " Starting dsnitch Automated End-to-End (E2E) Test Suite"
echo "=========================================================="

if [ ! -f "$BINARY" ]; then
    echo "[ERROR] Binary $BINARY not found. Please run 'cargo build --release' first."
    exit 1
fi

rm -f "$LOG_FILE"

echo "[0/6] Pre-pulling alpine test image..."
docker pull alpine:latest > /dev/null

echo "[1/6] Setting minimal Linux capabilities and launching unprivileged dsnitch..."
sudo setcap cap_sys_admin,cap_net_admin,cap_dac_read_search+ep "$BINARY"
"$BINARY" -s > "$LOG_FILE" 2>&1 &
DSNITCH_PID=$!

cleanup() {
    echo "--- Stopping dsnitch (PID: $DSNITCH_PID) ---"
    kill -INT "$DSNITCH_PID" 2>/dev/null || true
    sleep 2
}
trap cleanup EXIT

# Allow eBPF probes and Docker events stream to attach
sleep 3

if ! ps -p "$DSNITCH_PID" > /dev/null; then
    echo "[FAIL] dsnitch exited prematurely. Daemon log:"
    cat "$LOG_FILE"
    exit 1
fi

FAILED=0
assert_log_contains() {
    local pattern="$1"
    local desc="$2"
    if grep -q "$pattern" "$LOG_FILE"; then
        echo "  [PASS] $desc"
    else
        echo "  [FAIL] $desc (pattern '$pattern' not found)"
        FAILED=1
    fi
}

echo "[2/6] Running Test: Multi-Service Docker Compose Attribution..."
docker run --rm --name e2e-gateway -l com.docker.compose.project=shop -l com.docker.compose.service=gateway alpine wget -q -O /dev/null http://example.com
docker run --rm --name e2e-auth -l com.docker.compose.project=shop -l com.docker.compose.service=auth alpine wget -q -O /dev/null http://example.com
sleep 2

assert_log_contains "e2e-gateway" "Detected container e2e-gateway"
assert_log_contains "gateway" "Resolved Compose service 'gateway'"
assert_log_contains "e2e-auth" "Detected container e2e-auth"
assert_log_contains "auth" "Resolved Compose service 'auth'"

echo "[3/6] Running Test: Layer-3 ICMP Ping..."
# GitHub Actions firewall drops inbound ICMP echo replies; running '|| true' strictly INSIDE the container
# ensures docker run still fails if container fails to start, while allowing egress ICMP to be captured.
docker run --rm --name e2e-probe alpine sh -c 'ping -c 2 -W 1 1.1.1.1 > /dev/null || true'
sleep 2

assert_log_contains "e2e-probe" "Detected ICMP container e2e-probe"
assert_log_contains "ICMP" "Captured Layer-3 ICMP protocol"
assert_log_contains "1.1.1.1" "Captured ICMP destination 1.1.1.1"

echo "[4/6] Running Test: User-Defined Bridge Network..."
docker network create e2e-net > /dev/null
docker run --rm --network e2e-net --name e2e-bridge alpine wget -q -O /dev/null http://example.com
docker network rm e2e-net > /dev/null
sleep 2

assert_log_contains "e2e-bridge" "Detected container e2e-bridge on custom bridge network"

echo "[5/6] Running Test: High-Concurrency Burst..."
docker run --rm --name e2e-burst alpine sh -c 'for i in $(seq 1 10); do wget -q -O /dev/null http://example.com & done; wait'
sleep 2

assert_log_contains "e2e-burst" "Handled burst traffic under concurrent load"

echo "[6/6] Running Test: Rapid Container Churn..."
CHURN_PIDS=()
for i in 1 2 3; do
    docker run --rm --name "e2e-churn-$i" alpine sh -c "wget -q -O /dev/null http://example.com && sleep 1" &
    CHURN_PIDS+=($!)
done
wait "${CHURN_PIDS[@]}"
sleep 3

assert_log_contains "e2e-churn-1" "Resolved rapidly exiting container churn-1"
assert_log_contains "e2e-churn-2" "Resolved rapidly exiting container churn-2"
assert_log_contains "e2e-churn-3" "Resolved rapidly exiting container churn-3"

echo "=========================================================="
if [ $FAILED -eq 0 ]; then
    echo " ALL E2E INTEGRATION TESTS PASSED SUCCESSFULLY!"
    echo "=========================================================="
    exit 0
else
    echo " [ERROR] ONE OR MORE E2E TESTS FAILED. DAEMON LOG:"
    echo "=========================================================="
    cat "$LOG_FILE"
    exit 1
fi

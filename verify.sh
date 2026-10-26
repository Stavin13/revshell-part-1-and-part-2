#!/usr/bin/env bash
set -u

IMAGE=revshell-lab
STAMP="$(date +%s)$$"
NET="revshell-verify-$STAMP"
ATTACKER="verify-attacker-$STAMP"
VICTIM="verify-victim-$STAMP"
P1_MARK="PART1_OK_${STAMP}"
P2_MARK="PART2_OK_${STAMP}"
WORK="$(mktemp -d)"
FAILED=0
NET_CREATED=0
ATTACKER_CREATED=0
VICTIM_CREATED=0

cleanup() {
    if [ "$ATTACKER_CREATED" -eq 1 ]; then
        docker rm -f "$ATTACKER" >/dev/null 2>&1
    fi
    if [ "$VICTIM_CREATED" -eq 1 ]; then
        docker rm -f "$VICTIM" >/dev/null 2>&1
    fi
    if [ "$NET_CREATED" -eq 1 ]; then
        docker network rm "$NET" >/dev/null 2>&1
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed"
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not running"
    exit 1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -q -t "$IMAGE" . >/dev/null || exit 1
fi

docker network create --internal "$NET" >/dev/null || exit 1
NET_CREATED=1
docker run -d --name "$ATTACKER" --network "$NET" --network-alias attacker "$IMAGE" sleep 300 >/dev/null || exit 1
ATTACKER_CREATED=1
docker run -d --name "$VICTIM" --network "$NET" "$IMAGE" sleep 300 >/dev/null || exit 1
VICTIM_CREATED=1

verify() {
    local label="$1" marker="$2" listener="$3" payload="$4"
    local slug="${label// /_}"
    local out="$WORK/$slug.log"
    local victim_out="$WORK/${slug}-victim.log"

    printf 'id; echo %s; exit\n' "$marker" \
        | docker exec -i "$ATTACKER" timeout 10 $listener >"$out" 2>&1 &
    local listener_pid=$!
    sleep 2
    docker exec -i "$VICTIM" timeout 6 $payload >"$victim_out" 2>&1 || true
    wait "$listener_pid" 2>/dev/null || true

    if grep -q "$marker" "$out" \
        && grep -q 'uid=0' "$out" \
        && ! grep -qi 'Traceback' "$victim_out"; then
        echo "PASS  $label"
    else
        echo "FAIL  $label"
        echo "--- listener output ---"
        sed -n '1,25p' "$out"
        echo "--- victim output ---"
        sed -n '1,25p' "$victim_out"
        FAILED=1
    fi
}

check_frames() {
    local out="$WORK/frames-payload.log"
    local victim_out="$WORK/frames-payload-victim.log"
    local listener_out="$WORK/frames-listener.log"
    local client_out="$WORK/frames-client.log"

    docker exec -i "$ATTACKER" timeout 25 python3 /opt/revshell/frame_probe.py listen >"$out" 2>&1 &
    local probe_pid=$!
    sleep 2
    docker exec -i "$VICTIM" timeout 20 python3 /opt/revshell/encrypted_shell.py >"$victim_out" 2>&1 &
    local payload_pid=$!
    wait "$probe_pid" 2>/dev/null || true
    kill "$payload_pid" 2>/dev/null || true
    docker exec "$VICTIM" pkill -9 -f 'encrypted_shell.py' >/dev/null 2>&1 || true
    wait "$payload_pid" 2>/dev/null || true

    if grep -q '^RESULT PASS$' "$out"; then
        echo "PASS  Backoff and rejected frames (payload)"
    else
        echo "FAIL  Backoff and rejected frames (payload)"
        echo "--- probe output ---"
        sed -n '1,25p' "$out"
        echo "--- victim output ---"
        sed -n '1,25p' "$victim_out"
        FAILED=1
    fi

    docker exec -i "$ATTACKER" timeout 20 python3 /opt/revshell/encrypted_listener.py >"$listener_out" 2>&1 &
    local listener_pid=$!
    sleep 2
    docker exec -i "$VICTIM" timeout 15 python3 /opt/revshell/frame_probe.py client >"$client_out" 2>&1 || true
    docker exec "$ATTACKER" pkill -9 -f 'encrypted_listener.py' >/dev/null 2>&1 || true
    wait "$listener_pid" 2>/dev/null || true

    if grep -q '^RESULT PASS$' "$client_out" && grep -q 'ALIVE_OK' "$listener_out"; then
        echo "PASS  Rejected frames (listener)"
    else
        echo "FAIL  Rejected frames (listener)"
        echo "--- client output ---"
        sed -n '1,25p' "$client_out"
        echo "--- listener output ---"
        sed -n '1,25p' "$listener_out"
        FAILED=1
    fi
}

verify "Part 1 (plaintext)" "$P1_MARK" "nc -N -lvn 443" "python3 /opt/revshell/shell.py"
verify "Part 2 (encrypted)" "$P2_MARK" "python3 /opt/revshell/encrypted_listener.py" "python3 /opt/revshell/encrypted_shell.py"
check_frames

if [ "$FAILED" -eq 0 ]; then
    echo "All checks passed"
else
    echo "Some checks failed"
fi
exit "$FAILED"

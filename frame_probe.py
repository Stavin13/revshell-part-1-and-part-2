import itertools
import socket
import struct
import sys
import time

KEY = b"my_secret_key"
PORT = 443
FRAME_DATA = b"D"
HEADER = struct.Struct("!cI")
MAX_DATA_FRAME = 4096


def new_keystream():
    return itertools.cycle(KEY)


def xor_crypt(keystream, data):
    return bytes([a ^ b for a, b in zip(data, keystream)])


def send_frame(conn, keystream, kind, payload):
    conn.sendall(xor_crypt(keystream, HEADER.pack(kind, len(payload)) + payload))


def wait_closed(conn, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        conn.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            return False
        except OSError:
            return True
        if not chunk:
            return True
    return False


def drain(conn, keystream, timeout, marker):
    deadline = time.time() + timeout
    buffer = b""
    data = b""
    while time.time() < deadline:
        conn.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buffer += xor_crypt(keystream, chunk)
        while len(buffer) >= HEADER.size:
            kind, length = HEADER.unpack_from(buffer)
            if kind != FRAME_DATA or length > MAX_DATA_FRAME:
                return data
            end = HEADER.size + length
            if len(buffer) < end:
                break
            payload = buffer[HEADER.size:end]
            buffer = buffer[end:]
            data += payload
            if marker in data:
                return data
    return data


def listen_mode():
    ok = True
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(2)
    server.settimeout(10)

    try:
        conn, _ = server.accept()
    except socket.timeout:
        print("SESSION FAIL no connection")
        print("RESULT FAIL")
        return 1

    send_stream = new_keystream()
    recv_stream = new_keystream()
    send_frame(conn, send_stream, FRAME_DATA, b"echo RECONNECT'_'OK; exit\n")
    data = drain(conn, recv_stream, 6, b"RECONNECT_OK")
    closed_at = time.time()
    conn.close()

    if b"RECONNECT_OK" in data:
        print("SESSION PASS")
    else:
        print("SESSION FAIL")
        ok = False

    server.settimeout(15)
    try:
        conn, _ = server.accept()
    except socket.timeout:
        print("BACKOFF FAIL no reconnect")
        print("RESULT FAIL")
        return 1

    gap = time.time() - closed_at
    if gap >= 4.5:
        print(f"BACKOFF PASS {gap:.1f}s")
    else:
        print(f"BACKOFF FAIL {gap:.1f}s")
        ok = False

    conn.sendall(xor_crypt(new_keystream(), HEADER.pack(FRAME_DATA, MAX_DATA_FRAME + 1)))
    closed = wait_closed(conn, 5)
    if closed:
        print("OVERSIZED PASS")
    else:
        print("OVERSIZED FAIL connection stayed open")
        ok = False
    conn.close()

    server.settimeout(20)
    try:
        conn, _ = server.accept()
    except socket.timeout:
        print("UNKNOWN FAIL no reconnect")
        print("RESULT FAIL")
        return 1

    conn.sendall(xor_crypt(new_keystream(), HEADER.pack(b"X", 0)))
    closed = wait_closed(conn, 5)
    if closed:
        print("UNKNOWN PASS")
    else:
        print("UNKNOWN FAIL connection stayed open")
        ok = False
    conn.close()

    server.settimeout(30)
    try:
        conn, _ = server.accept()
    except socket.timeout:
        print("RECOVER FAIL no reconnect")
        print("RESULT FAIL")
        return 1

    send_frame(conn, new_keystream(), FRAME_DATA, b"echo RECOVER'_'OK; exit\n")
    data = drain(conn, new_keystream(), 6, b"RECOVER_OK")
    conn.close()
    if b"RECOVER_OK" in data:
        print("RECOVER PASS")
    else:
        print("RECOVER FAIL")
        ok = False
    server.close()

    print("RESULT " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def connect():
    last = None
    for _ in range(10):
        try:
            return socket.create_connection(("attacker", PORT), timeout=3)
        except OSError as error:
            last = error
            time.sleep(0.5)
    raise last


def client_mode():
    ok = True

    conn = connect()
    send_frame(conn, new_keystream(), b"X", b"")
    closed = wait_closed(conn, 5)
    conn.close()
    print("UNKNOWN PASS" if closed else "UNKNOWN FAIL connection stayed open")
    ok = ok and closed

    conn = connect()
    conn.sendall(xor_crypt(new_keystream(), HEADER.pack(FRAME_DATA, MAX_DATA_FRAME + 1)))
    closed = wait_closed(conn, 5)
    conn.close()
    print("OVERSIZED PASS" if closed else "OVERSIZED FAIL connection stayed open")
    ok = ok and closed

    conn = connect()
    conn.sendall(b"\x00\x00")
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()
    time.sleep(0.5)

    conn = connect()
    send_frame(conn, new_keystream(), FRAME_DATA, b"ALIVE_OK")
    time.sleep(1)
    conn.close()

    print("RESULT " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("listen", "client"):
        print("usage: frame_probe.py listen|client", file=sys.stderr)
        return 2
    if sys.argv[1] == "listen":
        return listen_mode()
    return client_mode()


if __name__ == "__main__":
    sys.exit(main())

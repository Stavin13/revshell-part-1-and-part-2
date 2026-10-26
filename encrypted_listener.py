import itertools
import os
import select
import signal
import socket
import struct
import sys
import termios
import tty

KEY = b"my_secret_key"
HOST = "0.0.0.0"
PORT = 443
FRAME_DATA = b"D"
FRAME_RESIZE = b"R"
HEADER = struct.Struct("!cI")
MAX_DATA_FRAME = 4096


def new_keystream():
    return itertools.cycle(KEY)


def xor_crypt(keystream, data):
    return bytes([a ^ b for a, b in zip(data, keystream)])


def validate_frame(kind, length):
    if (kind == FRAME_DATA and length <= MAX_DATA_FRAME) or (kind == FRAME_RESIZE and length == 4):
        return
    raise ValueError("invalid frame")


def send_frame(sock, keystream, kind, payload):
    frame = HEADER.pack(kind, len(payload)) + payload
    sock.sendall(xor_crypt(keystream, frame))


def terminal_size(fd):
    try:
        size = os.get_terminal_size(fd)
    except OSError:
        return None
    return size.lines, size.columns


def relay(conn):
    stdin_fd = sys.stdin.buffer.fileno()
    raw = sys.stdin.isatty()
    saved = termios.tcgetattr(stdin_fd) if raw else None
    if raw:
        tty.setraw(stdin_fd, termios.TCSANOW)

    to_shell = new_keystream()
    from_shell = new_keystream()
    buffer = b""
    stdin_open = True
    resized = raw

    def on_winch(signum, frame):
        nonlocal resized
        resized = True

    previous = signal.signal(signal.SIGWINCH, on_winch) if raw else None
    try:
        while True:
            if resized:
                size = terminal_size(stdin_fd)
                if size is not None:
                    send_frame(conn, to_shell, FRAME_RESIZE, struct.pack("!HH", *size))
                resized = False
            watch = [conn, stdin_fd] if stdin_open else [conn]
            readable, _, _ = select.select(watch, [], [], 0.5)
            if conn in readable:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += xor_crypt(from_shell, chunk)
                while len(buffer) >= HEADER.size:
                    kind, length = HEADER.unpack_from(buffer)
                    validate_frame(kind, length)
                    end = HEADER.size + length
                    if len(buffer) < end:
                        break
                    payload = buffer[HEADER.size:end]
                    buffer = buffer[end:]
                    if kind == FRAME_DATA:
                        sys.stdout.buffer.write(payload)
                        sys.stdout.buffer.flush()
            if stdin_open and stdin_fd in readable:
                data = os.read(stdin_fd, 1024)
                if not data:
                    stdin_open = False
                    conn.shutdown(socket.SHUT_WR)
                else:
                    send_frame(conn, to_shell, FRAME_DATA, data)
    finally:
        if raw:
            signal.signal(signal.SIGWINCH, previous)
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved)


def main():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, PORT))
    listener.listen(1)
    print(f"Listening on {HOST}:{PORT}...")
    while True:
        conn, addr = listener.accept()
        print(f"Connection from {addr}")
        try:
            try:
                relay(conn)
            except ValueError as error:
                print(f"Rejected invalid frame from {addr}: {error}")
        finally:
            conn.close()
        print("Connection closed")


if __name__ == "__main__":
    main()

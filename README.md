# Part 1: Python PTY reverse shell

`shell.py` connects to `attacker:443`, redirects standard input and output to the socket, then starts Bash through a PTY. It provides an unauthenticated remote shell and does not encrypt traffic.

Use only in an authorized, isolated lab. Start a listener at `attacker:443`, then run `python3 shell.py` in the lab.

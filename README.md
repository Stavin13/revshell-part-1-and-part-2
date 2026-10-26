# Part 1: Python PTY reverse shell

Reconstruction of the code example from [the Part 1 article](https://medium.com/@stavinfernandes2098/how-hard-is-it-to-build-a-reverse-shell-in-python-79082dada876).

`shell.py` connects to `attacker:443`, redirects standard input and output to the socket, then starts Bash through a PTY. It provides an unauthenticated remote shell and does not encrypt traffic.

Use only in an authorized, isolated lab. Start a listener at `attacker:443`, then run `python3 shell.py` in the lab.

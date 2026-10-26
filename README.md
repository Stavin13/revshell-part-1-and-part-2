# Python reverse-shell article examples
Use only in an authorized, isolated lab. These examples provide an unauthenticated remote shell.

## Files

- `shell.py`: Part 1 PTY shell.
- `reconnect_shell.py`: Part 2 reconnect loop with capped backoff and jitter.
- `encrypted_shell.py` and `encrypted_listener.py`: Part 2 bidirectional XOR relay.
- `frame_probe.py`: frame validation probe used by `verify.sh`.
- `reverse_shell.yar`: YARA detection example.
- `Dockerfile`: lab image.
- `verify.sh`: one-shot lab checks.
- `.gitignore` and `.dockerignore`: exclude capture files, local caches, and Git metadata from Git and the Docker build context.

## Part 2 XOR note

The published snippets defined `send_encrypted` and `recv_encrypted` but never called them, so the shell traffic remained plaintext. This version uses a framed PTY relay and applies XOR in both directions.

The repeating XOR key has no authentication and is not secure encryption. It only obfuscates traffic. Use this example for lab learning, not for protecting data.

## Isolated Docker lab

The image contains the scripts from both parts. The `--internal` network blocks container access to external networks, but it does not fully isolate containers from the Docker host. No ports are published. The image does not start the shell or listener by itself.

Build the image and create the internal network:

```sh
docker build -t revshell-lab .
docker network create --internal revshell-lab
```

If `revshell-lab` already exists, inspect it with `docker network inspect revshell-lab`. Remove it only if it belongs to this lab.

Start an attacker and victim container:

```sh
docker run -dit --name revshell-attacker --network revshell-lab --network-alias attacker revshell-lab
docker run -dit --name revshell-victim --network revshell-lab revshell-lab
```

### Part 1: plaintext PTY shell

In one terminal, start the listener:

```sh
docker exec -it revshell-attacker nc -lvn 443
```

In another terminal, run the Part 1 shell:

```sh
docker exec -it revshell-victim python3 /opt/revshell/shell.py
```

### Part 2: reconnect variant

Use the same listener, then run:

```sh
docker exec -it revshell-victim python3 /opt/revshell/reconnect_shell.py
```

### Part 2: XOR relay

Start the listener:

```sh
docker exec -it revshell-attacker python3 /opt/revshell/encrypted_listener.py
```

Then run the shell:

```sh
docker exec -it revshell-victim python3 /opt/revshell/encrypted_shell.py
```

### Detection example

Run the YARA rule against the packaged Python scripts:

```sh
docker exec revshell-attacker sh -c 'for f in /opt/revshell/*.py; do yara /opt/revshell/reverse_shell.yar "$f"; done'
```

## Verification

`./verify.sh` builds the image on every run (cached layers keep it fast), starts throwaway containers, checks a plaintext session and the XOR relay, probes invalid and oversized frames on both sides, confirms the payload reconnects and runs a valid session after a rejection, and checks that the YARA rule matches every payload. It prints `PASS` or `FAIL` and exits nonzero if a check fails.

## Packet capture

`tcpdump` is installed in the image. Capture synthetic lab traffic from the attacker container:

```sh
docker exec -d revshell-attacker tcpdump -i eth0 -s 0 -U -w /tmp/part2.pcap 'tcp port 443'
```

Run the listener and shell, then stop and copy the capture:

```sh
docker exec revshell-attacker pkill -x tcpdump
docker cp revshell-attacker:/tmp/part2.pcap ./part2.pcap
open -a Wireshark ./part2.pcap
```

`-s 0` captures full payloads, including everything typed and printed in the shell. Use only synthetic commands; never capture real credentials or secrets. The samples in `captures/` contain only test commands. Capture files are omitted from the repository: `.gitignore` and `.dockerignore` exclude `captures/`, `*.pcap`, and `*.pcapng`.

In Wireshark, decode TCP port 443 as plain data, then use **Follow → TCP Stream → Raw**. Part 1 traffic is cleartext; Part 2 traffic is XOR-obfuscated. Docker Desktop keeps container traffic inside its VM, so capture inside a container rather than on the host.

## Cleanup

```sh
docker stop revshell-victim revshell-attacker
docker rm revshell-victim revshell-attacker
docker network rm revshell-lab
```

The container runs as root because the listener binds port 443. Keep the lab isolated.
